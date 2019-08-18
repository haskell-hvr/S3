{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

{-

Copyright (c) 2016-2019  Herbert Valerio Riedel <hvr@gnu.org>

 This file is free software: you may copy, redistribute and/or modify it
 under the terms of the GNU General Public License as published by the
 Free Software Foundation, either version 3 of the License, or (at your
 option) any later version.

 This file is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program (see `LICENSE`).  If not, see
 <https://www.gnu.org/licenses/gpl-3.0.html>.

-}

-- |
-- Copyright: © Herbert Valerio Riedel 2016-2019
-- SPDX-License-Identifier: GPL-3.0-or-later
module Network.S3.Signature
    ( AWSHeaders(..)
    , setAWSRequest
    ) where

import           Internal
import           Network.S3.Types

import qualified Codec.Base16          as B16
import qualified Codec.Base64          as B64
import qualified Crypto.Hash.SHA1      as SHA1
import qualified Crypto.Hash.SHA256    as SHA256
import qualified Data.ByteString       as BS
import qualified Data.ByteString.Char8 as BC8
import qualified Data.List             as List
import qualified Data.Text.Short       as TS
import           Data.Time.Format      (defaultTimeLocale)
import qualified Data.Time.Format      as DT
import qualified Network.Http.Client   as HC


data AWSHeaders = AWSHeaders
  { ahdrMethod        :: HC.Method
  , ahdrUrlPath       :: UrlPath -- always starting w/ a '/'
  , ahdrUrlQuery      :: ByteString -- always starting w/ the '?' separator
  , ahdrTimestamp     :: UTCTime
  , ahdrContentType   :: CType
  , ahdrContentHashes :: Maybe (MD5Val,SHA256Val,Int64)
  , ahdrExtraHeaders  :: [(ByteString,ByteString)]
  , ahdrSigType       :: SignatureVersion
  , ahdrHost          :: ByteString
  , ahdrRegion        :: ByteString
  }

-- | Sets up AWS headers and performs AWS signature
setAWSRequest :: Credentials -> AWSHeaders -> HC.RequestBuilder ()
setAWSRequest creds AWSHeaders{..} = do
    HC.http ahdrMethod (ahdrUrlPath <> ahdrUrlQuery)
    HC.setHeader "Date" dateRFC1123
    unless (BS.null ctype) $ HC.setContentType ctype
    forM_ clen HC.setContentLength
    forM_ ahdrExtraHeaders (uncurry HC.setHeader)

    unless (isAnonCredentials creds) $ case ahdrSigType of
      SignatureV2 -> do
        unless (BS.null cmd5)  $ HC.setHeader "Content-MD5" cmd5

        HC.setHeader "Authorization" $
          genSignatureV2 ahdrMethod ahdrUrlPath (cmd5,ctype,dateRFC1123) ahdrExtraHeaders creds

      SignatureV4 -> do
        let v4hdrs = [("host", ahdrHost)
                     ,("x-amz-date",dateAmz)
                     ,("x-amz-content-sha256",csha256)
                     ]

        HC.setHeader "x-amz-date" dateAmz
        HC.setHeader "x-amz-content-sha256" csha256

        HC.setHeader "Authorization" $
          genSignatureV4 ahdrMethod (ahdrUrlPath,ahdrUrlQuery) (csha256,dateAmz) (v4hdrs<>ahdrExtraHeaders) ahdrRegion creds

  where
    dateRFC1123 = formatRFC1123 ahdrTimestamp
    dateAmz     = formatAmzDate ahdrTimestamp

    ctype = let CType x = ahdrContentType in TS.toByteString x

    (cmd5,csha256,clen) = case ahdrContentHashes of
             Just (md5,sha256,l) -> (md5b64 md5,sha256hex sha256,Just l)
             Nothing | hasBody ahdrMethod -> (md5b64 (md5hash mempty), csha256Empty, Just 0)
                     | otherwise          -> (mempty,csha256Empty,Nothing)

    csha256Empty = sha256hex (sha256hash mempty)

formatRFC1123 :: UTCTime -> ByteString
formatRFC1123 = BC8.pack . DT.formatTime defaultTimeLocale "%a, %d %b %Y %X GMT"

formatAmzDate :: UTCTime -> ByteString
formatAmzDate = BC8.pack . DT.formatTime defaultTimeLocale "%Y%m%dT%H%M%SZ"


{- | Compute AWS v2 signature
@
Authorization = "AWS" + " " + AWSAccessKeyId + ":" + Signature;

Signature = Base64( HMAC-SHA1( YourSecretAccessKeyID, UTF-8-Encoding-Of( StringToSign ) ) );

StringToSign = HTTP-Verb + "\n" +
	Content-MD5 + "\n" +
	Content-Type + "\n" +
	Date + "\n" +
	CanonicalizedAmzHeaders +
	CanonicalizedResource;

CanonicalizedResource = [ "/" + Bucket ] +
	<HTTP-Request-URI, from the protocol name up to the query string> +
	[ subresource, if present. For example "?acl", "?location", "?logging", or "?torrent"];

CanonicalizedAmzHeaders = ...
@

-}
genSignatureV2 :: HC.Method -> ByteString
               -> (ByteString,ByteString,ByteString)
               -> [(ByteString,ByteString)]
               -> Credentials
               -> ByteString
genSignatureV2 verb urlp (cmd5,ctype,date) amzhdrs (Credentials akey skey)
  = mconcat ["AWS ", akey, ":", B64.encode sig]
  where
    -- signature
    sig = SHA1.hmac skey msg
    -- string-to-sign
    msg = joinWithLF $
              [ meth2bs verb
              , cmd5
              , ctype
              , date
              ] <>
              [ k <> ":" <> v | (k,v) <- List.sort amzhdrs ] <>
              [ urlp ]

-- | Compute AWS v4 signature
genSignatureV4 :: HC.Method
               -> (ByteString,ByteString)
               -> (ByteString,ByteString)
               -> [(ByteString,ByteString)]
               -> ByteString
               -> Credentials
               -> ByteString
genSignatureV4 verb (urlp,urlq) (csha256,ts) amzhdrs region (Credentials akey skey0)
  = mconcat
    [ algoId
    , " Credential=", akey, "/", credScope
    , ", SignedHeaders=", signedHdrs
    , ", Signature=", B16.encode sig
    ]

  where
    algoId = "AWS4-HMAC-SHA256"
    hdrs' = List.sort amzhdrs

    -- signature
    sig = SHA256.hmac signKey msg

    -- signing-key
    signKey = ("AWS4"<>skey0) `SHA256.hmac` tsDate
                              `SHA256.hmac` region
                              `SHA256.hmac` "s3"
                              `SHA256.hmac` "aws4_request"

    -- string-to-sign
    msg = joinWithLF
      [ algoId
      , ts
      , credScope
      , B16.encode (SHA256.hash crq)
      ]

    -- canonical request
    crq = joinWithLF $
      [ meth2bs verb
      , urlp
      , BS.drop 1 urlq ] <>
      [ k <> ":" <> v | (k,v) <- hdrs' ] <>
      [ mempty
      , signedHdrs
      , csha256
      ]

    signedHdrs = BS.intercalate ";" (fst <$> hdrs')

    credScope = mconcat [ tsDate , "/", region, "/s3/aws4_request" ]

    -- i.e., the date-part of the timestamp
    tsDate = BC8.takeWhile (/='T') ts

-- NB: this does not add a trailing newline
joinWithLF :: [ByteString] -> ByteString
joinWithLF = BS.intercalate "\n"


meth2bs :: HC.Method -> ByteString
meth2bs = \case
  HC.PUT      -> "PUT"
  HC.POST     -> "POST"
  HC.GET      -> "GET"
  HC.HEAD     -> "HEAD"
  HC.DELETE   -> "DELETE"
  HC.OPTIONS  -> "OPTIONS"
  HC.PATCH    -> "PATCH"
  HC.CONNECT  -> "CONNECT"
  HC.TRACE    -> "TRACE"
  HC.Method x -> x

hasBody :: HC.Method -> Bool
hasBody = \case
  HC.PUT      -> True
  HC.POST     -> True
  HC.PATCH    -> True
  HC.Method _ -> undefined -- TODO
  _           -> False
