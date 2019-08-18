{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE OverloadedStrings          #-}

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
module Network.S3.Types
    ( module Network.S3.Types
    ) where

import qualified Data.ByteString       as BS
import qualified Data.ByteString.Char8 as BC8
import qualified Data.ByteString.Short as BSS
import           Data.Char
import qualified Data.Text.Encoding    as T
import qualified Data.Text.Short       as TS
import           Internal
import qualified Network.Http.Client   as HC

class XsdString a where fromXsdString :: Text -> a
instance XsdString Text where fromXsdString = id
instance XsdString ShortText where fromXsdString = TS.fromText
instance XsdString ShortByteString where fromXsdString = TS.toShortByteString . TS.fromText
instance XsdString ByteString where fromXsdString = T.encodeUtf8

type UrlPath = ByteString

-- | Content-type
newtype CType = CType ShortText
              deriving (Eq,Show,Typeable,Generic,NFData,Hashable)

-- | Unspecified 'CType'
noCType :: CType
noCType = CType mempty

-- | Configure S3 endpoint
data S3Cfg = S3Cfg
    { s3cfgBaseUrl     :: !HC.URL -- ^ Service endpoint (i.e without 'BucketId'); Only scheme, host and port are used currently
--  , s3cfgPathStyle  :: !Bool -- ^ use path-style access mode (i.e. <http://s3.example.org/bucket-id> instead of virtual-hosted style <http://bucket-id.s3.example.org/>)
    , s3cfgRegion      :: !ByteString -- ^ E.g. @"us-east-1"@ this is currently only used for computing the signature when 's3cfgSigVersion' is set to 'SignatureV4'
    , s3cfgSigVersion  :: !SignatureVersion -- ^ Which signature algorithm to use for authentication; 'SignatureV4' is recommended unless there's reason to use the legacy 'SignatureV2' variant.
    , s3cfgEncodingUrl :: !Bool -- ^ Enable use of @encoding=url@ feature for some operations
                                --
                                -- This is only needed when object keys contain Unicode code-points not representable in XML 1.0; the XML 1.0 representable code-points are
                                --
                                -- > Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
                                --
                                -- Note that some S3 server implementations exhibit bugs when using LF or CR characters in object keys.
                                --
                                -- Note also that some S3 implementation have been observed to incorrectly implement @encoding=url@ so it's generally advisable to disable this feature unless there's actual need and it's been confirmed that the S3 server implementatio implements it correctly.
    , s3cfgDebug       :: !Bool -- ^ Enable protocol debugging output to stdout
    } deriving (Show,Typeable,Generic)

instance NFData S3Cfg

-- | Default 'S3Cfg' value with recommended/default settings, i.e.
--
-- >>> defaultS3Cfg
-- S3Cfg {s3cfgBaseUrl = "", s3cfgRegion = "us-east-1", s3cfgSigVersion = SignatureV4, s3cfgEncodingUrl = False, s3cfgDebug = False}
--
-- __NOTE__: At the very least you have to override the 's3cfgBaseUrl' field.
defaultS3Cfg :: S3Cfg
defaultS3Cfg = S3Cfg
    { s3cfgBaseUrl     = ""
--  , s3cfgPathStyle   = True
    , s3cfgRegion      = "us-east-1"
    , s3cfgSigVersion  = SignatureV4
    , s3cfgEncodingUrl = False
    , s3cfgDebug       = False
    }

-- | Denotes version of the S3 request signing algorithm
data SignatureVersion = SignatureV2 -- ^ Legacy HMAC-SHA1/MD5 based signing algorithm
                      | SignatureV4 -- ^ Current HMAC-SHA256 based signing algorithm (recommended)
                      deriving (Eq,Show,Typeable,Generic)

instance NFData SignatureVersion

-- | S3 Credentials
--
-- We use memory pinned 'ByteString's because we don't want to have the credential data copied around more than necessary.
data Credentials = Credentials
    { s3AccessKey :: !ByteString -- ^ 'mempty' denotes anonymous access (see also 'noCredentials')
    , s3SecretKey :: !ByteString
    } deriving (Eq,Show,Typeable,Generic)

instance NFData Credentials

-- | Anonymous access
noCredentials :: Credentials
noCredentials = Credentials "" ""

isAnonCredentials :: Credentials -> Bool
isAnonCredentials (Credentials akey _) = BS.null akey

-- | S3 Bucket identifier
--
--
newtype BucketId = BucketId ShortByteString    -- ^ Must be valid as DNS name component; S3 server implementations may have additional restrictions (see e.g. AWS S3's <https://docs.aws.amazon.com/AmazonS3/latest/dev/BucketRestrictions.html#bucketnamingrules "Rules for Bucket Naming">)
                 deriving (Eq,Ord,Show,NFData,Generic,Typeable,XsdString,Hashable)

-- | The name for a key is a non-empty sequence of Unicode characters whose UTF-8 encoding is at most 1024 bytes long.
--
-- See also remarks in 's3cfgEncodingUrl' about permissible code-points.
--
-- See also AWS S3's documentation on <https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingMetadata.html "Object Key and Metadata">
newtype ObjKey = ObjKey ShortText
               deriving (Show,Eq,Ord,Typeable,Generic,NFData,Hashable)

unObjKey :: ObjKey -> ShortText
unObjKey (ObjKey k) = k

-- | Represents the /null/ (or empty) 'ObjKey'
nullObjKey :: ObjKey
nullObjKey = ObjKey mempty

-- | Test whether 'ObjKey' is the 'nullObjKey'
isNullObjKey :: ObjKey -> Bool
isNullObjKey = TS.null . unObjKey


----------------------------------------------------------------------------

-- | Denotes an <https://en.wikipedia.org/wiki/HTTP_ETag ETag>
data ETag = ETag !ShortByteString
          | ETagMD5 !MD5Val -- ^ This constructor will be used if the ETag looks like a proper MD5 based ETag
          deriving (Show,Eq,Ord,Typeable,Generic)

instance NFData ETag where
  rnf !_ = ()

instance Hashable ETag

{-

entity-tag = [ weak ] opaque-tag
     weak       = %x57.2F ; "W/", case-sensitive
     opaque-tag = DQUOTE *etagc DQUOTE
     etagc      = %x21 / %x23-7E / obs-text
                ; VCHAR except double quotes, plus obs-text
     obs-text   = %x80-FF
-}

etagToBS :: ETag -> ByteString
etagToBS (ETag etag)   = BSS.fromShort etag
etagToBS (ETagMD5 md5) = mconcat [ "\"", md5hex md5, "\"" ]

mkETag :: ByteString -> ETag
mkETag bs
  | BS.length bs == 34, BC8.head bs == '"', BC8.last bs == '"'
  , BC8.all (\c -> isHexDigit c && not (isUpper c)) (BS.init (BS.tail bs))
  , Just md5 <- md5unhex (BS.init (BS.tail bs)) = ETagMD5 md5

  | otherwise = ETag (BSS.toShort bs)

----------------------------------------------------------------------------

-- | Object Metadata
data ObjMetaInfo = OMI
    { omiKey          :: !ObjKey
    , omiEtag         :: !ETag
    , omiSize         :: !Int64
    , omiOwnerId      :: !(Maybe ShortText)
    , omiLastModified :: !UTCTime
    } deriving (Eq,Ord,Show,Typeable,Generic)

instance NFData ObjMetaInfo

----------------------------------------------------------------------------

-- | Conditional Request
--
-- Note that S3 server implementations vary in their support for
-- conditional requests
--
data Condition = IfExists         -- ^ @If-Match: *@
               | IfNotExists      -- ^ @If-None-Match: *@
               | IfMatch !ETag    -- ^ @If-Match: ...@
               | IfNotMatch !ETag -- ^ @If-None-Match: ...@
               deriving (Eq,Show,Typeable,Generic)

instance NFData Condition

setConditionHeader :: Condition -> HC.RequestBuilder ()
setConditionHeader = \case
  IfExists        -> HC.setHeader "If-Match" "*"
  IfNotExists     -> HC.setHeader "If-None-Match" "*"
  IfMatch  etag   -> HC.setHeader "If-Match" (etagToBS etag)
  IfNotMatch etag -> HC.setHeader "If-None-Match" (etagToBS etag)
