{-# LANGUAGE DeriveDataTypeable  #-}
{-# LANGUAGE DeriveGeneric       #-}
{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}

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
--
-- Simple lightweight S3 API implementation
--
-- This implementation has been tested succesfully against MinIO's, Dreamhost's, and AWS' S3 server implementations
--
-- == API Usage Example
--
-- The example below shows how to create, populate, list, and finally destroy a bucket again.
--
-- @
--  -- demo credentials for http://play.min.io/
--  let s3cfg = 'defaultS3Cfg' { 's3cfgBaseUrl' = \"https://play.min.io:9000\" }
--      creds = 'Credentials' \"Q3AM3UQ867SPQQA43P2F\" \"zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG\"
--
--  -- we'll create this bucket and delete it again
--  let testBucket = 'BucketId' "haskell-test-bucket-42"
--
--  'withConnection' s3cfg $ \conn -> do
--    'createBucket' conn creds testBucket Nothing
--
--    etag1 <- 'putObject' conn creds testBucket ('ObjKey' \"folder\/file1\") \"content1\" (CType \"text\/plain\") Nothing
--    etag2 <- 'putObject' conn creds testBucket ('ObjKey' \"file2\") \"content2\" (CType \"text\/plain\") Nothing
--
--    -- will list the key \"file2\" and the common-prefix \"folder\/\"
--    print =<< 'listObjects' conn creds testBucket 'nullObjKey' (Just \'\/\')
--    -- will list only the key \"folder\/file1\"
--    print =<< 'listObjects' conn creds testBucket ('ObjKey' \"folder\/\") (Just \'\/\')
--    -- will list the two keys \"folder\/file1\" and \"file2\" (and no common prefix)
--    print =<< 'listObjects' conn creds testBucket 'nullObjKey' Nothing
--
--    -- ...and now we remove the two objects we created above
--    'deleteObject' conn creds testBucket ('ObjKey' \"folder\/file1\")
--    'deleteObject' conn creds testBucket ('ObjKey' \"file2\")
--
--    'deleteBucket' conn creds testBucket
-- @
--
module Network.S3
    ( -- * Operations on Buckets
      BucketId(..)
    , BucketInfo(..)
    , Acl(..)

    , listBuckets
    , createBucket
    , deleteBucket

    , listObjects
    , listObjectsFold
    , listObjectsChunk

      -- * Operations on Objects

      -- ** Object keys
    , ObjKey(..), isNullObjKey, nullObjKey

      -- ** Object metadata
    , ObjMetaInfo(..)
    , CType(..), noCType
    , ETag(..)

      -- *** MD5 hashes
    , MD5Val
    , md5hash
    , md5hex
    , md5unhex
    , md5ToSBS
    , md5FromSBS

      -- ** Operations
    , putObject
    , copyObject
    , getObject
    , deleteObject

      -- ** Conditional operations
    , Condition(..)
    , putObjectCond
    , getObjectCond
    , deleteObjectCond

      -- * Errors
    , ErrorCode(..)
    , ProtocolError(..)

      -- * Authentication
    , Credentials(..), noCredentials

      -- * Connection handling
    , S3Cfg(..), defaultS3Cfg
    , SignatureVersion(..)

    , Connection
    , withConnection
    , connect
    , close
    ) where

import           Internal
import           Network.S3.Signature
import           Network.S3.Types
import           Network.S3.XML

import           Control.Concurrent
import           Control.Exception
import qualified Data.ByteString         as BS
import qualified Data.ByteString.Builder as Builder
import qualified Data.ByteString.Char8   as BC8
import qualified Data.ByteString.Lazy    as BL
import qualified Data.ByteString.Short   as BSS
import           Data.Char
import qualified Data.Text               as T
import qualified Data.Text.IO            as T
import qualified Data.Text.Lazy.Encoding as TL
import qualified Data.Text.Short         as TS
import           Data.Time.Clock         (getCurrentTime)
import qualified Network.Http.Client     as HC
import qualified System.IO.Streams       as Streams
import qualified Text.XML                as X

-- | Protocol-level errors and exceptions
data ProtocolError
     = ProtocolInconsistency String
     | HttpFailure !SomeException
     | UnexpectedResponse {- code -} !Int
                       {- message -} !ShortByteString
                  {- content-type -} !ShortByteString
                          {- body -} BL.ByteString
     deriving (Show, Typeable, Generic)

instance Exception ProtocolError

-- | S3-level errors
data ErrorCode
     = AccessDenied
     | BucketAlreadyExists -- not owned by you
     | BucketAlreadyOwnedByYou
     | BucketNotEmpty
     | MalformedXML
     | NoSuchBucket
     | NoSuchKey
     | InvalidArgument
     | InvalidDigest
     | SignatureDoesNotMatch
     | UnknownError !ShortText
     deriving (Show, Typeable, Generic)

instance Exception ErrorCode
instance NFData ErrorCode

errorToErrorCode :: Error -> ErrorCode
errorToErrorCode (Error x) = case x of
    "AccessDenied"            -> AccessDenied
    "BucketAlreadyExists"     -> BucketAlreadyExists
    "BucketAlreadyOwnedByYou" -> BucketAlreadyOwnedByYou
    "BucketNotEmpty"          -> BucketNotEmpty
    "MalformedXML"            -> MalformedXML
    "NoSuchBucket"            -> NoSuchBucket
    "NoSuchKey"               -> NoSuchKey
    "InvalidArgument"         -> InvalidArgument
    "InvalidDigest"           -> InvalidDigest
    "SignatureDoesNotMatch"   -> SignatureDoesNotMatch
    _                         -> UnknownError x

urlEncodeObjKey, urlEncodeObjKeyQry :: ObjKey -> ByteString
urlEncodeObjKey = urlEncode False . TS.toByteString . unObjKey
urlEncodeObjKeyQry = urlEncode True . TS.toByteString . unObjKey

s3'ObjKey :: X.LName -> Bool -> X.Element -> Either String ObjKey
s3'ObjKey ln False el = ObjKey <$> xsd'string (s3qname ln) el
s3'ObjKey ln True el = do
  s <- xsd'string (s3qname ln) el
  case TS.fromText <$> urlDecodeTextUtf8 s of
    Just s' -> pure (ObjKey s')
    Nothing -> Left ("<" <> showQN (X.elName el) <> "> failed to url-decode ObjKey")

objUrlPath :: BucketId -> ObjKey -> UrlPath
objUrlPath (BucketId bucketId) objkey = "/" <> BSS.fromShort bucketId <> "/" <> urlEncodeObjKey objkey

bucketUrlPath :: BucketId -> UrlPath
bucketUrlPath (BucketId bucketId) = "/" <> BSS.fromShort bucketId

withAWSHeaders :: Connection -> (AWSHeaders -> IO b) -> IO b
withAWSHeaders conn cont = do
  now <- getCurrentTime

  cont AWSHeaders
         { ahdrMethod        = HC.GET
         , ahdrUrlPath       = "/"
         , ahdrUrlQuery      = mempty
         , ahdrTimestamp     = now
         , ahdrContentType   = noCType
         , ahdrContentHashes = Nothing
         , ahdrExtraHeaders  = []
         , ahdrSigType       = s3cfgSigVersion $ s3connCfg conn
         , ahdrHost          = s3connHost conn
         , ahdrRegion        = s3cfgRegion $ s3connCfg conn
         }

-- | List buckets owned by user
listBuckets :: Connection
            -> Credentials
            -> IO [BucketInfo]
listBuckets conn creds = withAWSHeaders conn $ \awsh -> do
    let q = HC.buildRequest1 $
              setAWSRequest creds awsh
                { ahdrMethod        = HC.GET
                , ahdrUrlPath       = "/"
                }

    (resp,mtmp) <- doHttpReqXml conn q HC.emptyBody

    case HC.getStatusCode resp of
      200 -> pure ()
      _   -> throwUnexpectedXmlResp resp mtmp

    case maybe (Left "empty body") parseXML mtmp of
      Right (ListAllMyBucketsResult bs) -> pure bs
      Left err -> throwProtoFail $ "ListAllMyBucketsResult: " <> err

-- | Create bucket
createBucket :: Connection
             -> Credentials
             -> BucketId
             -> Maybe Acl
             -> IO ()
createBucket conn creds bid macl = withAWSHeaders conn $ \awsh -> do
    let q = HC.buildRequest1 $
              setAWSRequest creds awsh
                { ahdrMethod        = HC.PUT
                , ahdrUrlPath       = bucketUrlPath bid
                , ahdrExtraHeaders  = hdrs
                }

    (resp, mtmp) <- doHttpReqXml conn q HC.emptyBody

    case HC.getStatusCode resp of
      200 -> pure ()
      _   -> throwUnexpectedXmlResp resp mtmp
  where
    hdrs = case macl of
             Nothing  -> []
             Just acl -> [("x-amz-acl", acl2str acl)]

-- | Delete bucket
--
-- __NOTE__: Most S3 implementations require the bucket to be empty before it can be deleted. See documentation of 'listObjectsFold' for a code example deleting a non-empty bucket.
deleteBucket :: Connection
               -> Credentials
               -> BucketId
               -> IO ()
deleteBucket conn creds bid = withAWSHeaders conn $ \awsh -> do
    let q = HC.buildRequest1 $
              setAWSRequest creds awsh
                { ahdrMethod        = HC.DELETE
                , ahdrUrlPath       = bucketUrlPath bid
                }

    (resp, mtmp) <- doHttpReqXml conn q HC.emptyBody

    case HC.getStatusCode resp of
      204 -> pure ()
      _   -> throwUnexpectedXmlResp resp mtmp

    pure ()

----------------------------------------------------------------------------

-- | Represents a single-threaded HTTP channel to the S3 service
data Connection = S3Conn (MVar HC.Connection) !ByteString !S3Cfg

s3connCfg :: Connection -> S3Cfg
s3connCfg (S3Conn _ _ cfg) = cfg

s3connHost :: Connection -> ByteString
s3connHost (S3Conn _ h _) = h

-- | Simple single-connection 'bracket' style combinator over 'connect' and 'close'
--
-- If you need resource pool management you can use 'connect' in combination with packages such as [resource-pool](http://hackage.haskell.org/package/resource-pool).
withConnection :: S3Cfg -> (Connection -> IO a) -> IO a
withConnection cfg@S3Cfg{..} = bracket (connect cfg) close

-- | Create HTTP(s) connection based on 'S3Cfg'
connect :: S3Cfg -> IO Connection
connect cfg@S3Cfg{..} = do
  c  <- HC.establishConnection s3cfgBaseUrl
  c' <- newMVar c
  pure (S3Conn c' (cHost c) cfg)

-- | Close connection constructed via 'connect'
close :: Connection -> IO ()
close (S3Conn cref _ _) = withMVar cref HC.closeConnection

cHost :: HC.Connection -> ByteString
cHost c = HC.getHostname c (HC.buildRequest1 (pure ()))


-- low-level helper
doHttpReq :: Bool -> Connection -> HC.Request
          -> (Streams.OutputStream Builder.Builder -> IO ())
          -> IO (HC.Response, BL.ByteString)
doHttpReq isProtocol (S3Conn cref _ S3Cfg{..}) q body = withMVar cref $ \c -> do
    when s3cfgDebug $ do
      BS.putStrLn sep1
      T.putStr (T.pack $ show q)
      BS.putStrLn sep2

    (resp,bs) <- handle exh $ do
      () <- HC.sendRequest c q body
      HC.receiveResponse c concatHandler

    when s3cfgDebug $ do
      T.putStr (T.pack $ show resp)
      unless (BL.null bs) $ do
        BS.putStrLn sep2
        if isProtocol || HC.getStatusCode resp /= 200
          then BL.putStrLn bs
          else T.putStrLn (T.pack $ "[non-protocol body with size=" <> show (BL.length bs) <> "]")
      BS.putStrLn sep3

    pure (resp, bs)
  where
    sep1 = "/==========================================================================\\"
    sep2 = "----------------------------------------------------------------------------"
    sep3 = "\\==========================================================================/"

    exh ex = throwIO (HttpFailure ex)

    concatHandler :: HC.Response -> Streams.InputStream ByteString -> IO (HC.Response,BL.ByteString)
    concatHandler res i1 = do
      xs <- Streams.toList i1
      return (res, BL.fromChunks xs)

doHttpReqXml :: Connection -> HC.Request
             -> (Streams.OutputStream Builder.Builder -> IO ())
             -> IO (HC.Response, Maybe X.Element)
doHttpReqXml cn rq body = do
  (resp,bs) <- doHttpReq True cn rq body

  case fromMaybe mempty $ HC.getHeader resp "content-type" of
    ct | isXmlMimeType ct -> do
           txt <- either (\_ -> throwProtoFail "failed to decode UTF-8 content from server") pure (TL.decodeUtf8' bs)
           case X.parseXMLRoot txt of
             Left _  -> throwProtoFail "received malformed XML response from server"
             Right x -> pure (resp,Just $! X.rootElement x)
       | HC.getStatusCode resp == 204 -> pure (resp, Nothing)
       | HC.getStatusCode resp == 200, BL.null bs -> pure (resp, Nothing)
       | otherwise -> throwUnexpectedResp resp bs


getCT :: HC.Response -> CType
getCT resp = case HC.getHeader resp "Content-Type" of
               Nothing -> noCType
               Just bs -> maybe noCType CType (TS.fromByteString bs)

-- c.f. RFC 7303
isXmlMimeType :: ByteString -> Bool
isXmlMimeType bs = case type_subtype of
                     "application/xml" -> True
                     "text/xml"        -> True
                     _                 -> False
  where
    type_subtype = BC8.map toLower $ BC8.takeWhile (not . \c -> isSpace c || c == ';') bs

throwUnexpectedResp :: HC.Response -> BL.ByteString -> IO a
throwUnexpectedResp resp bs
  = case fromMaybe mempty $ HC.getHeader resp "Content-Type" of
      ct | isXmlMimeType ct
         , Right e <- decodeXML bs -> throwIO $! errorToErrorCode e
         | otherwise -> genEx ct

  where
    genEx ct = throwIO $! UnexpectedResponse (HC.getStatusCode resp) (BSS.toShort $ HC.getStatusMessage resp) (BSS.toShort ct) bs


throwUnexpectedXmlResp :: HC.Response -> Maybe X.Element -> IO a
throwUnexpectedXmlResp resp Nothing
  = throwIO $! UnexpectedResponse (HC.getStatusCode resp)
                                  (BSS.toShort $ HC.getStatusMessage resp)
                                  (maybe mempty BSS.toShort $ HC.getHeader resp "Content-Type")
                                  mempty
throwUnexpectedXmlResp resp (Just x) = case parseXML x of
    Right e -> throwIO $! errorToErrorCode e
    Left _  -> genEx
  where
    genEx = throwIO $! UnexpectedResponse (HC.getStatusCode resp) (BSS.toShort $ HC.getStatusMessage resp) "application/xml" (TL.encodeUtf8 (X.serializeXMLDoc x))

throwProtoFail :: String -> IO a
throwProtoFail = throwIO . ProtocolInconsistency

----------------------------------------------------------------------------

{-
-- | Stream bucket listing of objects
listStreamAllObjects :: Connection -> Credentials -> BucketId -> ObjKey -> Maybe Char -> IO S3ListStream
listStreamAllObjects (S3Conn _ cfg) creds bid pfx0 delim0 = go isNullObjKey Nothing -- FIXME
  where
    go :: ObjKey -> Maybe Connection -> IO S3ListStream
    go mmarker Nothing = do
        res <- try $ connect cfg
        case res of
          Left e  -> pure (S3ListEx e (go mmarker Nothing))
          Right c -> go mmarker (Just c)
    go mmarker (Just c) = do
        res <- try $ listObjectsChunk c creds bid pfx0 mmarker delim0
        case res of
          Left e -> pure (S3ListEx e (go mmarker Nothing))
          Right (nextMarker, objs, pfxs)
              | not (TS.null nextMarker) -> do
                    pure $ S3ListFrag objs pfxs
                                      (go nextMarker (Just c))
                                      (close c)
              | otherwise -> do
                    close c
                    if null objs
                        then pure S3ListDone
                        else pure $ S3ListFrag objs pfxs
                                               (pure S3ListDone)
                                               (pure ())


data S3ListStream
    = S3ListFrag  [ObjMetaInfo] [ObjKey]  {- next -}  (IO S3ListStream) {- terminate -} (IO ())
    | S3ListEx    SomeException  {- retry -} (IO S3ListStream) {- terminates by default -}
    | S3ListDone {- terminates by default -}

-}

-- | List all objects in a bucket
--
-- This operation may cause multiple HTTP requests to be issued
--
-- See also 'listObjectsChunk' and 'listObjectsFold'
listObjects :: Connection
            -> Credentials
            -> BucketId
            -> ObjKey -- ^ prefix
            -> Maybe Char -- ^ delimiter
            -> IO ([ObjMetaInfo],[ObjKey]) -- ^ @(objects, prefixes)@
listObjects conn creds bid pfx delim = go nullObjKey [] []
  where
    go marker acc1 acc2 = do
      (marker', objs, pfxs) <- listObjectsChunk conn creds bid pfx delim marker 0
      let acc1' = acc1 <> objs
          acc2' = acc2 <> pfxs
      case () of
        _ | isNullObjKey marker' -> pure (acc1', acc2')
          | otherwise            -> go marker' acc1' acc2'

-- | Convenient 'foldM'-like object listing operation
--
-- Here's an usage example for iterating over the list of objects in
-- chunks of 100 objects and deleting those; and finally deleting the bucket:
--
-- > destroyBucket conn creds bid = do
-- >   listObjectsFold conn creds bid nullObjKey Nothing 100 () $ \() objs [] ->
-- >     forM_ objs $ \omi -> deleteObject conn creds bid (omiKey omi)
-- >   deleteBucket conn creds bid
--
listObjectsFold :: Connection
                -> Credentials
                -> BucketId
                -> ObjKey -- ^ prefix
                -> Maybe Char -- ^ delimiter
                -> Word16 -- ^ max number of keys per iteration
                -> a -- ^ initial value of accumulator argument to folding function
                -> (a -> [ObjMetaInfo] -> [ObjKey] -> IO a) -- ^ folding function
                -> IO a -- ^ returns final value of accumulator value
listObjectsFold conn creds bid pfx delim maxKeys acc0 lbody = go nullObjKey acc0
  where
    go marker acc = do
      (marker', objs, pfxs) <- listObjectsChunk conn creds bid pfx delim marker maxKeys
      acc' <- lbody acc objs pfxs
      case () of
        _ | isNullObjKey marker' -> pure acc'
          | otherwise            -> go marker' acc'

{-
listAllObjects conn creds bid pfx delim = listStreamAllObjects conn creds bid pfx delim >>= go 5 [] []
  where
    go :: Int -> [ObjMetaInfo] -> [ObjKey] -> S3ListStream -> IO ([ObjMetaInfo],[ObjKey])
    go !_         acc acc' S3ListDone = evaluate (acc,acc')
    go maxRetries acc acc' (S3ListEx ex retry)
      | maxRetries > 1 = retry >>= go (maxRetries-1) acc acc'
      | otherwise      = do
          _ <- throwProtoFail ("listAllObjects needed more than 5 retries (" <> show ex <> ")")
          throwIO ex

    go maxRetries acc acc' (S3ListFrag objs pfxs next _) =
        go maxRetries (acc <> objs) (acc' <> pfxs) =<< next

-}

-- -- |
-- --
-- -- TODO: currently supports only non-paginated top-level folder
-- listObjectsFolder :: S3Cfg -> S3Connection -> IO [ObjMetaInfo]
-- listObjectsFolder s3cfg c = do
--     (nextMarker, objs, pfxs) <- listObjectsChunk s3cfg c isNullObjKey isNullObjKey (Just '/')
--     unless (nextMarker == isNullObjKey) $ throwProtoFail "listObjectsFolder"
--     pure $! objs

{-

  <xsd:complexType name="ListBucketResult">
    <xsd:sequence>
      <xsd:element name="Metadata" type="tns:MetadataEntry" minOccurs="0" maxOccurs="unbounded"/>
      <xsd:element name="Name" type="xsd:string"/>
      <xsd:element name="Prefix" type="xsd:string"/>
      <xsd:element name="Marker" type="xsd:string"/>
      <xsd:element name="NextMarker" type="xsd:string" minOccurs="0"/>
      <xsd:element name="MaxKeys" type="xsd:int"/>
      <xsd:element name="Delimiter" type="xsd:string" minOccurs="0"/>
      <xsd:element name="IsTruncated" type="xsd:boolean"/>
      <xsd:element name="Contents" type="tns:ListEntry" minOccurs="0" maxOccurs="unbounded"/>
      <xsd:element name="CommonPrefixes" type="tns:PrefixEntry" minOccurs="0" maxOccurs="unbounded"/>
    </xsd:sequence>
  </xsd:complexType>


-}

data MetadataEntry = MetadataEntry {-key-} ShortText {-value-} ShortText
  deriving Show

pMetadataEntry :: P MetadataEntry
pMetadataEntry = MetadataEntry <$> one (s3_xsd'string "Name") <*> one (s3_xsd'string "Value")

data ListBucketResult = LBR
  { lbrMetadata        :: [MetadataEntry]
  , lbrName            :: BucketId
  , lbrPrefix          :: ObjKey
  , lbrMarker          :: ObjKey
  , lbrNextMarker      :: Maybe ObjKey
  , lbrMaxKeys         :: Int32
  , lbrDelimiter       :: Maybe Char
  , lbrIsTruncated     :: Bool
  , lbrEncodingTypeUrl:: Bool
  , lbrContents        :: [ObjMetaInfo]
  , lbrCommonPrefixes  :: [ObjKey]
  } deriving Show

instance FromXML ListBucketResult where
  tagFromXML _   = s3qname "ListBucketResult"
  parseXML_ = withChildren $ do
      lbrMetadata       <- unbounded (parseXML' (s3qname "Metadata") (withChildren pMetadataEntry))
      lbrName           <- one (s3_xsd'string "Name")

      -- we need this information early on as it affects the decoding of
      -- ObjKey values; so let's read-ahead
      tmp               <- aheadMaybeOne ((== s3qname "EncodingType") . X.elName)
                                         (s3_xsd'string "EncodingType")

      lbrEncodingTypeUrl <- case tmp :: Maybe Text of
                              Just "url" -> pure True
                              Nothing    -> pure False
                              Just _     -> failP "unsupported <EncodingType> encoutered"

      lbrPrefix         <- one (s3'ObjKey "Prefix" lbrEncodingTypeUrl)
      lbrMarker         <- one (s3'ObjKey "Marker" lbrEncodingTypeUrl)
      lbrNextMarker     <- maybeOne (s3'ObjKey "NextMarker" lbrEncodingTypeUrl)
      lbrMaxKeys        <- one (s3_xsd'int "MaxKeys")
      lbrDelimiter      <- fmap T.head <$> maybeOne (s3_xsd'string "Delimiter")
      lbrIsTruncated    <- one (s3_xsd'boolean "IsTruncated")
      lbrContents       <- unbounded (parseXML' (s3qname "Contents") $
                                       withChildren (pObjMetaInfo lbrEncodingTypeUrl))
      lbrCommonPrefixes <- unbounded (parseXML' (s3qname "CommonPrefixes") $
                                       withChildren (pCommonPrefixes lbrEncodingTypeUrl))

      pure LBR{..}
    where
      pCommonPrefixes urlEnc = one (s3'ObjKey "Prefix" urlEnc)

-- | Primitive operation for list objects
--
-- This operation corresponds to a single HTTP service request
--
-- The 'listObjectsChunk' and 'listObjects' operations build on this primitive building block.
listObjectsChunk :: Connection
                 -> Credentials
                 -> BucketId
                 -> ObjKey     -- ^ prefix (use 'isNullObjKey' if none)
                 -> Maybe Char -- ^ delimiter
                 -> ObjKey     -- ^ marker (use 'isNullObjKey' if none)
                 -> Word16     -- ^ max-keys (set @0@ to use default which is usually @1000@)
                 -> IO (ObjKey,[ObjMetaInfo],[ObjKey]) -- ^ @(next-marker, objects, prefixes)@
listObjectsChunk conn creds bid pfx delim marker maxKeys = withAWSHeaders conn $ \awsh -> do
    let q = HC.buildRequest1 $
              setAWSRequest creds awsh
                { ahdrMethod        = HC.GET
                , ahdrUrlPath       = bucketUrlPath bid
                , ahdrUrlQuery      = urlq
                }

    (resp,mtmp) <- doHttpReqXml conn q HC.emptyBody

    case HC.getStatusCode resp of
      200 -> pure ()
      _   -> throwUnexpectedXmlResp resp mtmp

    LBR{..} <- case maybe (Left "empty body") parseXML mtmp of
      Right lbr -> pure (lbr :: ListBucketResult)
      Left err  -> throwProtoFail $ "ListObjects: " <> err

    let nextMarker' | lbrIsTruncated = fromMaybe nullObjKey (max (omiKey <$> last lbrContents) (last lbrCommonPrefixes))
                    | otherwise      = nullObjKey

        nextMarker  | lbrIsTruncated = fromMaybe nextMarker' lbrNextMarker
                    | otherwise      = nullObjKey

    unless (lbrIsTruncated /= isNullObjKey nextMarker) $
      throwProtoFail "NextMarker and isTruncated inconsistent"

    unless (nextMarker == nextMarker') $
      throwProtoFail "NextMarker inconsistent" -- should never happen

    evaluate (force (nextMarker,lbrContents,lbrCommonPrefixes))
  where
    -- we could use max-keys=, but unfortunately AWS S3 doesn't appear
    -- to support pureing more than 1000 entries (which is the
    -- default anyway)

    -- NB: keep this alphabetically sorted
    qryparms = mconcat
      [ [ "delimiter=" <> urlEncode True (BC8.singleton d) | Just d <- [delim] ]
      , [ "encoding-type=url" | s3cfgEncodingUrl (s3connCfg conn) ]
      , [ "marker="    <> urlEncodeObjKeyQry marker | not (isNullObjKey marker) ]
      , [ "max-keys="  <> BC8.pack (show maxKeys) | maxKeys > 0 ]
      , [ "prefix="    <> urlEncodeObjKeyQry pfx | not (isNullObjKey pfx) ]
      ]
    urlq | null qryparms = mempty
         | otherwise = "?" <> BC8.intercalate "&" qryparms

-- | Access permissions (aka /Canned ACLs/)
--
-- This has different meanings depending on whether it's set for buckets or objects
--
-- The owner of an entity has always full read & write access
--
-- For buckets, read access denotes the ability to list objects
data Acl = AclPrivate
         | AclPublicRead
         | AclPublicReadWrite
         | AclPublicAuthenticatedRead
         deriving (Show,Typeable,Generic)

instance NFData Acl

acl2str :: Acl -> ByteString
acl2str acl = case acl of
                AclPrivate                 -> "private"
                AclPublicRead              -> "public-read"
                AclPublicReadWrite         -> "public-read-write"
                AclPublicAuthenticatedRead -> "authenticated-read"


data CopyObjectResult = CopyObjectResult
  { _corLastModified :: UTCTime
  , corETag          :: ETag
  } deriving Show


instance FromXML CopyObjectResult where
  tagFromXML _ = s3qname "CopyObjectResult"
  parseXML_ = withChildren $
    CopyObjectResult <$> one (s3_xsd'dateTime "LastModified")
                     <*> (mkETag <$> one (s3_xsd'string "ETag"))

-- | Copy Object
copyObject :: Connection
           -> Credentials
           -> BucketId
           -> ObjKey
           -> (BucketId,ObjKey) -- ^ source object to copy
           -> Maybe Acl
           -> IO ETag
copyObject conn creds bid objkey (srcBid,srcObjKey) macl = withAWSHeaders conn $ \awsh -> do
    let q = HC.buildRequest1 $
              setAWSRequest creds awsh
                { ahdrMethod        = HC.PUT
                , ahdrUrlPath       = objUrlPath bid objkey
                , ahdrExtraHeaders  = hdrs
                }
              -- TODO: forM_ mcond setConditionHeader

    (resp, mtmp) <- doHttpReqXml conn q HC.emptyBody

    case (HC.getStatusCode resp,mtmp) of
      (200,Just x) | Right v <- parseXML x -> pure (corETag v)
      _ -> throwUnexpectedXmlResp resp mtmp
  where
    hdrs = ("x-amz-copy-source", objUrlPath srcBid srcObjKey)
           : case macl of
               Nothing  -> []
               Just acl -> [("x-amz-acl", acl2str acl)]


-- | @PUT@ Object
putObject :: Connection
          -> Credentials
          -> BucketId
          -> ObjKey        -- ^ Object key
          -> BL.ByteString -- ^ Object payload data
          -> CType         -- ^ @content-type@ (e.g. @application/binary@); see also 'noCType'
          -> Maybe Acl
          -> IO ETag
putObject conn creds bid objkey objdata ctype macl
  = fromMaybe undefined <$> putObjectX conn creds bid objkey objdata ctype macl Nothing

putObjectCond :: Connection
              -> Credentials
              -> BucketId
              -> ObjKey        -- ^ Object key
              -> BL.ByteString -- ^ Object payload data
              -> CType         -- ^ @content-type@ (e.g. @application/binary@); see also 'noCType'
              -> Maybe Acl
              -> Condition
              -> IO (Maybe ETag)
putObjectCond conn creds bid objkey objdata ctype macl cond
  = putObjectX conn creds bid objkey objdata ctype macl (Just cond)

-- common codepath
putObjectX :: Connection
            -> Credentials
            -> BucketId
            -> ObjKey
            -> BL.ByteString
            -> CType
            -> Maybe Acl
            -> Maybe Condition
            -> IO (Maybe ETag)
putObjectX conn creds bid objkey objdata ctype macl mcond = withAWSHeaders conn $ \awsh -> do
    let q = HC.buildRequest1 $ do
              setAWSRequest creds awsh
                { ahdrMethod        = HC.PUT
                , ahdrUrlPath       = objUrlPath bid objkey
                , ahdrContentType   = ctype
                , ahdrContentHashes = Just (md5,sha256,BL.length objdata)
                , ahdrExtraHeaders  = hdrs
                }

              -- sadly, `setHeader "Last-Modified" ...` doesn't seem have any effect
              forM_ mcond setConditionHeader

    (resp, bs) <- doHttpReq True conn q (bsBody objdata)

    case HC.getStatusCode resp of
      200 -> case mkETag <$> HC.getHeader resp "ETag" of
               Just x  -> pure (Just x)
               Nothing -> throwProtoFail "ETag"
      412 | Just _ <- mcond -> pure Nothing
      _   -> throwUnexpectedResp resp bs
  where
    hdrs = case macl of
             Nothing  -> []
             Just acl -> [("x-amz-acl", acl2str acl)]

    md5    = md5hash    objdata
    sha256 = sha256hash objdata

    bsBody :: BL.ByteString -> Streams.OutputStream Builder.Builder -> IO ()
    bsBody bs = Streams.write (Just (Builder.lazyByteString bs))

-- | @GET@ Object
getObject :: Connection
          -> Credentials
          -> BucketId
          -> ObjKey        -- ^ Object key
          -> IO (ETag, CType, BL.ByteString)
getObject conn creds bid objkey = withAWSHeaders conn $ \awsh -> do
    let q = HC.buildRequest1 $
              setAWSRequest creds awsh
                { ahdrMethod        = HC.GET
                , ahdrUrlPath       = objUrlPath bid objkey
                }

    (resp, bs) <- doHttpReq False conn q HC.emptyBody

    case HC.getStatusCode resp of
      200 -> case mkETag <$> HC.getHeader resp "ETag" of
               Just x  -> pure (x, getCT resp, bs)
               Nothing -> throwProtoFail "ETag"
      _   -> throwUnexpectedResp resp bs

getObjectCond :: Connection
              -> Credentials
              -> BucketId
              -> ObjKey        -- ^ Object key
              -> Condition
              -> IO (Maybe (ETag, CType, BL.ByteString))
getObjectCond conn creds bid objkey cond = withAWSHeaders conn $ \awsh -> do
    let q = HC.buildRequest1 $ do
              setAWSRequest creds awsh
                { ahdrMethod        = HC.GET
                , ahdrUrlPath       = objUrlPath bid objkey
                }
              setConditionHeader cond

    (resp, bs) <- doHttpReq False conn q HC.emptyBody

    case HC.getStatusCode resp of
      200 -> case mkETag <$> HC.getHeader resp "ETag" of
               Just x  -> pure $ Just (x, getCT resp, bs)
               Nothing -> throwProtoFail "ETag"
      304 | IfNotMatch  _ <- cond -> pure Nothing
          | IfNotExists   <- cond -> pure Nothing
      412 | IfMatch     _ <- cond -> pure Nothing
          | IfExists      <- cond -> pure Nothing -- non-sensical
      _   -> throwUnexpectedResp resp bs

-- | @DELETE@ Object
deleteObject :: Connection -> Credentials -> BucketId -> ObjKey -> IO ()
deleteObject conn creds bid objkey = withAWSHeaders conn $ \awsh -> do
    let q = HC.buildRequest1 $
              setAWSRequest creds awsh
                { ahdrMethod        = HC.DELETE
                , ahdrUrlPath       = objUrlPath bid objkey
                }

    (resp, bs) <- doHttpReq True conn q HC.emptyBody

    case HC.getStatusCode resp of
      204 -> pure ()
      _   -> throwUnexpectedResp resp bs


deleteObjectCond :: Connection -> Credentials -> BucketId -> ObjKey -> Condition -> IO Bool
deleteObjectCond conn creds bid objkey cond = withAWSHeaders conn $ \awsh -> do
    let q = HC.buildRequest1 $ do
              setAWSRequest creds awsh
                { ahdrMethod        = HC.DELETE
                , ahdrUrlPath       = objUrlPath bid objkey
                }
              setConditionHeader cond

    (resp, bs) <- doHttpReq True conn q HC.emptyBody

    case HC.getStatusCode resp of
      204 -> pure True
      412 -> pure False
      _   -> throwUnexpectedResp resp bs

-- | Bucket metadata reported by 'listBuckets'
data BucketInfo = BucketInfo !BucketId !UTCTime
                deriving (Show,Typeable,Generic)

instance NFData BucketInfo

instance FromXML BucketInfo where
  tagFromXML _   = s3qname "Bucket"
  parseXML_ = withChildren $
    BucketInfo <$> one (s3_xsd'string "Name")
               <*> one (s3_xsd'dateTime "CreationDate")


pObjMetaInfo :: Bool -> P ObjMetaInfo
pObjMetaInfo urlEnc = do
    omiKey <- one (s3'ObjKey "Key" urlEnc)
    omiLastModified <- one (s3_xsd'dateTime "LastModified")

    omiEtag <- mkETag <$> one (s3_xsd'string "ETag")
    -- -- sometimes the reported MD5 is computed over chunks, in
    -- -- which case the etag has a "-<num>" suffix. For now, we just
    -- -- map those to the special zero MD5 as we can't do anything
    -- -- sensible with it anyway (but we may want to be able to
    -- -- detect that the MD5 reported was not a proper MD5)

    omiSize <- one (s3_xsd'long "Size")

    let sc = \case
          "DEEP_ARCHIVE"       -> Just ()
          "GLACIER"            -> Just ()
          "INTELLIGENT_TIERING"-> Just ()
          "ONEZONE_IA"         -> Just ()
          "REDUCED_REDUNDANCY" -> Just ()
          "STANDARD"           -> Just ()
          "STANDARD_IA"        -> Just ()
          "UNKNOWN"            -> Just ()
          _                    -> Nothing -- FIXME

    let s3_storageClass = s3_xsd'enum "StorageClass" sc -- StorageClass / TODO

    -- NB: some implementations have (optional) <Owner> and
    -- (mandatory) <StorageClass> swapped in their schema
    -- (i.e. <StorageClass> not being last); so we tolerate both
    -- orderings

    msc <- maybeOne s3_storageClass
    (own,()) <- case msc of
      Nothing  -> (,) <$> (Just <$> one parseXML) <*> one s3_storageClass
      Just sc' -> (,) <$> maybeOne parseXML <*> pure sc'

    let omiOwnerId = fmap ownerID own

    pure $! (OMI {..})


----------------------------------------------------------------------------

data Owner = Owner { ownerID           :: ShortText
                   , _ownerDisplayName :: Maybe ShortText
                   } deriving Show

instance FromXML Owner where
  tagFromXML _ = s3qname "Owner"
  parseXML_ = withChildren $
    Owner <$> one (s3_xsd'string "ID")
          <*> maybeOne (s3_xsd'string "DisplayName")


newtype ListAllMyBucketsResult = ListAllMyBucketsResult [BucketInfo]

instance FromXML ListAllMyBucketsResult where
  tagFromXML _ = s3qname "ListAllMyBucketsResult"

  parseXML_ = withChildren $ do
    _ <- one pure -- owner; todo
    ListAllMyBucketsResult <$> one (fmap unBuckets . parseXML)

newtype Buckets = Buckets { unBuckets :: [BucketInfo] }

instance FromXML Buckets where
  tagFromXML _ = s3qname "Buckets"
  parseXML_ = withChildren $ Buckets <$> unbounded parseXML

----------------------------------------------------------------------------

newtype Error = Error ShortText
              deriving Show

{- NB: The <Error> response element has no namespace and its schema is not openly documented; the first sub-element is always a <Code> text-element.

<Error>
  <Code>BucketNotEmpty</Code>
  <BucketName>hstest1</BucketName>
  <RequestId>tx000000000000002d08a23-005b80213f-5893fff-us-east-1-iad1</RequestId>
  <HostId>5893fff-us-east-1-iad1-us-east-1</HostId>
</Error>

-}

instance FromXML Error where
  tagFromXML _ = X.unqual "Error"

  parseXML_ = withChildren $ do
    code <- one (xsd'string (X.unqual "Code"))
    void unboundedAny -- skip the rest
    pure (Error code)
