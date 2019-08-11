{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE LambdaCase #-}

{-# OPTIONS_GHC -Wno-deprecations #-}

-- |
-- Copyright: © Herbert Valerio Riedel 2016-2019
-- SPDX-License-Identifier: GPL-3.0-or-later
--
-- Simple lightweight S3 API implementation
--
-- This implementation has been tested succesfully against MinIO's, Dreamhost's, and Amazon's S3 server implementations
module Network.S3
    ( -- * Operations on Buckets
      BucketId(..)
    , BucketInfo(..)
    , Acl(..)

    , listBuckets
    , putBucket
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
    , S3Cfg(..)

    , Connection
    , withConnection
    , connect
    , close
    ) where

import           Internal

import Text.Read (readMaybe)
import Control.Monad
import           Control.Concurrent
import           Control.Exception
import qualified Crypto.Hash.MD5         as MD5
import qualified Crypto.Hash.SHA1        as SHA1
import qualified Data.ByteString         as BS
import qualified Codec.Base64  as B64
import qualified Data.ByteString.Builder as Builder
import qualified Data.ByteString.Char8   as BC8
import qualified Data.ByteString.Short   as BSS
import qualified Data.ByteString.Lazy   as BL
import           Data.Char
import qualified Data.List               as List
import qualified Data.Text.Short         as TS
import qualified Data.Text               as T
import qualified Data.Text.Encoding               as T
import qualified Data.Text.Lazy.Encoding               as TL
import           Data.Time               (UTCTime)
import           Data.Time.Clock         (getCurrentTime)
import           Data.Time.Format        (defaultTimeLocale)
import qualified Data.Time.Format        as DT
import qualified Network.Http.Client     as HC
import qualified System.IO.Streams       as Streams
import qualified Text.XML                as X

-- | Protocol-level errors and exceptions
data ProtocolError
     = ProtocolInconsistency String
     | HttpFailure !SomeException
     | UnexpectedResponse {- code -} !Int {- message -} !ShortByteString {- content-type -} !ShortByteString {- body -} ByteString
     deriving (Show, Typeable)
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
     | UnknownError !ShortText
     deriving (Show, Typeable)
instance Exception ErrorCode

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
    _                         -> UnknownError x

-- | Content-type
newtype CType = CType ShortText
              deriving Show

-- | Unspecified 'CType'
noCType :: CType
noCType = CType mempty

data S3Cfg = S3Cfg
    { s3cfgBaseUrl :: !HC.URL -- ^ Service endpoint (i.e without 'BucketId'); Only scheme, host and port are used currently
    }

-- | S3 Credentials
--
-- We use memory pinned 'ByteString's because we don't want to have the credential data copied around more than necessary.
data Credentials = Credentials
    { s3AccessKey :: !ByteString -- ^ 'mempty' denotes anonymous access (see also 'noCredentials')
    , s3SecretKey :: !ByteString
    }

-- | Anonymous access
noCredentials :: Credentials
noCredentials = Credentials "" ""

-- | S3 Bucket identifier
--
--
newtype BucketId = BucketId ShortByteString    -- ^ Must be valid as DNS name component; S3 provider may have additional restrictions (see e.g. AWS S3's <https://docs.aws.amazon.com/AmazonS3/latest/dev/BucketRestrictions.html#bucketnamingrules "Rules for Bucket Naming">)
                 deriving (Eq,Ord,Show,NFData,XsdString)

-- | List buckets owned by user
listBuckets :: Connection
            -> Credentials
            -> IO ([BucketInfo])
listBuckets conn creds = do
    now <- getCurrentTime

    let q = HC.buildRequest1 $
              setAWSHeaders HC.GET (BucketId "",nullObjKey,"") ("",noCType,now) [] creds

    (resp,mtmp) <- doHttpReqXml conn q HC.emptyBody

    case HC.getStatusCode resp of
      200 -> pure ()
      403 -> throwIO AccessDenied
      _   -> throwUnexpectedXmlResp resp (fromMaybe dummyEl mtmp)

    case maybe (Left "empty body") parseXML mtmp of
      Right (ListAllMyBucketsResult bs) -> pure bs
      Left err -> throwProtoFail $ "ListAllMyBucketsResult: " <> err

-- | Create bucket
putBucket :: Connection
          -> Credentials
          -> BucketId
          -> Maybe Acl
          -> IO ()
putBucket conn creds bid macl = do
    now <- getCurrentTime

    let q = HC.buildRequest1 $ do
              setAWSHeaders HC.PUT (bid,nullObjKey,mempty) ("",noCType,now) hdrs creds
              HC.setContentLength 0

    (resp, mtmp) <- doHttpReqXml conn q HC.emptyBody

    case HC.getStatusCode resp of
      200 -> pure ()
      403 -> throwIO AccessDenied
      _   -> throwUnexpectedXmlResp resp (fromMaybe dummyEl mtmp)
  where
    hdrs = case macl of
             Nothing  -> []
             Just acl -> [("x-amz-acl", acl2str acl)]

-- | Delete bucket
--
-- __NOTE__: Many S3 implementations require the bucket to be empty before it can be deleted
deleteBucket :: Connection
               -> Credentials
               -> BucketId
               -> IO ()
deleteBucket conn creds bid = do
    now <- getCurrentTime

    let q = HC.buildRequest1 $ do
              setAWSHeaders HC.DELETE (bid,nullObjKey,mempty) (mempty,noCType,now) [] creds

    (resp, mtmp) <- doHttpReqXml conn q HC.emptyBody

    case HC.getStatusCode resp of
      204 -> pure ()
      403 -> throwIO AccessDenied
      _   -> throwUnexpectedXmlResp resp (fromMaybe dummyEl mtmp)

    pure ()


-- | The name for a key is a sequence of Unicode characters whose UTF-8 encoding is at most 1024 bytes long.
--
-- See also AWS S3's documentation on <https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingMetadata.html "Object Key and Metadata">
newtype ObjKey = ObjKey ShortText
               deriving (Show,Eq,Ord,NFData)

unObjKey :: ObjKey -> ShortText
unObjKey (ObjKey k) = k

nullObjKey :: ObjKey
nullObjKey = ObjKey mempty

isNullObjKey :: ObjKey -> Bool
isNullObjKey = TS.null . unObjKey

data ETag = ETag !ShortByteString
          | ETagMD5 !MD5Val
          deriving (Show,Eq,Ord)

instance NFData ETag where
  rnf !_ = ()

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


-- | Conditional Request
--
-- Note that S3 server implementations vary in their support for
-- conditional requests
--
data Condition = IfExists         -- ^ @If-Match: *@
               | IfNotExists      -- ^ @If-None-Match: *@
               | IfMatch !ETag    -- ^ @If-Match: ...@
               | IfNotMatch !ETag -- ^ @If-None-Match: ...@

setConditionHeader :: Condition -> HC.RequestBuilder ()
setConditionHeader cond = case cond of
  IfExists        -> HC.setHeader "If-Match" "*"
  IfNotExists     -> HC.setHeader "If-None-Match" "*"
  IfMatch  etag   -> HC.setHeader "If-Match" (etagToBS etag)
  IfNotMatch etag -> HC.setHeader "If-None-Match" (etagToBS etag)


data ObjMetaInfo = OMI
    { omiKey          :: !ObjKey
    , omiEtag         :: !ETag
    , omiSize         :: !Int64
    , omiOwnerId      :: !(Maybe ShortText)
    , omiLastModified :: !UTCTime
    } deriving (Eq,Ord,Show)

instance NFData ObjMetaInfo where rnf !_ = ()

urlEncodeObjKey :: ObjKey -> ByteString
urlEncodeObjKey = BC8.concatMap go . TS.toByteString . unObjKey
  where
    go c | inRng '0' '9' c ||
           inRng 'a' 'z' c ||
           inRng 'A' 'Z' c ||
           c `elem` ['-','_','.','~'] = BC8.singleton c

         | otherwise = let (h,l) = quotRem (fromIntegral $ fromEnum c) 0x10
                       in BS.pack [0x25, hex h, hex l]

    inRng x y c = c >= x && c <= y

    hex j | j < 10    = 0x30 + j
          | otherwise = 0x37 + j

----------------------------------------------------------------------------

-- | Represents a single-threaded HTTP channel to the S3 service
data Connection = S3Conn (MVar HC.Connection) !S3Cfg

-- | Simple single-connection 'bracket' style combinator over 'connect' and 'close'
--
-- If you need resource pool management you can use 'connect' in combination with packages such as [resource-pool](http://hackage.haskell.org/package/resource-pool).
withConnection :: S3Cfg -> (Connection -> IO a) -> IO a
withConnection cfg@S3Cfg{..} act = HC.withConnection (HC.establishConnection s3cfgBaseUrl) $ \c -> do
  c' <- newMVar c
  act (S3Conn c' cfg)

connect :: S3Cfg -> IO Connection
connect cfg@S3Cfg{..} = do
  c' <- newMVar =<< HC.establishConnection s3cfgBaseUrl
  pure (S3Conn c' cfg)

close :: Connection -> IO ()
close (S3Conn cref _) = withMVar cref $ \c -> do
  HC.closeConnection c

debugHttp :: Bool
debugHttp = True

-- is4xx :: HC.StatusCode -> Bool
-- is4xx sc = 400 <= sc && sc < 500

-- low-level helper
doHttpReq :: Connection -> HC.Request -> (Streams.OutputStream Builder.Builder -> IO ()) -> IO (HC.Response, ByteString)
doHttpReq (S3Conn cref S3Cfg{..}) q body = withMVar cref $ \c -> do
    (resp,bs) <- handle exh $ do
      () <- HC.sendRequest c q body
      HC.receiveResponse c concatHandler

    when debugHttp $ do
      putStrLn "============================================================================"
      print q
      putStrLn "----------------------------------------------------------------------------"
      print resp
      BS.putStrLn bs
      -- BS.writeFile "response.xml" bs
      putStrLn "============================================================================"

    pure (resp, bs)
  where
    exh ex = throwIO (HttpFailure ex)

    concatHandler :: HC.Response -> Streams.InputStream ByteString -> IO (HC.Response,ByteString)
    concatHandler p i = (,) p <$> HC.concatHandler p i

doHttpReqXml :: Connection -> HC.Request
             -> (Streams.OutputStream Builder.Builder -> IO ())
             -> IO (HC.Response, Maybe X.Element)
doHttpReqXml cn rq body = do
  (resp,bs) <- doHttpReq cn rq body

  case fromMaybe mempty $ HC.getHeader resp "content-type" of
    ct | isXmlMimeType ct -> do
           txt <- either (\_ -> throwProtoFail "failed to decode UTF-8 content from server") pure (T.decodeUtf8' bs)
           case X.parseXMLRoot txt of
             Left _  -> throwProtoFail "received malformed XML response from server"
             Right x -> pure (resp,Just $! X.rootElement x)
       | HC.getStatusCode resp == 204 -> pure (resp, Nothing)
       | HC.getStatusCode resp == 200, BS.null bs -> pure (resp, Nothing)
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

throwUnexpectedResp :: HC.Response -> ByteString -> IO a
throwUnexpectedResp resp bs = do
    case maybe mempty id $ HC.getHeader resp "Content-Type" of
      ct | isXmlMimeType ct
         , Right e <- decodeXML bs -> throwIO $! errorToErrorCode e
         | otherwise -> genEx ct

  where
    genEx ct = throwIO $! UnexpectedResponse (HC.getStatusCode resp) (BSS.toShort $ HC.getStatusMessage resp) (BSS.toShort ct) bs


throwUnexpectedXmlResp :: HC.Response -> X.Element -> IO a
throwUnexpectedXmlResp resp x = case parseXML x of
    Right e -> throwIO $! errorToErrorCode e
    Left _  -> genEx
  where
    genEx = throwIO $! UnexpectedResponse (HC.getStatusCode resp) (BSS.toShort $ HC.getStatusMessage resp) "application/xml" (BL.toStrict $ TL.encodeUtf8 (X.serializeXMLDoc x))

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
            -> Maybe Char -- ^ delim
            -> IO ([ObjMetaInfo],[ObjKey])

listObjects conn creds bid pfx delim = go nullObjKey [] []
  where
    go marker acc1 acc2 = do
      (marker', objs, pfxs) <- listObjectsChunk conn creds bid pfx delim marker 0
      let acc1' = acc1 <> objs
          acc2' = acc2 <> pfxs
      case () of
        _ | isNullObjKey marker' -> pure (acc1', acc2')
          | otherwise            -> go marker' acc1' acc2'

listObjectsFold :: Connection -> Credentials -> BucketId -> ObjKey -> Maybe Char
                -> a -> (a -> [ObjMetaInfo] -> [ObjKey] -> IO a)
                -> IO (Maybe a)
listObjectsFold conn creds bid pfx delim acc0 lbody = go nullObjKey acc0
  where
    go marker acc = do
      (marker', objs, pfxs) <- listObjectsChunk conn creds bid pfx delim marker 0
      acc' <- lbody acc objs pfxs
      case () of
        _ | isNullObjKey marker' -> pure Nothing
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
  { lbrMetadata       :: [MetadataEntry]
  , lbrName           :: BucketId
  , lbrPrefix         :: ObjKey
  , lbrMarker         :: ObjKey
  , lbrNextMarker     :: Maybe ObjKey
  , lbrMaxKeys        :: Int32
  , lbrDelimiter      :: Maybe Char
  , lbrIsTruncated    :: Bool
  , lbrEncodingType   :: Maybe ShortText
  , lbrContents       :: [ObjMetaInfo]
  , lbrCommonPrefixes :: [ObjKey]
  } deriving Show

instance FromXML ListBucketResult where
  tagFromXML _   = s3qname "ListBucketResult"
  parseXML_ = withChildren $ do
    lbrMetadata       <- unbounded (parseXML' (s3qname "Metadata") (withChildren pMetadataEntry))
    lbrName           <- one (s3_xsd'string "Name")
    lbrPrefix         <- ObjKey <$> one (s3_xsd'string "Prefix")
    lbrMarker         <- ObjKey <$> one (s3_xsd'string "Marker")
    lbrNextMarker     <- fmap ObjKey <$> maybeOne (s3_xsd'string "NextMarker")
    lbrMaxKeys        <- one (s3_xsd'int "MaxKeys")
    lbrDelimiter      <- fmap T.head <$> maybeOne (s3_xsd'string "Delimiter")
    lbrIsTruncated    <- one (s3_xsd'boolean "IsTruncated")
    lbrEncodingType   <- maybeOne (s3_xsd'string "EncodingType")
    lbrContents       <- unbounded parseXML
    lbrCommonPrefixes <- fmap unCommonPrefixes <$> unbounded parseXML

    pure LBR{..}


-- | Basic @List Objects@ service call
--
-- See also 'listObjectsChunk
listObjectsChunk :: Connection
                 -> Credentials
                 -> BucketId
                 -> ObjKey     -- ^ prefix (use 'isNullObjKey' if none)
                 -> Maybe Char -- ^ delimiter
                 -> ObjKey     -- ^ marker (use 'isNullObjKey' if none)
                 -> Word16     -- ^ max-keys (set @0@ to use default which is usually @1000@)
                 -> IO (ObjKey,[ObjMetaInfo],[ObjKey]) -- ^ @(next-marker, objects, prefixes)@
listObjectsChunk conn creds bid pfx delim marker maxKeys = do
    now <- getCurrentTime

    let q = HC.buildRequest1 $
              setAWSHeaders HC.GET (bid,nullObjKey,qry) ("",noCType,now) [] creds

    (resp,mtmp) <- doHttpReqXml conn q HC.emptyBody

    case HC.getStatusCode resp of
      200 -> pure ()
      403 -> throwIO AccessDenied
      _   -> throwUnexpectedXmlResp resp (fromMaybe dummyEl mtmp)

    LBR{..} <- case maybe (Left "empty body") parseXML mtmp of
      Right lbr -> pure (lbr :: ListBucketResult)
      Left err  -> throwProtoFail $ "ListObjects: " <> err

    let nextMarker' | lbrIsTruncated = fromMaybe nullObjKey (max (omiKey <$> last lbrContents) (last lbrCommonPrefixes))
                    | otherwise      = nullObjKey

        nextMarker  | lbrIsTruncated = fromMaybe nextMarker' lbrNextMarker
                    | otherwise      = nullObjKey

    unless (lbrIsTruncated /= isNullObjKey nextMarker) $
      throwProtoFail "NextMarker and isTruncated inconsistent"

    unless (nextMarker == nextMarker') $ do
      throwProtoFail "NextMarker inconsistent" -- should never happen

    evaluate (force (nextMarker,lbrContents,lbrCommonPrefixes))
  where
    -- we could use max-keys=, but unfortunately AWS S3 doesn't appear
    -- to support pureing more than 1000 entries (which is the
    -- default anyway)

    -- TODO: percent encode
    qryparms = [ "prefix="    <> urlEncodeObjKey pfx | not (isNullObjKey pfx) ] <>
               [ "delimiter=" <> urlEncodeObjKey (ObjKey (TS.singleton d)) | Just d <- [delim] ] <>
               [ "marker="    <> urlEncodeObjKey marker | not (isNullObjKey marker) ] <>
               [ "max-keys="  <> BC8.pack (show maxKeys) | maxKeys > 0 ]
               -- [ "encoding-type=url" ]
    qry | null qryparms = mempty
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
         deriving Show

acl2str :: Acl -> ByteString
acl2str acl = case acl of
                AclPrivate                 -> "private"
                AclPublicRead              -> "public-read"
                AclPublicReadWrite         -> "public-read-write"
                AclPublicAuthenticatedRead -> "authenticated-read"


data CopyObjectResult = CopyObjectResult
  { corLastModified :: UTCTime
  , corETag :: ETag
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
copyObject conn creds bid objkey (srcBid,srcObjKey) macl = do
    now <- getCurrentTime

    let q = HC.buildRequest1 $ do
              setAWSHeaders HC.PUT (bid,objkey,mempty) (cmd5,noCType,now) hdrs creds
              -- forM_ mcond setConditionHeader
              HC.setContentLength 0

    (resp, mtmp) <- doHttpReqXml conn q HC.emptyBody

    case (HC.getStatusCode resp,mtmp) of
      (200,Just x) -> case parseXML x of
        Right v  -> pure (corETag v)
        Left _   -> throwUnexpectedXmlResp resp x

      (403,_) -> throwIO AccessDenied

      (_,Nothing) -> throwUnexpectedResp resp mempty
      (_,Just x)  -> throwUnexpectedXmlResp resp x
  where
    hdrs = ("x-amz-copy-source", mkUrlPath (srcBid,srcObjKey,mempty))
           : case macl of
               Nothing  -> []
               Just acl -> [("x-amz-acl", acl2str acl)]

    cmd5 = B64.encode (MD5.hash mempty) -- RFC1864


-- | @PUT@ Object
putObject :: Connection
          -> Credentials
          -> BucketId
          -> ObjKey        -- ^ Object key
          -> ByteString    -- ^ Object payload data
          -> CType         -- ^ @content-type@ (e.g. @application/binary@); see also 'noCType'
          -> Maybe Acl
          -> IO ETag
putObject conn creds bid objkey objdata ctype macl = maybe undefined id <$> putObjectX conn creds bid objkey objdata ctype macl Nothing

putObjectCond :: Connection
              -> Credentials
              -> BucketId
              -> ObjKey        -- ^ Object key
              -> ByteString    -- ^ Object payload data
              -> CType         -- ^ @content-type@ (e.g. @application/binary@); see also 'noCType'
              -> Maybe Acl
              -> Condition
              -> IO (Maybe ETag)
putObjectCond conn creds bid objkey objdata ctype macl cond = putObjectX conn creds bid objkey objdata ctype macl (Just cond)

-- common codepath
putObjectX :: Connection
            -> Credentials
            -> BucketId
            -> ObjKey
            -> ByteString
            -> CType
            -> Maybe Acl
            -> Maybe Condition
            -> IO (Maybe ETag)
putObjectX conn creds bid objkey objdata ctype macl mcond = do
    now <- getCurrentTime

    let q = HC.buildRequest1 $ do
              setAWSHeaders HC.PUT (bid,objkey,mempty) (cmd5,ctype,now) hdrs creds
              -- sadly, `setHeader "Last-Modified" ...` doesn't seem have any effect
              forM_ mcond setConditionHeader
              HC.setContentLength (fromIntegral $ BS.length objdata)

    (resp, bs) <- doHttpReq conn q (bsBody objdata)

    case HC.getStatusCode resp of
      200 -> case mkETag <$> HC.getHeader resp "ETag" of
               Just x  -> pure (Just x)
               Nothing -> throwProtoFail "ETag"
      403 -> throwIO AccessDenied
      412 | Just _ <- mcond -> pure Nothing
      _   -> throwUnexpectedResp resp bs
  where
    hdrs = case macl of
             Nothing  -> []
             Just acl -> [("x-amz-acl", acl2str acl)]

    cmd5 = B64.encode (MD5.hash objdata) -- RFC1864

    bsBody :: ByteString -> Streams.OutputStream Builder.Builder -> IO ()
    bsBody bs = Streams.write (Just (Builder.byteString bs))

-- | @GET@ Object
getObject :: Connection
          -> Credentials
          -> BucketId
          -> ObjKey        -- ^ Object key
          -> IO (ETag, CType, ByteString)
getObject conn creds bid objkey = do
    now <- getCurrentTime

    let q = HC.buildRequest1 $ do
          setAWSHeaders HC.GET (bid,objkey,mempty) (mempty,noCType,now) [] creds

    (resp, bs) <- doHttpReq conn q HC.emptyBody

    case HC.getStatusCode resp of
      200 -> case mkETag <$> HC.getHeader resp "ETag" of
               Just x  -> pure (x, getCT resp, bs)
               Nothing -> throwProtoFail "ETag"
      403 -> throwIO AccessDenied
      _   -> throwUnexpectedResp resp bs

getObjectCond :: Connection
              -> Credentials
              -> BucketId
              -> ObjKey        -- ^ Object key
              -> Condition
              -> IO (Maybe (ETag, CType, ByteString))
getObjectCond conn creds bid objkey cond = do
    now <- getCurrentTime

    let q = HC.buildRequest1 $ do
              setAWSHeaders HC.GET (bid,objkey,mempty) (mempty,noCType,now) [] creds
              setConditionHeader cond

    (resp, bs) <- doHttpReq conn q HC.emptyBody

    case HC.getStatusCode resp of
      200 -> case mkETag <$> HC.getHeader resp "ETag" of
               Just x  -> pure $ Just (x, getCT resp, bs)
               Nothing -> throwProtoFail "ETag"
      304 | IfNotMatch  _ <- cond -> pure Nothing
          | IfNotExists   <- cond -> pure Nothing
      412 | IfMatch     _ <- cond -> pure Nothing
          | IfExists      <- cond -> pure Nothing -- non-sensical
      403 -> throwIO AccessDenied
      _   -> throwUnexpectedResp resp bs

-- | @DELETE@ Object
deleteObject :: Connection -> Credentials -> BucketId -> ObjKey -> IO ()
deleteObject conn creds bid objkey = do
    now <- getCurrentTime

    let q = HC.buildRequest1 $ do
              setAWSHeaders HC.DELETE (bid,objkey,mempty) (mempty,noCType,now) [] creds

    (resp, bs) <- doHttpReq conn q HC.emptyBody

    case HC.getStatusCode resp of
      204 -> pure ()
      403 -> throwIO AccessDenied
      _   -> throwUnexpectedResp resp bs


deleteObjectCond :: Connection -> Credentials -> BucketId -> ObjKey -> Condition -> IO Bool
deleteObjectCond conn creds bid objkey cond = do
    now <- getCurrentTime

    let q = HC.buildRequest1 $ do
              setAWSHeaders HC.DELETE (bid,objkey,mempty) (mempty,noCType,now) [] creds
              setConditionHeader cond

    (resp, bs) <- doHttpReq conn q HC.emptyBody

    case HC.getStatusCode resp of
      204 -> pure True
      403 -> throwIO AccessDenied
      412 -> pure False
      _   -> throwUnexpectedResp resp bs

-- | Wrapper around 'genSignatureV2', sets basic AWS headers
setAWSHeaders :: HC.Method
              -> (BucketId,ObjKey,ByteString)        -- constructs url-path
              -> (ByteString,CType,UTCTime)  -- core headers: md5,ctype,date
              -> [(ByteString,ByteString)]           -- extra headers
              -> Credentials
              -> HC.RequestBuilder ()
setAWSHeaders verb urlp@(bid,objkey,_) (cmd5,CType ctype0,date0) amzhdrs creds@(Credentials akey _) = do
    HC.http verb (mkUrlPath urlp)
    HC.setHeader "Date" date
    unless (BS.null ctype) $ HC.setContentType ctype
    unless (BS.null cmd5)  $ HC.setHeader "Content-MD5" cmd5
    forM_ amzhdrs (uncurry HC.setHeader)
    unless (BS.null akey) $
      HC.setHeader "Authorization" ("AWS " <> akey <> ":" <> signature)
  where
    signature = genSignatureV2 verb bid objkey (cmd5,ctype,date) amzhdrs creds

    date = formatRFC1123 date0
    ctype = TS.toByteString ctype0


mkUrlPath :: (BucketId, ObjKey, ByteString) -> ByteString
mkUrlPath (BucketId bucketId, objkey, query) = p <> query
  where
    p = case (BSS.null bucketId, isNullObjKey objkey) of
      (True, True)   -> "/"
      (False, True)  -> "/" <> BSS.fromShort bucketId
      (True, False)  -> error "mkUrlPath: invalid argument"
      (False, False) -> "/" <> BSS.fromShort bucketId <> "/" <> urlEncodeObjKey objkey


{- | Compute S3 v2 signature
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
genSignatureV2 :: HC.Method -> BucketId -> ObjKey -> (ByteString,ByteString,ByteString) -> [(ByteString,ByteString)] -> Credentials -> ByteString
genSignatureV2 verb bid objkey (cmd5,ctype,date) amzhdrs (Credentials _ skey) = B64.encode sig
  where
    sig = SHA1.hmac skey msg
    msg = BS.intercalate "\n" $
              [ verb'
              , cmd5
              , ctype
              , date
              ] <>
              [ k <> ":" <> v | (k,v) <- List.sort amzhdrs ] <>
              [ mkUrlPath (bid, objkey, mempty) ]

    verb' = case verb of
        HC.PUT    -> "PUT"
        HC.GET    -> "GET"
        HC.HEAD   -> "HEAD"
        HC.DELETE -> "DELETE"
        _         -> error "genSignatureV2: unsupported verb"


formatRFC1123 :: UTCTime -> ByteString
formatRFC1123 = BC8.pack . DT.formatTime defaultTimeLocale "%a, %d %b %Y %X GMT"

newtype CommonPrefixes = CommonPrefixes { unCommonPrefixes :: ObjKey }

instance FromXML CommonPrefixes where
  tagFromXML _   = s3qname "CommonPrefixes"
  parseXML_ = withChildren $ do
    k <- one (s3_xsd'string "Prefix")
    pure (CommonPrefixes (ObjKey k))

data BucketInfo = BucketInfo !BucketId !UTCTime
                deriving Show

instance FromXML BucketInfo where
  tagFromXML _   = s3qname "Bucket"
  parseXML_ = withChildren $ do
    BucketInfo <$> one (s3_xsd'string "Name")
               <*> one (s3_xsd'dateTime "CreationDate")

instance FromXML ObjMetaInfo where
    tagFromXML _   = s3qname "Contents"
    parseXML_ = withChildren $ do
        omiKey <- ObjKey <$> one (s3_xsd'string "Key")
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

data Owner = Owner { ownerID :: ShortText
                   , ownerDisplayName :: Maybe ShortText
                   } deriving Show

instance FromXML Owner where
  tagFromXML _ = s3qname "Owner"
  parseXML_ = withChildren $
    Owner <$> one (s3_xsd'string "ID")
          <*> maybeOne (s3_xsd'string "DisplayName")


data ListAllMyBucketsResult = ListAllMyBucketsResult [BucketInfo]

{-


<ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">
<Owner><ID>hackage</ID><DisplayName>hackage</DisplayName></Owner>
  <Buckets>
    <Bucket><Name>hackage-mirror</Name><CreationDate>2018-06-21T23:14:36.660Z</CreationDate></Bucket>
  </Buckets>
</ListAllMyBucketsResult>

-}

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

{- NB: The <Error> response element has no namespace

<Error>
  <Code>BucketNotEmpty</Code>
  <BucketName>hstest1</BucketName>
  <RequestId>tx000000000000002d08a23-005b80213f-5893fff-us-east-1-iad1</RequestId>
  <HostId>5893fff-us-east-1-iad1-us-east-1</HostId>
</Error>

-}

instance FromXML Error where
  tagFromXML _ = (X.unqual "Error")

  parseXML_ = withChildren $ do
    code <- one (xsd'string (X.unqual "Code"))
    void unboundedAny -- skip the rest
    pure (Error code)

----------------------------------------------------------------------------
-- XML parsing

s3qname :: X.LName -> X.QName
s3qname n = X.QName { X.qLName = n, X.qURI = s3xmlns, X.qPrefix = Nothing }
  where
    s3xmlns = "http://s3.amazonaws.com/doc/2006-03-01/"

showQN :: X.QName -> String
showQN (X.QName (X.LName ln) ns@(X.URI ns') _)
  | X.isNullURI ns = TS.unpack ln
  | otherwise      = mconcat [ "{", TS.unpack ns', "}", TS.unpack ln ]

xsd'string :: XsdString t => X.QName -> X.Element -> Either String t
xsd'string elNameExpected el
  | X.elName el /= elNameExpected
  = Left ("expected <" <> showQN elNameExpected <> "> but got <" <> showQN (X.elName el) <> "> instead")
  | not (null (X.elChildren el)) = Left ("<" <> showQN (X.elName el) <> "> schema violation")
  | otherwise = Right (fromXsdString $ X.strContent el)

xsd'dateTime :: X.QName -> X.Element -> Either String UTCTime
xsd'dateTime n el = do
  t <- xsd'string n el
  case DT.parseTime defaultTimeLocale "%Y-%m-%dT%H:%M:%S%QZ" (T.unpack t) of
    Nothing -> Left ("<" <> showQN (X.elName el) <> "> failed to decode xsd:dateTime")
    Just dt -> pure dt

xsd'long :: X.QName -> X.Element -> Either String Int64
xsd'long qn el = do
  t <- xsd'string qn el
  case readMaybe (T.unpack t) of
    Nothing -> Left ("<" <> showQN (X.elName el) <> "> failed to decode xsd:long")
    Just dt -> pure dt

xsd'int :: X.QName -> X.Element -> Either String Int32
xsd'int qn el = do
  t <- xsd'string qn el
  case readMaybe (T.unpack t) of
    Nothing -> Left ("<" <> showQN (X.elName el) <> "> failed to decode xsd:int")
    Just dt -> pure dt

xsd'enum :: X.QName -> (T.Text -> Maybe a) -> X.Element -> Either String a
xsd'enum ln f el = do
  t <- xsd'string ln el
  case f t of
    Nothing -> Left ("<" <> showQN (X.elName el) <> "> failed to decode xsd:string enumeration")
    Just dt -> pure dt

xsd'boolean :: X.QName -> X.Element -> Either String Bool
xsd'boolean ln el = do
  t <- xsd'string ln el
  case t :: T.Text of
    "true"  -> pure True
    "1"     -> pure True
    "false" -> pure False
    "0"     -> pure False
    _       -> Left ("<" <> showQN (X.elName el) <> "> failed to decode xsd:boolean enumeration")

class XsdString a where fromXsdString :: T.Text -> a
instance XsdString T.Text where fromXsdString = id
instance XsdString ShortText where fromXsdString = TS.fromText
instance XsdString ShortByteString where fromXsdString = TS.toShortByteString . TS.fromText
instance XsdString ByteString where fromXsdString = T.encodeUtf8

s3_xsd'string :: XsdString t => X.LName -> X.Element -> Either String t
s3_xsd'string = xsd'string . s3qname

s3_xsd'dateTime :: X.LName -> X.Element -> Either String UTCTime
s3_xsd'dateTime = xsd'dateTime . s3qname

s3_xsd'long :: X.LName -> X.Element -> Either String Int64
s3_xsd'long = xsd'long . s3qname

s3_xsd'int :: X.LName -> X.Element -> Either String Int32
s3_xsd'int = xsd'int . s3qname

s3_xsd'boolean :: X.LName -> X.Element -> Either String Bool
s3_xsd'boolean = xsd'boolean . s3qname

s3_xsd'enum :: X.LName -> (T.Text -> Maybe a) -> X.Element -> Either String a
s3_xsd'enum ln = xsd'enum (s3qname ln)

class FromXML a where
    parseXML_  :: X.Element -> Either String a
    tagFromXML :: Proxy a -> X.QName

parseXML :: forall a . FromXML a => X.Element -> Either String a
parseXML = parseXML' elNameExpected parseXML_
  where
    elNameExpected = tagFromXML (Proxy :: Proxy a)

parseXML' :: X.QName -> (X.Element -> Either String a) -> X.Element -> Either String a
parseXML' elNameExpected p el = do
    unless (X.elName el == elNameExpected) $
      Left ("expected <" <> showQN elNameExpected <> "> but got <" <> showQN (X.elName el) <> "> instead")
    p el


decodeXML :: forall a . FromXML a => ByteString -> Either String a
decodeXML bs = case filterContent tag <$> X.parseXML (T.decodeUtf8 bs) of
                 Right [x] -> parseXML x
                 _   -> Left ("decodeXML: failed to locate " <> show tag)
  where
    tag = tagFromXML (Proxy :: Proxy a)

filterContent :: X.QName -> [X.Content] -> [X.Element]
filterContent q = filter ((== q) . X.elName) . X.onlyElems

-- withChildren :: ([X.Element] -> Either String a) -> X.Element -> Either String a
-- withChildren h el
--   | not (T.all isSpace (X.strContent el)) = Left ("<" <> showQN (X.elName el) <> "> schema violation")
--   | otherwise = h (X.elChildren el)

withChildren :: P a -> X.Element -> Either String a
withChildren h el
  | not (T.all isSpace (X.strContent el)) = Left ("<" <> showQN (X.elName el) <> "> schema violation")
  | otherwise = go (X.elChildren el)
  where
    go els0 = do
      (els1,x) <- runP_ h els0
      case els1 of
        [] -> pure x
        e1:_ -> Left ("unexpected " <> showQN (X.elName e1))

one :: (X.Element -> Either String a) -> P a
one p = P $ \case
  []       -> Left "premature end-tag"
  el1:els  -> (,) els <$> p el1

maybeOne :: (X.Element -> Either String a) -> P (Maybe a)
maybeOne p = (Just <$> one p) <|> pure Nothing

unbounded :: (X.Element -> Either String a) -> P [a]
unbounded p = many (one p)

-- | More efficient variant of @'unbounded' 'pure'@
unboundedAny :: P [X.Element]
unboundedAny = P $ \els -> pure ([],els)

-- unbounded1 :: (X.Element -> Either String a) -> P [a] -- NonEmpty
-- unbounded1 p = some (one p)

newtype P a = P { runP_ :: [X.Element] -> Either String ([X.Element], a) }

instance Functor P where
  fmap g (P m) = P (fmap (fmap (fmap g)) m)

instance Applicative P where
  pure x = P $ \cs -> Right (cs,x)
  (<*>) = ap

instance Monad P where
  p1 >>= p2 = P $ \cs0 -> do (cs1,a) <- runP_ p1 cs0
                             runP_ (p2 a) cs1

instance Alternative P where
  empty = failP "empty"
  p1 <|> p2 = P $ \cs0 -> either (\_ -> runP_ p2 cs0) pure (runP_ p1 cs0)

failP :: String -> P a
failP msg = P $ \_ -> Left msg

-- hack; fixme
dummyEl :: X.Element
dummyEl = X.node (X.unqual "empty") ()
