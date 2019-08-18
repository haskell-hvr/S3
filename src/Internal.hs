{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
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
-- Copyright: © Herbert Valerio Riedel 2016-2018
-- SPDX-License-Identifier: GPL-3.0-or-later
--
module Internal
    ( module Internal
    , ByteString
    , ShortByteString
    , ShortText
    , T.Text
    , Proxy(..)
    , NFData(rnf), force
    , UTCTime
    , Hashable
    , ap
    ) where

import qualified Codec.Base16                  as B16
import qualified Codec.Base64                  as B64
import           Control.DeepSeq
import           Control.Monad                 (ap)
import qualified Crypto.Hash.MD5               as MD5
import qualified Crypto.Hash.SHA256            as SHA256
import           Data.ByteString               (ByteString)
import qualified Data.ByteString               as BS
import qualified Data.ByteString.Char8         as BC8
import qualified Data.ByteString.Lazy          as BL
import qualified Data.ByteString.Lazy.Internal
import           Data.ByteString.Short         (ShortByteString, fromShort,
                                                toShort)
import qualified Data.ByteString.Short         as SBS
import           Data.Hashable
import           Data.Proxy
import           Data.Text                     (Text)
import qualified Data.Text                     as T
import qualified Data.Text.Encoding            as T
import           Data.Text.Short               (ShortText)
import           Data.Time                     (UTCTime)

newtype SHA256Val = SHA256Val ShortByteString
                  deriving (Eq,Ord,Hashable,NFData,Typeable)

instance Show SHA256Val where
    show = show . sha256hex

sha256hash :: BL.ByteString -> SHA256Val
sha256hash = SHA256Val . toShort . SHA256.hashlazy

sha256hex :: SHA256Val -> ByteString
sha256hex (SHA256Val x) = B16.encode (fromShort x)

-- | MD5 Hash
newtype MD5Val = MD5Val ShortByteString
               deriving (Eq,Ord,Hashable,NFData,Typeable)

instance Show MD5Val where
    show = show . md5hex

instance IsString MD5Val where
    fromString = fromMaybe (error "invalid MD5Val string-literal") . md5unhex . fromString

-- | Compute MD5 hash
md5hash :: BL.ByteString -> MD5Val
md5hash = MD5Val . toShort . MD5.hashlazy

-- | Hex-encode MD5 digest value
md5hex :: MD5Val -> ByteString
md5hex (MD5Val x) = B16.encode x

-- i.e. RFC1864
md5b64 :: MD5Val -> ByteString
md5b64 (MD5Val x) = B64.encode x

-- | Hex-decode MD5 digest value
md5unhex :: ByteString -> Maybe MD5Val
md5unhex x = case B16.decode x of
    Right d -> md5FromSBS d
    _       -> Nothing

-- | Extract MD5 digest value
md5ToSBS :: MD5Val -> ShortByteString
md5ToSBS (MD5Val x) = x

-- | Construct MD5 digest value from 16 octets
md5FromSBS :: ShortByteString -> Maybe MD5Val
md5FromSBS d | SBS.length d == 16 = Just (MD5Val d)
             | otherwise          = Nothing

-- Special reserved 'SHA256Val'
md5zero :: MD5Val
md5zero = MD5Val $ toShort $ BS.replicate 16 0

strictPair :: a -> b -> (a,b)
strictPair !a !b = (a,b)

-- | AWS S3 specific URL encoding
urlEncode :: Bool -> ByteString -> ByteString
urlEncode escapeSlash = BC8.concatMap go
  where
    go c | inRng '0' '9' c ||
           inRng 'a' 'z' c ||
           inRng 'A' 'Z' c ||
           c `elem` ['-','_','.','~'] = BC8.singleton c

         | c == '/' = if escapeSlash then "%2F" else BC8.singleton c

         | otherwise = let (h,l) = quotRem (fromIntegral $ fromEnum c) 0x10
                       in BS.pack [0x25, hex h, hex l]

    inRng x y c = c >= x && c <= y

    hex j | j < 10    = 0x30 + j
          | otherwise = 0x37 + j -- uppercase letters

urlDecodeTextUtf8 :: Text -> Maybe Text
urlDecodeTextUtf8 t0
  | (_,[]) <- chunks = Just t' -- shortcut
  | all ((==2) . T.length . fst) (snd chunks) = T.concat <$> mchunks3
  | otherwise = Nothing
  where
    mchunks3 = h chunks2
      where
        h (c1,cs) = (:) c1 . mconcat <$> mapM go cs

    go :: (Text,Text) -> Maybe [Text]
    go (x,y) = do x'  <- e2m (B16.decode x)
                  x'' <- e2m (T.decodeUtf8' x')
                  pure [x'', y]

    chunks2 = compact [] <$> chunks

    compact acc [] = [(T.concat (reverse acc),"") | not (null acc) ]
    compact acc ((octet,""):rest) = compact (octet:acc) rest
    compact acc ((octet,chunk):rest)
      | null acc = (octet,chunk) : compact [] rest
      | otherwise = (T.concat (reverse (octet:acc)),chunk) : compact [] rest

    chunks = case T.splitOn "%" t' of
               []     -> undefined -- impossible
               [_]    -> (t0,[])
               (x:xs) -> (x,fmap (T.splitAt 2) xs)

    -- MinIO appears to use application/x-www-form-urlencoded rules
    t' | T.any (=='+') t0 = T.map (\c -> if c == '+' then ' ' else c) t0
       | otherwise        = t0

e2m :: Either a1 a2 -> Maybe a2
e2m = either (\_->Nothing) Just

mkChunk :: ByteString -> BL.ByteString -> BL.ByteString
mkChunk bs bl
  | BS.null bs = bl
  | otherwise = Data.ByteString.Lazy.Internal.Chunk bs bl
