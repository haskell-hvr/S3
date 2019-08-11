{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- |
-- Copyright: © Herbert Valerio Riedel 2016-2018
-- SPDX-License-Identifier: GPL-3.0-or-later
--
module Internal
    ( module Internal
    , ByteString
    , ShortByteString
    , ShortText
    , Proxy(..)
    , NFData(rnf), force
    ) where

import           Control.DeepSeq
import qualified Crypto.Hash.MD5        as MD5
import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as BS
import qualified Codec.Base16 as B16
import           Data.Text.Short        (ShortText)
import           Data.ByteString.Short  (ShortByteString, fromShort, toShort)
import           Data.Hashable
import           Data.Proxy

newtype SHA256Val = SHA256Val ShortByteString
                  deriving (Eq,Ord,Hashable,NFData,Show)

instance IsString MD5Val where
    fromString = fromMaybe (error "invalid MD5Val string-literal") . md5unhex . fromString

newtype MD5Val    = MD5Val    ShortByteString
                  deriving (Eq,Ord,Hashable,NFData)

instance Show MD5Val where
    show = show . md5hex

md5hash :: ByteString -> MD5Val
md5hash = MD5Val . toShort . MD5.hash

md5hex :: MD5Val -> ByteString
md5hex (MD5Val x) = B16.encode (fromShort x)

md5unhex :: ByteString -> Maybe MD5Val
md5unhex x = case B16.decode x of
    Right d | BS.length d == 16 -> Just (MD5Val (toShort d))
    _                           -> Nothing

-- Special reserved 'SHA256Val'
md5zero :: MD5Val
md5zero = MD5Val $ toShort $ BS.replicate 16 0

strictPair :: a -> b -> (a,b)
strictPair !a !b = (a,b)

-- strictTriple :: a -> b -> c -> (a,b,c)
-- strictTriple !a !b !c = (a,b,c)



