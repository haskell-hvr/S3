{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE OverloadedStrings   #-}
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

-- | XML utilities
--
-- Copyright: © Herbert Valerio Riedel 2016-2019
-- SPDX-License-Identifier: GPL-3.0-or-later
module Network.S3.XML where

import           Internal
import           Network.S3.Types

import qualified Data.ByteString.Lazy    as BL
import           Data.Char
import qualified Data.Text               as T
import qualified Data.Text.Lazy.Encoding as TL
import qualified Data.Text.Short         as TS
import qualified Data.Time.Format        as DT
import           Text.Read               (readMaybe)
import qualified Text.XML                as X

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
  case DT.parseTime DT.defaultTimeLocale "%Y-%m-%dT%H:%M:%S%QZ" (T.unpack t) of
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

-- via 'FromXML' instance
parseXML :: forall a . FromXML a => X.Element -> Either String a
parseXML = parseXML' elNameExpected parseXML_
  where
    elNameExpected = tagFromXML (Proxy :: Proxy a)

-- direct parsing via inline parser
parseXML' :: X.QName -> (X.Element -> Either String a) -> X.Element -> Either String a
parseXML' elNameExpected p el = do
    unless (X.elName el == elNameExpected) $
      Left ("expected <" <> showQN elNameExpected <> "> but got <" <> showQN (X.elName el) <> "> instead")
    p el


decodeXML :: forall a . FromXML a => BL.ByteString -> Either String a
decodeXML bs = case filterContent tag <$> (X.parseXML =<< decUtf8 bs) of
                 Right [x] -> parseXML x
                 _   -> Left ("decodeXML: failed to locate " <> show tag)
  where
    tag = tagFromXML (Proxy :: Proxy a)
    decUtf8 = either (\_ -> Left (0,"invalid UTF-8")) Right . TL.decodeUtf8'

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
        []   -> pure x
        e1:_ -> Left ("unexpected " <> showQN (X.elName e1))

one :: (X.Element -> Either String a) -> P a
one p = P $ \case
    []       -> Left "premature end-tag"
    el1:els  -> (,) els <$> p el1

aheadOne :: (X.Element -> Bool) -> (X.Element -> Either String a) -> P a
aheadOne c p = P $ \els0 -> case break c els0 of
    (_,[])               -> Left "premature end-tag"
    (preEls,el1:postEls) -> (,) (preEls<>postEls) <$> p el1

maybeOne :: (X.Element -> Either String a) -> P (Maybe a)
maybeOne p = (Just <$> one p) <|> pure Nothing

aheadMaybeOne :: (X.Element -> Bool) -> (X.Element -> Either String a) -> P (Maybe a)
aheadMaybeOne c p = (Just <$> aheadOne c p) <|> pure Nothing


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
  return = pure
  p1 >>= p2 = P $ \cs0 -> do (cs1,a) <- runP_ p1 cs0
                             runP_ (p2 a) cs1

instance Alternative P where
  empty = failP "empty"
  p1 <|> p2 = P $ \cs0 -> either (\_ -> runP_ p2 cs0) pure (runP_ p1 cs0)

failP :: String -> P a
failP msg = P $ \_ -> Left msg
