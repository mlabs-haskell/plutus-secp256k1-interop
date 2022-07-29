{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Main (main) where

import Control.Monad (unless, (>=>))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Unsafe
  ( unsafePackMallocCStringLen,
    unsafeUseAsCStringLen,
  )
import Data.Kind (Type)
import FFI
  ( Context,
    Pubkey,
    XonlyPubkey,
    contextCreate,
    contextNoPrecomp,
    contextSign,
    ecCompressed,
    ecPubkeyCreate,
    ecPubkeySerialize,
    ecUncompressed,
    ecdsaSign,
    ecdsaSignatureSerializeDer,
    xonlyPubkeyFromPubkey,
    xonlyPubkeySerialize,
  )
import Foreign.C.Types (CUChar, CUInt)
import Foreign.Marshal.Alloc (alloca, mallocBytes)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (peek, poke)
import GHC.Exts (fromListN)
import GHC.IO.Encoding (setLocaleEncoding, utf8)
import Numeric (showHex)
import Plutus.SECP256K1.Interop
  ( decodeBIP340Pubkey,
    decodeDERPubkey,
    decodeDERSignature,
    revealEcdsaPubkeyState,
    revealEcdsaSignatureState,
    revealSchnorrPubkeyState,
  )
import System.IO.Unsafe (unsafeDupablePerformIO, unsafePerformIO)
import Test.QuickCheck
  ( Gen,
    Property,
    arbitrary,
    counterexample,
    forAllShow,
    property,
  )
import qualified Test.QuickCheck.Gen as Gen
import Test.Tasty (adjustOption, defaultMain, testGroup)
import Test.Tasty.QuickCheck (QuickCheckTests, testProperty)

main :: IO ()
main = do
  setLocaleEncoding utf8
  defaultMain . adjustOption go . testGroup "Properties" $
    [ testGroup
        "ECDSA"
        [ testGroup
            "Pubkey"
            [ testProperty "Compressed DER" propCompressedDER,
              testProperty "Uncompressed DER" propUncompressedDER
            ],
          testGroup
            "Signature"
            [ testProperty "DER" propSignatureDER
            ]
        ],
      testGroup
        "Schnorr"
        [ testGroup
            "Pubkey"
            [ testProperty "BIP-340" propBIP340Pubkey
            ]
        ]
    ]
  where
    go :: QuickCheckTests -> QuickCheckTests
    go = max 10_000

-- Properties

{-# NOINLINE propSignatureDER #-}
propSignatureDER :: Property
propSignatureDER = forAllShow gen showCase $ \(expected, input) -> do
  let actual = revealEcdsaSignatureState <$> decodeDERSignature input
   in counterexample (showFailure actual) . property $ case actual of
        Nothing -> False
        Just res -> res == expected
  where
    gen :: Gen (ByteString, ByteString)
    gen = do
      secretKey <- fromListN 32 <$> Gen.vectorOf 32 arbitrary
      messageHash <- fromListN 32 <$> Gen.vectorOf 32 arbitrary
      pure . unsafeDupablePerformIO . unsafeUseAsCStringLen secretKey $ \(skp, _) ->
        unsafeUseAsCStringLen messageHash $ \(msgp, _) -> do
          sigp <- mallocBytes 64
          res <- ecdsaSign signingCtx sigp (castPtr msgp) (castPtr skp) nullPtr nullPtr
          unless (res == 1) (error "Could not sign")
          alloca $ \lenp -> do
            serializedp <- mallocBytes 128 -- way more than we should need
            poke lenp 128
            res' <- ecdsaSignatureSerializeDer contextNoPrecomp serializedp lenp sigp
            unless (res' == 1) (error "Not enough memory to serialize")
            actualLen <- peek lenp
            expected <- unsafePackMallocCStringLen (castPtr sigp, 64)
            input <- unsafePackMallocCStringLen (castPtr serializedp, fromIntegral actualLen)
            pure (expected, input)

propBIP340Pubkey :: Property
propBIP340Pubkey =
  verKeyProp
    revealSchnorrPubkeyState
    decodeBIP340Pubkey
    (mkPubkey >=> toXonlyPubkey)
    mkBIP340

propCompressedDER :: Property
propCompressedDER =
  verKeyProp
    revealEcdsaPubkeyState
    decodeDERPubkey
    mkPubkey
    (mkDER ecCompressed)

propUncompressedDER :: Property
propUncompressedDER =
  verKeyProp
    revealEcdsaPubkeyState
    decodeDERPubkey
    mkPubkey
    (mkDER ecUncompressed)

verKeyProp ::
  forall (a :: Type) (b :: Type).
  (a -> ByteString) ->
  (ByteString -> Maybe a) ->
  (Ptr CUChar -> IO ByteString) ->
  (Ptr b -> IO ByteString) ->
  Property
verKeyProp reveal decode mkVerKey mkSerial =
  forAllShow (genVKCase mkVerKey mkSerial) showCase $ \(expected, input) -> do
    let actual = reveal <$> decode input
     in counterexample (showFailure actual)
          . property
          $ case actual of
            Nothing -> False
            Just res -> res == expected

-- Generators

{-# NOINLINE genVKCase #-}
genVKCase ::
  forall (a :: Type).
  (Ptr CUChar -> IO ByteString) ->
  (Ptr a -> IO ByteString) ->
  Gen (ByteString, ByteString)
genVKCase mkVK mkSerial = do
  secretKey <- fromListN 32 <$> Gen.vectorOf 32 arbitrary
  pure . unsafeDupablePerformIO . unsafeUseAsCStringLen secretKey $ \(skp, _) -> do
    verkey <- mkVK . castPtr $ skp
    serialized <- unsafeUseAsCStringLen verkey $ \(vkp, _) -> mkSerial (castPtr vkp)
    pure (verkey, serialized)

-- Helpers

mkPubkey :: Ptr CUChar -> IO ByteString
mkPubkey skp = do
  pkp <- mallocBytes 64
  res <- ecPubkeyCreate signingCtx pkp skp
  case res of
    1 -> unsafePackMallocCStringLen (castPtr pkp, 64)
    _ -> error "Could not generate ECDSA pubkey"

toXonlyPubkey :: ByteString -> IO ByteString
toXonlyPubkey bs = unsafeUseAsCStringLen bs $ \(pkp, _) -> do
  xopkp <- mallocBytes 64
  _ <- xonlyPubkeyFromPubkey signingCtx xopkp nullPtr (castPtr pkp)
  unsafePackMallocCStringLen (castPtr xopkp, 64)

mkBIP340 :: Ptr XonlyPubkey -> IO ByteString
mkBIP340 xopkp = do
  serializedp <- mallocBytes 32
  _ <- xonlyPubkeySerialize contextNoPrecomp serializedp xopkp
  unsafePackMallocCStringLen (castPtr serializedp, 32)

mkDER :: CUInt -> Ptr Pubkey -> IO ByteString
mkDER compression pkp = do
  let len = if compression == ecCompressed then 33 else 65
  let clen = fromIntegral len
  serializedp <- mallocBytes len
  alloca $ \lenp -> do
    poke lenp clen
    _ <- ecPubkeySerialize contextNoPrecomp serializedp lenp pkp compression
    writtenLen <- peek lenp
    unless (writtenLen == clen) (error "Didn't serialize ECDSA pubkey properly")
    unsafePackMallocCStringLen (castPtr serializedp, len)

hexByteString :: ByteString -> String
hexByteString bs = "0x" <> BS.foldr showHex "" bs

-- We need a signing context to generate our data, so we make one here and share
-- it everywhere. This is safe as long as nobody else gets to touch it.
{-# NOINLINE signingCtx #-}
signingCtx :: Ptr Context
signingCtx = unsafePerformIO . contextCreate $ contextSign

showCase :: (ByteString, ByteString) -> String
showCase (expected, input) =
  "Expected: "
    <> hexByteString expected
    <> "\n"
    <> "Input: "
    <> hexByteString input
    <> "\n"

showFailure :: Maybe ByteString -> String
showFailure = \case
  Nothing -> "Input did not deserialize."
  Just failure -> "Actual: " <> hexByteString failure
