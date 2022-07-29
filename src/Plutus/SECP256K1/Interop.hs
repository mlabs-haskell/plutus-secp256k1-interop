{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module: Plutus.SECP256K1.Interop
-- Copyright: (C) MLabs 2022
-- License: Apache 2.0
-- Maintainer: Koz Ross <koz@mlabs.city>
-- Portability: GHC only
-- Stability: Experimental
--
-- Provides a collection of interoperation wrappers for ECDSA and Schnorr
-- signature schemes between the verification on-chain primitives (and their
-- argument expectations) and typical serialized forms.
--
-- This is needed as the \'external\' forms of ECDSA scheme public keys and
-- signatures, as well as Schnorr scheme public keys, do not one-for-one
-- correspond to the \'internal\' forms of these same things that are consumed
-- by the Plutus primitives for verification. This module allows you to
-- conveniently convert from \'external\' to \'internal\' forms.
module Plutus.SECP256K1.Interop
  ( -- * Types
    ECDSAPubkeyState,
    ECDSASignatureState,
    SchnorrPubkeyState,

    -- * Functions

    -- ** Decoding
    decodeDERPubkey,
    decodeDERSignature,
    decodeBIP340Pubkey,

    -- ** Extraction
    revealEcdsaPubkeyState,
    revealEcdsaSignatureState,
    revealSchnorrPubkeyState,
  )
where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Unsafe
  ( unsafePackMallocCStringLen,
    unsafeUseAsCStringLen,
  )
import Data.Functor (($>))
import Data.Kind (Type)
import FFI
  ( Context,
    contextNoPrecomp,
    ecPubkeyParse,
    ecdsaSignatureParseDer,
    xonlyPubkeyParse,
  )
import Foreign.C.Types (CInt)
import Foreign.Marshal.Alloc (free, mallocBytes)
import Foreign.Ptr (Ptr, castPtr)
import System.IO.Unsafe (unsafeDupablePerformIO)

-- | The \'internal state\' of an ECDSA public (verification) key, suitable for
-- passing to the @verifyEcdsaSecp256k1Signature@ primitive after unwrapping.
--
-- @since 1.0.0
newtype ECDSAPubkeyState = ECDSAPKS_ ByteString
  deriving
    ( -- | @since 1.0.0
      Eq
    )
    via ByteString
  deriving stock
    ( -- | @since 1.0.0
      Show
    )

-- | Reveal the internal representation wrapped by 'ECDSAPubkeyState', so that
-- it can be passed to on-chain primitives.
--
-- = Note
--
-- This data should be considered an internal detail. While we can't stop you
-- serializing it directly, or passing it to other things, this can be quite
-- dangerous. Essentially, the result of this function /should/ be used /only/
-- to pass an argument to @verifyEcdsaSecp256k1Signature@.
--
-- @since 1.0.0
revealEcdsaPubkeyState :: ECDSAPubkeyState -> ByteString
revealEcdsaPubkeyState (ECDSAPKS_ bs) = bs

-- | Given a DER-encoded representation of an ECDSA public (verification) key,
-- attempts to decode it; returns 'Nothing' if the decoding fails. This accepts
-- both compressed and uncompressed representations.
--
-- @since 1.0.0
decodeDERPubkey :: ByteString -> Maybe ECDSAPubkeyState
decodeDERPubkey =
  runAllocating
    (\ctx dst ptr len -> ecPubkeyParse ctx dst (castPtr ptr) (fromIntegral len))
    64
    ECDSAPKS_

-- | The \'internal state\' of an ECDSA signature, suitable for passing to the
-- @verifyEcdsaSecp256k1Signature@ primitive after unwrapping.
--
-- @since 1.0.0
newtype ECDSASignatureState = ECDSASS_ ByteString
  deriving
    ( -- | @since 1.0.0
      Eq
    )
    via ByteString
  deriving stock
    ( -- | @since 1.0.0
      Show
    )

-- | Reveal the internal representation wrapped by 'ECDSASignatureState', so that
-- it can be passed to on-chain primitives.
--
-- = Note
--
-- This data should be considered an internal detail. While we can't stop you
-- serializing it directly, or passing it to other things, this can be quite
-- dangerous. Essentially, the result of this function /should/ be used /only/
-- to pass an argument to @verifyEcdsaSecp256k1Signature@.
--
-- @since 1.0.0
revealEcdsaSignatureState :: ECDSASignatureState -> ByteString
revealEcdsaSignatureState (ECDSASS_ bs) = bs

-- | Given a DER-encoded representation of an ECDSA signature, attempts to
-- decode it; returns 'Nothing' if the decoding fails.
--
-- @since 1.0.0
decodeDERSignature :: ByteString -> Maybe ECDSASignatureState
decodeDERSignature =
  runAllocating
    (\ctx dst ptr len -> ecdsaSignatureParseDer ctx dst (castPtr ptr) (fromIntegral len))
    64
    ECDSASS_

-- | The \'internal state\' of a Schnorr public (verification) key, suitable for
-- passing to the @verifySchnorrSecp256k1Signature@ primitive after unwrapping.
--
-- @since 1.0.0
newtype SchnorrPubkeyState = SchnorrPKS_ ByteString
  deriving
    ( -- | @since 1.0.0
      Eq
    )
    via ByteString
  deriving stock
    ( -- | @since 1.0.0
      Show
    )

-- | Reveal the internal representation wrapped by 'SchnorrPubkeyState', so that
-- it can be passed to on-chain primitives.
--
-- = Note
--
-- This data should be considered an internal detail. While we can't stop you
-- serializing it directly, or passing it to other things, this can be quite
-- dangerous. Essentially, the result of this function /should/ be used /only/
-- to pass an argument to @verifySchnorrSecp256k1Signature@.
--
-- @since 1.0.0
revealSchnorrPubkeyState :: SchnorrPubkeyState -> ByteString
revealSchnorrPubkeyState (SchnorrPKS_ bs) = bs

-- | Given a BIP-340-compliant representation of a Schnorr public (verification)
-- key, attempts to decode it; returns 'Nothing' if the decoding fails.
--
-- @since 1.0.0
decodeBIP340Pubkey :: ByteString -> Maybe SchnorrPubkeyState
decodeBIP340Pubkey bs
  | BS.length bs /= 32 = Nothing
  | otherwise =
    runAllocating
      (\ctx dst ptr _ -> xonlyPubkeyParse ctx dst (castPtr ptr))
      64
      SchnorrPKS_
      bs

-- Helpers

{-# NOINLINE runAllocating #-}
runAllocating ::
  forall (b :: Type) (a :: Type) (c :: Type).
  (Ptr Context -> Ptr a -> Ptr c -> Int -> IO CInt) ->
  Int ->
  (ByteString -> b) ->
  ByteString ->
  Maybe b
runAllocating f dstLen wrap input =
  unsafeDupablePerformIO . unsafeUseAsCStringLen input $ \(ptr, len) -> do
    dst <- mallocBytes dstLen
    res <- f contextNoPrecomp dst (castPtr ptr) (fromIntegral len)
    case res of
      1 -> pure . wrap <$> unsafePackMallocCStringLen (castPtr dst, dstLen)
      _ -> free dst $> Nothing
