{-# LANGUAGE DerivingVia #-}

module Plutus.SECP256K1.Interop
  ( -- * Types
    ECDSAPubkeyState,
    ECDSASignatureState,

    -- * Functions

    -- ** Decoding
    decodeDERPubkey,
    decodeDERSignature,

    -- ** Extraction
    revealEcdsaPubkeyState,
    revealEcdsaSignatureState,
  )
where

import Control.Exception (mask_)
import Data.ByteString (ByteString)
import Data.ByteString.Unsafe
  ( unsafePackMallocCStringLen,
    unsafeUseAsCStringLen,
  )
import Data.Functor (($>))
import Foreign.ForeignPtr (ForeignPtr, newForeignPtr, withForeignPtr)
import Foreign.Marshal.Alloc (free, mallocBytes)
import Foreign.Ptr (castPtr)
import Plutus.SECP256K1.FFI
  ( Context,
    contextCreate,
    contextDestroy,
    contextNone,
    ecPubkeyParse,
    ecdsaSignatureParseDer,
  )
import System.IO.Unsafe (unsafeDupablePerformIO, unsafePerformIO)

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
{-# NOINLINE decodeDERPubkey #-}
decodeDERPubkey :: ByteString -> Maybe ECDSAPubkeyState
decodeDERPubkey bs =
  unsafeDupablePerformIO . unsafeUseAsCStringLen bs $ \(ptr, len) ->
    withForeignPtr ctxPtr $ \ctx -> do
      dst <- mallocBytes 64
      res <- ecPubkeyParse ctx dst (castPtr ptr) (fromIntegral len)
      case res of
        1 -> pure . ECDSAPKS_ <$> unsafePackMallocCStringLen (castPtr dst, 64)
        _ -> free dst $> Nothing

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
{-# NOINLINE decodeDERSignature #-}
decodeDERSignature :: ByteString -> Maybe ECDSASignatureState
decodeDERSignature bs =
  unsafeDupablePerformIO . unsafeUseAsCStringLen bs $ \(ptr, len) ->
    withForeignPtr ctxPtr $ \ctx -> do
      dst <- mallocBytes 64
      res <- ecdsaSignatureParseDer ctx dst (castPtr ptr) (fromIntegral len)
      case res of
        1 -> pure . ECDSASS_ <$> unsafePackMallocCStringLen (castPtr dst, 64)
        _ -> free dst $> Nothing

-- Helpers

-- We create a single context, which can only be used for serialization and
-- deserialization, and use it everywhere. This saves considerable time, and is
-- safe, provided nobody but us ever gets to touch it.
--
-- We do _not_ make this dupable, as the whole point is _not_ to compute it more
-- than once!
{-# NOINLINE ctxPtr #-}
ctxPtr :: ForeignPtr Context
ctxPtr = unsafePerformIO . mask_ $ do
  ctx <- contextCreate contextNone
  newForeignPtr contextDestroy ctx
