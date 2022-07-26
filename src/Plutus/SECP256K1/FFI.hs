{-# LANGUAGE CApiFFI #-}

module Plutus.SECP256K1.FFI
  ( Context,
    ECDSAPubkey,
    ECDSASignature,
    contextNone,
    ecCompressed,
    ecUncompressed,
    ecPubkeyParse,
    contextCreate,
    contextDestroy,
    ecdsaSignatureParseDer,
  )
where

import Foreign.C.Types
  ( CInt (CInt),
    CSize (CSize),
    CUChar,
    CUInt (CUInt),
  )
import Foreign.Ptr (FunPtr, Ptr)

data Context

data ECDSAPubkey

data ECDSASignature

foreign import capi "secp256k1.h value SECP256K1_CONTEXT_NONE"
  contextNone :: CUInt

foreign import capi "secp256k1.h value SECP256K1_EC_COMPRESSED"
  ecCompressed :: CUInt

foreign import capi "secp256k1.h value SECP256K1_EC_UNCOMPRESSED"
  ecUncompressed :: CUInt

foreign import ccall unsafe "secp256k1.h secp256k1_ec_pubkey_parse"
  ecPubkeyParse ::
    Ptr Context -> -- initialized context
    Ptr ECDSAPubkey -> -- out-parameter to write to
    Ptr CUChar -> -- input data
    CSize -> -- length of input data
    IO CInt -- 1 on success, 0 on parse failure

foreign import ccall unsafe "secp256k1.h secp256k1_context_create"
  contextCreate ::
    CUInt -> -- flags
    IO (Ptr Context) -- initialized context

foreign import ccall unsafe "secp256k1.h &secp256k1_context_destroy"
  contextDestroy :: FunPtr (Ptr Context -> IO ())

foreign import ccall unsafe "secp256k1.h ecp256k1_ecdsa_signature_parse_der"
  ecdsaSignatureParseDer ::
    Ptr Context -> -- initialized context
    Ptr ECDSASignature -> -- out-parameter to write to
    Ptr CUChar -> -- input data
    CSize -> -- length of input data
    IO CInt -- 1 on success, 0 on parse failure
