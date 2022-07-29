{-# LANGUAGE CApiFFI #-}

module FFI
  ( Context,
    Pubkey,
    XonlyPubkey,
    ECDSASignature,
    contextNoPrecomp,
    ecPubkeyParse,
    ecdsaSignatureParseDer,
    xonlyPubkeyParse,
    xonlyPubkeySerialize,
    xonlyPubkeyFromPubkey,
    ecPubkeyCreate,
    ecPubkeySerialize,
    ecCompressed,
    ecUncompressed,
    contextCreate,
    contextSign,
    ecdsaSign,
    ecdsaSignatureSerializeDer,
  )
where

import Foreign.C.Types
  ( CChar,
    CInt (CInt),
    CSize (CSize),
    CUChar,
    CUInt (CUInt),
  )
import Foreign.Ptr (Ptr)

data Context

data Pubkey

data ECDSASignature

data XonlyPubkey

foreign import ccall unsafe "ffi.h context_no_precomp"
  contextNoPrecomp :: Ptr Context

foreign import ccall unsafe "secp256k1.h secp256k1_ec_pubkey_parse"
  ecPubkeyParse ::
    Ptr Context -> -- initialized context
    Ptr Pubkey -> -- out-parameter to write to
    Ptr CUChar -> -- input data
    CSize -> -- length of input data
    IO CInt -- 1 on success, 0 on parse failure

foreign import ccall unsafe "secp256k1.h secp256k1_ecdsa_signature_parse_der"
  ecdsaSignatureParseDer ::
    Ptr Context -> -- initialized context
    Ptr ECDSASignature -> -- out-parameter to write to
    Ptr CUChar -> -- input data
    CSize -> -- length of input data
    IO CInt -- 1 on success, 0 on parse failure

foreign import ccall unsafe "secp256k1_extrakeys.h secp256k1_xonly_pubkey_parse"
  xonlyPubkeyParse ::
    Ptr Context -> -- initialized context
    Ptr XonlyPubkey -> -- out-parameter to write to
    Ptr CUChar -> -- input data (must be 32 bytes long)
    IO CInt -- 1 on success, 0 on parse failure

foreign import ccall unsafe "secp256k1.h secp256k1_ec_pubkey_create"
  ecPubkeyCreate ::
    Ptr Context -> -- initialized context
    Ptr Pubkey -> -- out-parameter to write to
    Ptr CUChar -> -- 32-byte secret key
    IO CInt -- 1 on success, 0 on error

foreign import ccall unsafe "secp256k1.h secp256k1_ec_pubkey_serialize"
  ecPubkeySerialize ::
    Ptr Context -> -- initialized context
    Ptr CUChar -> -- 33 (if compressed) or 65 (if not) byte out-param to write to
    Ptr CSize -> -- indicates how much we wrote
    Ptr Pubkey -> -- key to serialize
    CUInt -> -- flags (one of ecCompressed or ecUncompressed)
    IO CInt -- always 1

foreign import capi "secp256k1.h value SECP256K1_EC_COMPRESSED"
  ecCompressed :: CUInt

foreign import capi "secp256k1.h value SECP256K1_EC_UNCOMPRESSED"
  ecUncompressed :: CUInt

foreign import ccall unsafe "secp256k1.h secp256k1_context_create"
  contextCreate ::
    CUInt -> -- flags (only contextSign)
    IO (Ptr Context)

foreign import capi "secp256k1.h value SECP256K1_CONTEXT_SIGN"
  contextSign :: CUInt

foreign import ccall unsafe "secp256k1_extrakeys.h secp256k1_xonly_pubkey_from_pubkey"
  xonlyPubkeyFromPubkey ::
    Ptr Context -> -- initialized context
    Ptr XonlyPubkey -> -- out-parameter to write to
    Ptr CInt -> -- always NULL
    Ptr Pubkey -> -- pubkey to convert
    IO CInt -- always 1

foreign import ccall unsafe "secp256k1_extrakeys.h secp256k1_xonly_pubkey_serialize"
  xonlyPubkeySerialize ::
    Ptr Context -> -- initialized context
    Ptr CUChar -> -- 32-byte out-parameter to write to
    Ptr XonlyPubkey -> -- xonly pubkey to serialize
    IO CInt -- always 1

foreign import ccall unsafe "secp256k1.h secp256k1_ecdsa_sign"
  ecdsaSign ::
    Ptr Context -> -- context initialized for signing
    Ptr ECDSASignature -> -- out-parameter to store signature
    Ptr CUChar -> -- 32-byte message hash
    Ptr CUChar -> -- 32-byte secret key
    Ptr CChar -> -- always NULL
    Ptr CChar -> -- always NULL
    IO CInt -- 1 on success, 0 on error

foreign import ccall unsafe "secp256k1.h secp256k1_ecdsa_signature_serialize_der"
  ecdsaSignatureSerializeDer ::
    Ptr Context -> -- initialized context
    Ptr CUChar -> -- out-parameter for serialized form
    Ptr CSize -> -- stores length and how much we wrote
    Ptr ECDSASignature -> -- signature to serialize
    IO CInt -- 1 if there was enough space, 0 otherwise
