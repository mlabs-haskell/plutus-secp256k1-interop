# `plutus-secp256k1-interop`

## What is this?

A collection of helpers to convert \'external\' representations of
SECP256k1-curve signature scheme components (which are suitable for
serialization and passing around) to \'internal\' representations of those same
components (which are suitable for passing to Plutus primitives).

## Which representations do you support?

Currently, we support all of the following:

* DER-encoded ECDSA scheme public keys
* DER-encoded ECDSA scheme signatures
* BIP-340-compatible Schnorr scheme public keys

## How do I use this?

The example below assumes you've received a DER-encoded public key (`derPK`) and
signature (`derSig`) from somewhere else.

```haskell
{-# LANGUAGE NoImplicitPrelude #-}

import Plutus.SECP256K1.Interop (
  revealEcdsaPubkeyState,
  revealEcdsaSignatureState,
  decodeDERPubkey,
  decodeDERSignature
  )
import PlutusTx.Builtin (
  toBuiltin,
  verifyEcdsaSecp256k1Signature
  )
import Data.ByteString (ByteString)
import Plutus.Prelude

tryAndVerify :: 
  ByteString -> 
  ByteString -> 
  ByteString -> 
  Bool
tryAndVerify derPK derSig messageHash = case go of 
  Nothing -> False -- parsing didn't go to plan
  Just (internalPK, internalSig) -> 
    verifyEcdsaSecp256k1Signature (toBuiltin internalPK) 
                                  (toBuiltin messageHash)
                                  (toBuiltin internalSig)
  where
    go :: Maybe (ByteString, ByteString)
    go = do
      internalPK <- revealEcdsaPubkeyState <$> decodeDERPubkey derPK
      internalSig <- revealEcdsaSignatureState <$> decodeDERSignature derSig
      pure (internalPK, internalSig)

```

## What can I do with this?

The code is licensed under Apache 2.0; check the LICENSE file for details.
