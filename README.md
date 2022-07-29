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

## What can I do with this?

The code is licensed under Apache 2.0; check the LICENSE file for details.
