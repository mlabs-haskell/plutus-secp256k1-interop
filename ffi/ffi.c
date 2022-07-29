#include "ffi.h"

secp256k1_context *context_no_precomp(void) {
  return (secp256k1_context *)secp256k1_context_no_precomp;
}
