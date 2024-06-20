#include <napi.h>

#include "EdhocCredentialManagerWrapper.h"
#include "EdhocCryptoManagerWrapper.h"
#include "LibEDHOC.h"

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  // Initialize the EdhocCryptoManagerWrapper
  EdhocCryptoManagerWrapper::Init(env, exports);

  // Initialize the EdhocCredentialManagerWrapper
  EdhocCredentialManagerWrapper::Init(env, exports);

  // Initialize the LibEDHOC
  LibEDHOC::Init(env, exports);

  return exports;
}

NODE_API_MODULE(addon, Init)