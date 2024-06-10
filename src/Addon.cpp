#include <napi.h>
#include "LibEDHOC.h"
#include "EdhocCryptoManagerWrapper.h"

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    // Initialize the EdhocCryptoManagerWrapper
    EdhocCryptoManagerWrapper::Init(env, exports);
    // Initialize the LibEDHOC
    LibEDHOC::Init(env, exports);
    return exports;
}

NODE_API_MODULE(addon, Init)