#include <napi.h>
#include "LibEDHOC.h"
#include "EdhocCryptoManagerWrapper.h"

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    EdhocCryptoManagerWrapper::Init(env, exports);
    LibEDHOC::Init(env, exports);
    return exports;
}

NODE_API_MODULE(addon, Init)