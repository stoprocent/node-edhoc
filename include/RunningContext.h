#ifndef LIB_EDHOC_H
#define LIB_EDHOC_H

#include <napi.h>

#include "EdhocCryptoManager.h"
#include "EdhocEadManager.h"
#include "EdhocCredentialManager.h"

extern "C" {
#include "edhoc.h"
}

class RunningContext {
 public:
  using CompletionHandler = std::function<void(Napi::Env, Napi::Value)>;
  
  RunningContext(LibEDHOC* libEDHOC);

  
  void BlockingCall(Napi::Env env,
                    Napi::Object jsObject,
                    const std::string& jsFunctionName,
                    const std::vector<napi_value>& arguments,
                    CompletionHandler completionHandler);


  Napi::Promise GetPromise();

 private:
  LibEDHOC* libEDHOC_;
  Napi::ThreadSafeFunction tsfn_;
  Napi::Promise::Deferred deferred_;
};

#endif  // LIB_EDHOC_H
