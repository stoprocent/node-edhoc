#ifndef RUNNING_CONTEXT_H
#define RUNNING_CONTEXT_H

#include <napi.h>
#include <future>

#include "EdhocCredentialManager.h"
#include "EdhocCryptoManager.h"
#include "EdhocEadManager.h"

extern "C" {
#include "edhoc.h"
}

class RunningContext {
 public:
  using ArgumentsHandler = std::function<const std::vector<napi_value>&(Napi::Env)>;
  using CompletionHandler = std::function<int(Napi::Env, Napi::Value)>;
  
  RunningContext(Napi::Env env, 
                 struct edhoc_context* edhoc_context,
                 EdhocCryptoManager* cryptoManager,
                 EdhocEadManager* eadManager,
                 EdhocCredentialManager* credentialManager);

  ~RunningContext();
      
  Napi::Env GetEnv() const { return deferred_.Env(); }

  int ThreadSafeBlockingCall(Napi::Object jsObject,
                             const std::string& jsFunctionName,
                             ArgumentsHandler argumentsHandler,
                             CompletionHandler completionHandler) const;

  Napi::ThreadSafeFunction GetTsfn() const { return tsfn_; }

  void Resolve(Napi::Value value) const;

  void Reject(Napi::Value value) const;

  Napi::Promise GetPromise() const;

  // Raw pointer getters
  EdhocCryptoManager* GetCryptoManager() const { return cryptoManager_; }
  EdhocEadManager* GetEadManager() const { return eadManager_; }
  EdhocCredentialManager* GetCredentialManager() const { return credentialManager_; }
  struct edhoc_context* GetEdhocContext() const { return edhoc_context_; }

 private:
  // Store raw pointers
  struct edhoc_context* edhoc_context_;
  EdhocCryptoManager* cryptoManager_;
  EdhocEadManager* eadManager_;
  EdhocCredentialManager* credentialManager_;

  Napi::ThreadSafeFunction tsfn_;
  Napi::Promise::Deferred deferred_;
};

#endif  // RUNNING_CONTEXT_H
