#include "RunningContext.h"
#include <iostream>
RunningContext::RunningContext(Napi::Env env, 
                 struct edhoc_context* edhoc_context,
                 EdhocCryptoManager* cryptoManager,
                 EdhocEadManager* eadManager,
                 EdhocCredentialManager* credentialManager,
                 const Napi::Function& logger) 
    : edhoc_context_(edhoc_context)
    , cryptoManager_(cryptoManager)
    , eadManager_(eadManager)
    , credentialManager_(credentialManager)
    , tsfn_()
    , deferred_(Napi::Promise::Deferred::New(env))
    , loggerRef_(Napi::Weak(logger))
    , isResolved_(false)
{
    Napi::Function jsCallback = Napi::Function::New(env, [](const Napi::CallbackInfo& info) { return Napi::Value(); });
    this->tsfn_ = Napi::ThreadSafeFunction::New(env, jsCallback, "jsCallback", 0, 1, this);
}

int RunningContext::ThreadSafeBlockingCall(
    Napi::ObjectReference& jsObjectRef,
    const std::string& jsFunctionName,
    ArgumentsHandler argumentsHandler,
    CompletionHandler completionHandler)
{
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  this->tsfn_.BlockingCall(&promise, [this, &jsObjectRef, jsFunctionName, argumentsHandler, completionHandler](Napi::Env env, Napi::Function jsCallback, std::promise<int>* promise) {
    Napi::HandleScope scope(env);
    auto deferred = Napi::Promise::Deferred::New(env);
    try {
      const std::vector<napi_value> arguments = argumentsHandler(env);
      Napi::Function jsFunction = jsObjectRef.Value().Get(jsFunctionName).As<Napi::Function>();
      Napi::Value result = jsFunction.Call(jsObjectRef.Value(), arguments);
      deferred.Resolve(result);
    } catch (const Napi::Error& e) {
      deferred.Reject(e.Value());
    } catch (const std::exception& e) {
      deferred.Reject(Napi::Error::New(env, e.what()).Value());
    }

    auto thenCallback = Napi::Function::New(env, [this, promise, completionHandler](const Napi::CallbackInfo& info) {
      Napi::Env env = info.Env();
      Napi::HandleScope scope(env);
      try {
        int result = completionHandler(env, info[0].As<Napi::Value>());
        promise->set_value(result);
      } catch (const Napi::Error& e) {
        this->Reject(info[0].As<Napi::Error>().Value());
        promise->set_value(EDHOC_ERROR_GENERIC_ERROR);
      } catch (const std::exception& e) {
        this->Reject(Napi::Error::New(env, e.what()).Value());
        promise->set_value(EDHOC_ERROR_GENERIC_ERROR);
      }
    });

    auto catchCallback = Napi::Function::New(env, [this, promise](const Napi::CallbackInfo& info) {
      Napi::Env env = info.Env();
      Napi::HandleScope scope(env);
      this->Reject(info[0].As<Napi::Error>().Value());
      promise->set_value(EDHOC_ERROR_GENERIC_ERROR);
    });

    Napi::Promise promise_ = deferred.Promise();
    promise_.Get("then").As<Napi::Function>().Call(promise_, { thenCallback, catchCallback });
  });  

  future.wait();
  return future.get();
}

void RunningContext::Resolve(Napi::Value value) {
    if (isResolved_) {
        return;
    }
    deferred_.Resolve(value);
    tsfn_.Release();
    isResolved_ = true;
}

void RunningContext::Reject(Napi::Value value) {
  if (isResolved_) {
    return;
  }
  deferred_.Reject(value);
  tsfn_.Release();
  isResolved_ = true;
}

Napi::Promise RunningContext::GetPromise() const {
    return deferred_.Promise();
} 