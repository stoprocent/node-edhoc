#include "EdhocKeyUpdateAsyncWorker.h"

EdhocKeyUpdateAsyncWorker::EdhocKeyUpdateAsyncWorker(Napi::Env& env,
                                                     struct edhoc_context& context,
                                                     std::vector<uint8_t> contextBuffer,
                                                     CallbackType callback)
    : Napi::AsyncWorker(env),
      deferred(Napi::Promise::Deferred::New(env)),
      context(context),
      contextBuffer(contextBuffer),
      callback(std::move(callback)) {}

void EdhocKeyUpdateAsyncWorker::Execute() {
  int ret = edhoc_export_key_update(&context, contextBuffer.data(), contextBuffer.size());

  if (ret != EDHOC_SUCCESS) {
    SetError("Failed to update key.");
  }
}

void EdhocKeyUpdateAsyncWorker::OnOK() {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);
  
  callback(env);

  if(env.IsExceptionPending()) {
    deferred.Reject(env.GetAndClearPendingException().Value());
  } else {
    deferred.Resolve(env.Undefined());
  }
}

void EdhocKeyUpdateAsyncWorker::OnError(const Napi::Error& error) {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);
  
  callback(env);

  if(env.IsExceptionPending()) {
    deferred.Reject(env.GetAndClearPendingException().Value());
  } else {
    deferred.Reject(error.Value());
  }
}

Napi::Promise EdhocKeyUpdateAsyncWorker::GetPromise() {
  return deferred.Promise();
}
