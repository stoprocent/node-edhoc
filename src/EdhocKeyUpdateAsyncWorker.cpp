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
  try {
    int ret = edhoc_export_key_update(&context, contextBuffer.data(), contextBuffer.size());

    if (ret != EDHOC_SUCCESS) {
      SetError("Failed to update key.");
    }
  } catch (const std::exception& e) {
    SetError(e.what());
  }
}

void EdhocKeyUpdateAsyncWorker::OnOK() {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);
  deferred.Resolve(env.Undefined());
  callback(env);
}

void EdhocKeyUpdateAsyncWorker::OnError(const Napi::Error& error) {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);
  deferred.Reject(error.Value());
  callback(env);
}

Napi::Promise EdhocKeyUpdateAsyncWorker::GetPromise() {
  return deferred.Promise();
}
