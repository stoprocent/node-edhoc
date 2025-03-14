#include "EdhocKeyExporterAsyncWorker.h"

static constexpr const char* kErrorMessageFormat = "Failed to export the key. Error code: %d.";
static constexpr size_t kErrorBufferSize = 100;

EdhocKeyExporterAsyncWorker::EdhocKeyExporterAsyncWorker(Napi::Env& env,
                                                         struct edhoc_context& context,
                                                         uint16_t label,
                                                         uint8_t desiredLength,
                                                         CallbackType callback)
    : Napi::AsyncWorker(env),
      deferred(Napi::Promise::Deferred::New(env)),
      context(context),
      label(label),
      desiredLength(desiredLength),
      output(desiredLength),
      callback(std::move(callback)) {}

void EdhocKeyExporterAsyncWorker::Execute() {
  int ret = edhoc_export_prk_exporter(&context, label, output.data(), desiredLength);
  if (ret != EDHOC_SUCCESS) {
    char errorMessage[kErrorBufferSize];
    std::snprintf(errorMessage, kErrorBufferSize, kErrorMessageFormat, ret);
    SetError(errorMessage);
  }
}

void EdhocKeyExporterAsyncWorker::OnOK() {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);
  auto outputBuffer = Napi::Buffer<uint8_t>::Copy(env, output.data(), output.size());
  
  callback(env);

  if(env.IsExceptionPending()) {
    deferred.Reject(env.GetAndClearPendingException().Value());
  } else {
    deferred.Resolve(outputBuffer);
  }
}

void EdhocKeyExporterAsyncWorker::OnError(const Napi::Error& error) {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);
  
  callback(env);

  if(env.IsExceptionPending()) {
    deferred.Reject(env.GetAndClearPendingException().Value());
  } else {
    deferred.Reject(error.Value());
  }
}

Napi::Promise EdhocKeyExporterAsyncWorker::GetPromise() {
  return deferred.Promise();
}
