#include "EdhocKeyExporterAsyncWorker.h"

static constexpr const char* kErrorMessageFormat =
    "Failed to export the key. Error code: %d.";
static constexpr size_t kErrorBufferSize = 100;

EdhocKeyExporterAsyncWorker::EdhocKeyExporterAsyncWorker(
    Napi::Env& env,
    Napi::Promise::Deferred deferred,
    struct edhoc_context& context,
    uint16_t label,
    uint8_t desiredLength,
    CallbackType callback)
    : Napi::AsyncWorker(env),
      deferred(std::move(deferred)),
      context(context),
      label(label),
      desiredLength(desiredLength),
      output(desiredLength),
      callback(std::move(callback)) {}

void EdhocKeyExporterAsyncWorker::Execute() {
  try {
    int ret = edhoc_export_prk_exporter(
        &context, label, output.data(), desiredLength);

    if (ret != EDHOC_SUCCESS) {
      char errorMessage[kErrorBufferSize];
      std::snprintf(errorMessage, kErrorBufferSize, kErrorMessageFormat, ret);
      SetError(errorMessage);
    }
  } catch (const std::exception& e) {
    SetError(e.what());
  }
}

void EdhocKeyExporterAsyncWorker::OnOK() {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);

  auto outputBuffer =
      Napi::Buffer<uint8_t>::Copy(env, output.data(), output.size());

  deferred.Resolve(outputBuffer);
  callback(env);
}

void EdhocKeyExporterAsyncWorker::OnError(const Napi::Error& error) {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);
  deferred.Reject(error.Value());
  callback(env);
}
