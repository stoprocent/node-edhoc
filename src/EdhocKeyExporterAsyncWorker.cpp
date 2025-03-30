#include "EdhocKeyExporterAsyncWorker.h"

static constexpr const char* kErrorMessageFormat = "Failed to export the key. Error code: %d.";
static constexpr size_t kErrorBufferSize = 100;

EdhocKeyExporterAsyncWorker::EdhocKeyExporterAsyncWorker(RunningContext* runningContext,
                                                         uint16_t label,
                                                         uint8_t desiredLength)
    : Napi::AsyncWorker(runningContext->GetEnv()),
      runningContext_(runningContext),
      label(label),
      desiredLength(desiredLength),
      output(desiredLength) {}

void EdhocKeyExporterAsyncWorker::Execute() {
  try {
    int ret = edhoc_export_prk_exporter(runningContext_->GetEdhocContext(), label, output.data(), desiredLength);
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
  auto outputBuffer = Napi::Buffer<uint8_t>::Copy(env, output.data(), output.size());
  runningContext_->Resolve(outputBuffer);
}

void EdhocKeyExporterAsyncWorker::OnError(const Napi::Error& error) {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);
  runningContext_->Reject(error.Value());
}
