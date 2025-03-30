#include "EdhocKeyExporterAsyncWorker.h"

static constexpr const char* kErrorMessageFormat = "Failed to export the key. Error code: %d.";
static constexpr size_t kErrorBufferSize = 100;

EdhocKeyExporterAsyncWorker::EdhocKeyExporterAsyncWorker(RunningContext* runningContext,
                                                         uint16_t label,
                                                         uint8_t desiredLength)
    : Napi::AsyncWorker(runningContext->GetEnv()),
      runningContext_(runningContext),
      label_(label),
      desiredLength_(desiredLength),
      output_(desiredLength) {}

void EdhocKeyExporterAsyncWorker::Execute() {
  try {
    int ret = edhoc_export_prk_exporter(runningContext_->GetEdhocContext(), label_, output_.data(), desiredLength_);
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
  auto outputBuffer = Napi::Buffer<uint8_t>::Copy(env, output_.data(), output_.size());
  runningContext_->Resolve(outputBuffer);
}

void EdhocKeyExporterAsyncWorker::OnError(const Napi::Error& error) {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);
  runningContext_->Reject(error.Value());
}
