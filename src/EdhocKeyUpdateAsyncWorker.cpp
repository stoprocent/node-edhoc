#include "EdhocKeyUpdateAsyncWorker.h"

EdhocKeyUpdateAsyncWorker::EdhocKeyUpdateAsyncWorker(RunningContext* runningContext,
                                                     std::vector<uint8_t> contextBuffer)
    : Napi::AsyncWorker(runningContext->GetEnv()),
      runningContext_(runningContext),
      contextBuffer_(contextBuffer) {}

void EdhocKeyUpdateAsyncWorker::Execute() {
  try {
    int ret = edhoc_export_key_update(runningContext_->GetEdhocContext(), contextBuffer_.data(), contextBuffer_.size());

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
  runningContext_->Resolve(env.Undefined());
}

void EdhocKeyUpdateAsyncWorker::OnError(const Napi::Error& error) {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);
  runningContext_->Reject(error.Value());
}
