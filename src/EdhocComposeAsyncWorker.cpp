#include "EdhocComposeAsyncWorker.h"

static const size_t kInitialBufferSize = 1024 * 10;
static constexpr const char* kErrorInvalidMessageNumber = "Invalid message number";
static constexpr const char* kErrorMessageFormat = "Failed to compose EDHOC message %d. Error code: %d";
static constexpr size_t kErrorBufferSize = 100;

EdhocComposeAsyncWorker::EdhocComposeAsyncWorker(RunningContext* runningContext, int messageNumber)
    : Napi::AsyncWorker(runningContext->GetEnv()),
      runningContext_(runningContext),
      messageNumber_(messageNumber) {}

void EdhocComposeAsyncWorker::Execute() {
  try {
    composedMessage_.resize(kInitialBufferSize);
    size_t composedMessageLength = 0;

    int ret = EDHOC_ERROR_GENERIC_ERROR;
    switch (messageNumber_) {
      case EDHOC_MSG_1:
        ret = edhoc_message_1_compose(runningContext_->GetEdhocContext(), composedMessage_.data(), composedMessage_.size(), &composedMessageLength);
        break;
      case EDHOC_MSG_2:
        ret = edhoc_message_2_compose(runningContext_->GetEdhocContext(), composedMessage_.data(), composedMessage_.size(), &composedMessageLength);
        break;
      case EDHOC_MSG_3:
        ret = edhoc_message_3_compose(runningContext_->GetEdhocContext(), composedMessage_.data(), composedMessage_.size(), &composedMessageLength);
        break;
      case EDHOC_MSG_4:
        ret = edhoc_message_4_compose(runningContext_->GetEdhocContext(), composedMessage_.data(), composedMessage_.size(), &composedMessageLength);
        break;
      default:
        SetError(kErrorInvalidMessageNumber);
        return;
    }

    composedMessage_.resize(composedMessageLength);

    if (ret != EDHOC_SUCCESS) {
      char errorMessage[kErrorBufferSize];
      std::snprintf(errorMessage, kErrorBufferSize, kErrorMessageFormat, messageNumber_ + 1, ret);
      SetError(errorMessage);
    }
  } catch (const std::exception& e) {
    SetError(e.what());
  }
}

void EdhocComposeAsyncWorker::OnOK() {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);
  runningContext_->Resolve(Napi::Buffer<uint8_t>::Copy(env, composedMessage_.data(), composedMessage_.size()));
  runningContext_->GetEadManager()->ClearEadByMessage(static_cast<enum edhoc_message>(messageNumber_));
}

void EdhocComposeAsyncWorker::OnError(const Napi::Error& error) {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);
  runningContext_->Reject(error.Value());
}
