#include "EdhocComposeAsyncWorker.h"

static const size_t kInitialBufferSize = 1024 * 10;
static constexpr const char* kErrorInvalidMessageNumber = "Invalid message number";
static constexpr const char* kErrorMessageFormat = "Failed to compose EDHOC message %d. Error code: %d";
static constexpr size_t kErrorBufferSize = 100;

EdhocComposeAsyncWorker::EdhocComposeAsyncWorker(Napi::Env& env,
                                                 struct edhoc_context& context,
                                                 int messageNumber,
                                                 CallbackType callback)
    : Napi::AsyncWorker(env),
      deferred(Napi::Promise::Deferred::New(env)),
      context(context),
      messageNumber(messageNumber),
      callback(std::move(callback)) {}

void EdhocComposeAsyncWorker::Execute() {
  composedMessage.resize(kInitialBufferSize);
  size_t composedMessageLength = 0;

  int ret = EDHOC_ERROR_GENERIC_ERROR;
  switch (messageNumber) {
    case EDHOC_MSG_1:
      ret = edhoc_message_1_compose(&context, composedMessage.data(), composedMessage.size(), &composedMessageLength);
      break;
    case EDHOC_MSG_2:
      ret = edhoc_message_2_compose(&context, composedMessage.data(), composedMessage.size(), &composedMessageLength);
      break;
    case EDHOC_MSG_3:
      ret = edhoc_message_3_compose(&context, composedMessage.data(), composedMessage.size(), &composedMessageLength);
      break;
    case EDHOC_MSG_4:
      ret = edhoc_message_4_compose(&context, composedMessage.data(), composedMessage.size(), &composedMessageLength);
      break;
    default:
      SetError(kErrorInvalidMessageNumber);
      return;
  }

  composedMessage.resize(composedMessageLength);

  if (ret != EDHOC_SUCCESS) {
    char errorMessage[kErrorBufferSize];
    std::snprintf(errorMessage, kErrorBufferSize, kErrorMessageFormat, messageNumber + 1, ret);
    SetError(errorMessage);
  }
}

void EdhocComposeAsyncWorker::OnOK() {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);

  callback(env);

  if (env.IsExceptionPending()) {
    deferred.Reject(env.GetAndClearPendingException().Value());
  } else {
    deferred.Resolve(Napi::Buffer<uint8_t>::Copy(env, composedMessage.data(), composedMessage.size()));
  }
}

void EdhocComposeAsyncWorker::OnError(const Napi::Error& error) {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);

  callback(env);

  if (env.IsExceptionPending()) {
    deferred.Reject(env.GetAndClearPendingException().Value());
  } else {
    deferred.Reject(error.Value());
  }
}

Napi::Promise EdhocComposeAsyncWorker::GetPromise() {
  return deferred.Promise();
}
