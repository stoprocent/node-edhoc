#include "EdhocProcessAsyncWorker.h"

#include <iostream>
static constexpr const char* kErrorInvalidMessageNumber = "Invalid message number";
static constexpr const char* kErrorMessageFormat = "Failed to process EDHOC message %d. Error code: %d";
static constexpr const char* kErrorWrongSelectedCipherSuiteFormat =
    "Wrong selected cipher suite. Supported: %s, Received: %s";
static constexpr size_t kErrorBufferSize = 100;

EdhocProcessAsyncWorker::EdhocProcessAsyncWorker(Napi::Env& env,
                                                 struct edhoc_context& context,
                                                 int messageNumber,
                                                 Napi::Buffer<uint8_t> buffer,
                                                 CallbackType callback)
    : Napi::AsyncWorker(env),
      deferred(Napi::Promise::Deferred::New(env)),
      context(context),
      messageNumber(messageNumber),
      messageBuffer(buffer.Data(), buffer.Data() + buffer.Length()),
      callback(std::move(callback)),
      peerCipherSuites() {}

void EdhocProcessAsyncWorker::Execute() {
  uint8_t* message = messageBuffer.data();
  size_t message_length = messageBuffer.size();

  int ret = EDHOC_ERROR_GENERIC_ERROR;
  switch (messageNumber) {
    case EDHOC_MSG_1:
      ret = edhoc_message_1_process(&context, message, message_length);
      break;
    case EDHOC_MSG_2:
      ret = edhoc_message_2_process(&context, message, message_length);
      break;
    case EDHOC_MSG_3:
      ret = edhoc_message_3_process(&context, message, message_length);
      break;
    case EDHOC_MSG_4:
      ret = edhoc_message_4_process(&context, message, message_length);
      break;
    default:
      SetError(kErrorInvalidMessageNumber);
      return;
  }

  if (ret != EDHOC_SUCCESS) {
    enum edhoc_error_code error_code = EDHOC_ERROR_CODE_SUCCESS;
    ret = edhoc_error_get_code(&context, &error_code);
    switch (error_code) {
      case EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE: {
        size_t csuites_len = 0;
        int32_t csuites[10] = {0};
        size_t peer_csuites_len = 0;
        int32_t peer_csuites[10] = {0};

        ret = edhoc_error_get_cipher_suites(&context, csuites, ARRAY_SIZE(csuites), &csuites_len, peer_csuites,
                                            ARRAY_SIZE(peer_csuites), &peer_csuites_len);
        if (ret == EDHOC_SUCCESS) {
          std::string suites_str = "[";
          for (size_t i = 0; i < csuites_len; i++) {
            suites_str += std::to_string(csuites[i]);
            if (i < csuites_len - 1) {
              suites_str += ", ";
            }
          }
          suites_str += "*]";

          std::string peer_suites_str = "[";
          for (size_t i = 0; i < peer_csuites_len; i++) {
            peer_suites_str += std::to_string(peer_csuites[i]);
            if (i < peer_csuites_len - 1) {
              peer_suites_str += ", ";
            }
          }
          peer_suites_str += "*]";

          peerCipherSuites.assign(peer_csuites, peer_csuites + peer_csuites_len);

          char errorMessage[kErrorBufferSize];
          std::snprintf(errorMessage, kErrorBufferSize, kErrorWrongSelectedCipherSuiteFormat, suites_str.c_str(),
                        peer_suites_str.c_str());
          SetError(errorMessage);
          return;
        }
        break;
      }
      default:
        break;
    }

    char errorMessage[kErrorBufferSize];
    std::snprintf(errorMessage, kErrorBufferSize, kErrorMessageFormat, messageNumber + 1, error_code);
    SetError(errorMessage);
  }
}

void EdhocProcessAsyncWorker::OnOK() {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);
  Napi::Array result = callback(env);

  callback(env);

  if (env.IsExceptionPending()) {
    deferred.Reject(env.GetAndClearPendingException().Value());
  } else {
    deferred.Resolve(result);
  }
}

void EdhocProcessAsyncWorker::OnError(const Napi::Error& error) {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);

  if (peerCipherSuites.size() > 0) {
    Napi::Array result = Napi::Array::New(env, peerCipherSuites.size());
    for (size_t i = 0; i < peerCipherSuites.size(); i++) {
      result.Set(i, Napi::Number::New(env, peerCipherSuites[i]));
    }
    error.Set("peerCipherSuites", result);
  }

  callback(env);

  if (env.IsExceptionPending()) {
    deferred.Reject(env.GetAndClearPendingException().Value());
  } else {
    deferred.Reject(error.Value());
  }
}

Napi::Promise EdhocProcessAsyncWorker::GetPromise() {
  return deferred.Promise();
}
