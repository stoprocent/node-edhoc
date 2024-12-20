#include "EdhocProcessAsyncWorker.h"

static constexpr const char* kErrorInvalidMessageNumber =
    "Invalid message number";
static constexpr const char* kErrorMessageFormat =
    "Failed to process EDHOC message %d. Error code: %d";
static constexpr const char* kErrorWrongSelectedCipherSuite =
    "Wrong selected cipher suite";
static constexpr size_t kErrorBufferSize = 100;

EdhocProcessAsyncWorker::EdhocProcessAsyncWorker(
    Napi::Env& env,
    Napi::Promise::Deferred deferred,
    struct edhoc_context& context,
    int messageNumber,
    Napi::Buffer<uint8_t> buffer,
    CallbackType callback)
    : Napi::AsyncWorker(env),
      deferred(deferred),
      context(context),
      messageNumber(messageNumber),
      messageBuffer(buffer.Data(), buffer.Data() + buffer.Length()),
      callback(std::move(callback)) {}

void EdhocProcessAsyncWorker::Execute() {
  try {
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
          int32_t csuites[10] = { 0 };
          ret = edhoc_error_get_cipher_suites(&context,
                                            csuites,
                                            ARRAY_SIZE(csuites),
                                            &csuites_len);
          if (ret == EDHOC_SUCCESS) {
            std::string suites_str = "[";
            for (size_t i = 0; i < csuites_len; i++) {
              suites_str += std::to_string(csuites[i]);
              if (i < csuites_len - 1) {
                suites_str += ",";
              }
            }
            suites_str += "]";

            char errorMessage[kErrorBufferSize];
            std::snprintf(errorMessage,
                         kErrorBufferSize,
                         "%s %s",
                         kErrorWrongSelectedCipherSuite,
                         suites_str.c_str());
            SetError(errorMessage);
            return;
          }
          break;
        }
        default:
          break;
      }
      
      char errorMessage[kErrorBufferSize];
      std::snprintf(errorMessage,
                    kErrorBufferSize,
                    kErrorMessageFormat,
                    messageNumber + 1,
                    error_code);
      SetError(errorMessage);
    }

  } catch (const std::exception& e) {
    SetError(e.what());
  }
}

void EdhocProcessAsyncWorker::OnOK() {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);
  Napi::Array result = callback(env);
  deferred.Resolve(result);
}

void EdhocProcessAsyncWorker::OnError(const Napi::Error& error) {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);
  deferred.Reject(Napi::String::New(env, error.Message()));
  callback(env);
}
