#include "EdhocProcessAsyncWorker.h"

static constexpr const char* kErrorInvalidMessageNumber = "Invalid message number";
static constexpr const char* kErrorMessageFormat = "Failed to process EDHOC message %d. Error code: %d";
static constexpr const char* kErrorWrongSelectedCipherSuiteFormat =
    "Wrong selected cipher suite. Supported: %s, Received: %s";
static constexpr size_t kErrorBufferSize = 100;

EdhocProcessAsyncWorker::EdhocProcessAsyncWorker(RunningContext* runningContext,
                                                 int messageNumber,
                                                 Napi::Buffer<uint8_t> buffer)
    : Napi::AsyncWorker(runningContext->GetEnv()),
      runningContext_(runningContext),
      messageNumber_(messageNumber),
      messageBuffer_(buffer.Data(), buffer.Data() + buffer.Length()),
      peerCipherSuites_() {}

void EdhocProcessAsyncWorker::Execute() {
  try {
    uint8_t* message = messageBuffer_.data();
    size_t message_length = messageBuffer_.size();

    int ret = EDHOC_ERROR_GENERIC_ERROR;
    switch (messageNumber_) {
      case EDHOC_MSG_1:
        ret = edhoc_message_1_process(runningContext_->GetEdhocContext(), message, message_length);
        break;
      case EDHOC_MSG_2:
        ret = edhoc_message_2_process(runningContext_->GetEdhocContext(), message, message_length);
        break;
      case EDHOC_MSG_3:
        ret = edhoc_message_3_process(runningContext_->GetEdhocContext(), message, message_length);
        break;
      case EDHOC_MSG_4:
        ret = edhoc_message_4_process(runningContext_->GetEdhocContext(), message, message_length);
        break;
      default:
        SetError(kErrorInvalidMessageNumber);
        return;
    }

    if (ret != EDHOC_SUCCESS) {
      enum edhoc_error_code error_code = EDHOC_ERROR_CODE_SUCCESS;
      ret = edhoc_error_get_code(runningContext_->GetEdhocContext(), &error_code);
      switch (error_code) {
        case EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE: {
          size_t csuites_len = 0;
          int32_t csuites[10] = {0};
          size_t peer_csuites_len = 0;
          int32_t peer_csuites[10] = {0};

          ret = edhoc_error_get_cipher_suites(runningContext_->GetEdhocContext(), csuites, ARRAY_SIZE(csuites), &csuites_len, peer_csuites,
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

            peerCipherSuites_.assign(peer_csuites, peer_csuites + peer_csuites_len);

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
      std::snprintf(errorMessage, kErrorBufferSize, kErrorMessageFormat, messageNumber_ + 1, error_code);
      SetError(errorMessage);
    }

  } catch (const std::exception& e) {
    SetError(e.what());
  }
}

void EdhocProcessAsyncWorker::OnOK() {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);
  
  Napi::Array EADs = runningContext_->GetEadManager()->GetEadByMessage(env, static_cast<enum edhoc_message>(messageNumber_));
  runningContext_->GetEadManager()->ClearEadByMessage(static_cast<enum edhoc_message>(messageNumber_));

  runningContext_->Resolve(EADs);
}

void EdhocProcessAsyncWorker::OnError(const Napi::Error& error) {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);

  if (peerCipherSuites_.size() > 0) {
    Napi::Array result = Napi::Array::New(env, peerCipherSuites_.size());
    for (size_t i = 0; i < peerCipherSuites_.size(); i++) {
      result.Set(i, Napi::Number::New(env, peerCipherSuites_[i]));
    }
    error.Set("peerCipherSuites", result);
  }

  runningContext_->Reject(error.Value());
}
