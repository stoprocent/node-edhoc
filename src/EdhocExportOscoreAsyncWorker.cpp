#include "EdhocExportOscoreAsyncWorker.h"

static constexpr const char* kErrorMessageFormat = "Failed to export OSCORE. Error code: %d.";
static constexpr const char* kPropMasterSecret = "masterSecret";
static constexpr const char* kPropMasterSalt = "masterSalt";
static constexpr const char* kPropSenderId = "senderId";
static constexpr const char* kPropRecipientId = "recipientId";
static constexpr size_t kErrorBufferSize = 100;
static constexpr size_t kMasterSecrectSize = 16;
static constexpr size_t kMasterSaltSize = 8;
static constexpr size_t kConnectionIdSize = 7;

EdhocExportOscoreAsyncWorker::EdhocExportOscoreAsyncWorker(RunningContext* runningContext)
    : Napi::AsyncWorker(runningContext->GetEnv()),
      runningContext_(runningContext),
      masterSecret_(kMasterSecrectSize),
      masterSalt_(kMasterSaltSize),
      senderId_(kConnectionIdSize),
      recipientId_(kConnectionIdSize) {}

EdhocExportOscoreAsyncWorker::~EdhocExportOscoreAsyncWorker() {}

void EdhocExportOscoreAsyncWorker::Execute() {
  try {
    size_t sender_id_length, recipient_id_length;

    int ret = edhoc_export_oscore_session(runningContext_->GetEdhocContext(), masterSecret_.data(), masterSecret_.size(), masterSalt_.data(),
                                          masterSalt_.size(), senderId_.data(), senderId_.size(), &sender_id_length,
                                          recipientId_.data(), recipientId_.size(), &recipient_id_length);

    if (ret != EDHOC_SUCCESS) {
      char errorMessage[kErrorBufferSize];
      std::snprintf(errorMessage, kErrorBufferSize, kErrorMessageFormat, ret);
      SetError(errorMessage);
    } else {
      senderId_.resize(sender_id_length);
      recipientId_.resize(recipient_id_length);
    }

  } catch (const std::exception& e) {
    SetError(e.what());
  }
}

void EdhocExportOscoreAsyncWorker::OnOK() {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);

  auto masterSecretBuffer = Napi::Buffer<uint8_t>::Copy(env, masterSecret_.data(), masterSecret_.size());
  auto masterSaltBuffer = Napi::Buffer<uint8_t>::Copy(env, masterSalt_.data(), masterSalt_.size());
  auto senderIdBuffer = Napi::Buffer<uint8_t>::Copy(env, senderId_.data(), senderId_.size());
  auto recipientIdBuffer = Napi::Buffer<uint8_t>::Copy(env, recipientId_.data(), recipientId_.size());

  Napi::Object resultObj = Napi::Object::New(env);
  resultObj.Set(kPropMasterSecret, masterSecretBuffer);
  resultObj.Set(kPropMasterSalt, masterSaltBuffer);
  resultObj.Set(kPropSenderId, senderIdBuffer);
  resultObj.Set(kPropRecipientId, recipientIdBuffer);

  runningContext_->Resolve(resultObj);
}

void EdhocExportOscoreAsyncWorker::OnError(const Napi::Error& error) {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);
  runningContext_->Reject(error.Value());
}
