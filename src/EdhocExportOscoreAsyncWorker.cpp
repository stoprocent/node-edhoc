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

EdhocExportOscoreAsyncWorker::EdhocExportOscoreAsyncWorker(Napi::Env& env,
                                                           struct edhoc_context& context,
                                                           CallbackType callback)
    : Napi::AsyncWorker(env),
      deferred(Napi::Promise::Deferred::New(env)),
      context(context),
      masterSecret(kMasterSecrectSize),
      masterSalt(kMasterSaltSize),
      senderId(kConnectionIdSize),
      recipientId(kConnectionIdSize),
      callback(std::move(callback)) {}

EdhocExportOscoreAsyncWorker::~EdhocExportOscoreAsyncWorker() {}

void EdhocExportOscoreAsyncWorker::Execute() {
  size_t sender_id_length, recipient_id_length;

  int ret = edhoc_export_oscore_session(&context, masterSecret.data(), masterSecret.size(), masterSalt.data(),
                                        masterSalt.size(), senderId.data(), senderId.size(), &sender_id_length,
                                        recipientId.data(), recipientId.size(), &recipient_id_length);

  if (ret != EDHOC_SUCCESS) {
    char errorMessage[kErrorBufferSize];
    std::snprintf(errorMessage, kErrorBufferSize, kErrorMessageFormat, ret);
    SetError(errorMessage);
  } else {
    senderId.resize(sender_id_length);
    recipientId.resize(recipient_id_length);
  }
}

void EdhocExportOscoreAsyncWorker::OnOK() {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);

  auto masterSecretBuffer = Napi::Buffer<uint8_t>::Copy(env, masterSecret.data(), masterSecret.size());
  auto masterSaltBuffer = Napi::Buffer<uint8_t>::Copy(env, masterSalt.data(), masterSalt.size());
  auto senderIdBuffer = Napi::Buffer<uint8_t>::Copy(env, senderId.data(), senderId.size());
  auto recipientIdBuffer = Napi::Buffer<uint8_t>::Copy(env, recipientId.data(), recipientId.size());

  Napi::Object resultObj = Napi::Object::New(env);
  resultObj.Set(kPropMasterSecret, masterSecretBuffer);
  resultObj.Set(kPropMasterSalt, masterSaltBuffer);
  resultObj.Set(kPropSenderId, senderIdBuffer);
  resultObj.Set(kPropRecipientId, recipientIdBuffer);

  callback(env);

  if (env.IsExceptionPending()) {
    deferred.Reject(env.GetAndClearPendingException().Value());
  } else {
    deferred.Resolve(resultObj);
  }
}

void EdhocExportOscoreAsyncWorker::OnError(const Napi::Error& error) {
  Napi::Env env = Env();
  Napi::HandleScope scope(env);

  callback(env);

  if (env.IsExceptionPending()) {
    deferred.Reject(env.GetAndClearPendingException().Value());
  } else {
    deferred.Reject(error.Value());
  }
}

Napi::Promise EdhocExportOscoreAsyncWorker::GetPromise() {
  return deferred.Promise();
}
