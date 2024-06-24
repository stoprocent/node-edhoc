#include "EdhocCryptoManagerWrapper.h"

static constexpr const char* kErrorFunctionExpected = "Function expected";
static constexpr const char* kTsfnNameGenerateKey = "GenerateKey";
static constexpr const char* kTsfnNameDestroyKey = "DestroyKey";
static constexpr const char* kTsfnNameMakeKeyPair = "MakeKeyPair";
static constexpr const char* kTsfnNameKeyAgreement = "KeyAgreement";
static constexpr const char* kTsfnNameSign = "Sign";
static constexpr const char* kTsfnNameVerify = "Verify";
static constexpr const char* kTsfnNameExtract = "Extract";
static constexpr const char* kTsfnNameExpand = "Expand";
static constexpr const char* kTsfnNameEncrypt = "Encrypt";
static constexpr const char* kTsfnNameDecrypt = "Decrypt";
static constexpr const char* kTsfnNameHash = "Hash";
static constexpr const char* kClassName = "EdhocCryptoManager";
static constexpr const char* kGenerateKeyAccessor = "generateKey";
static constexpr const char* kDestroyKeyAccessor = "destroyKey";
static constexpr const char* kMakeKeyPairAccessor = "makeKeyPair";
static constexpr const char* kKeyAgreementAccessor = "keyAgreement";
static constexpr const char* kSignAccessor = "sign";
static constexpr const char* kVerifyAccessor = "verify";
static constexpr const char* kExtractAccessor = "extract";
static constexpr const char* kExpandAccessor = "expand";
static constexpr const char* kEncryptAccessor = "encrypt";
static constexpr const char* kDecryptAccessor = "decrypt";
static constexpr const char* kHashAccessor = "hash";

EdhocCryptoManagerWrapper::EdhocCryptoManagerWrapper(
    const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<EdhocCryptoManagerWrapper>(info) {
  manager = std::make_shared<EdhocCryptoManager>();
  Napi::Value make = info.This().As<Napi::Object>().Get(kMakeKeyPairAccessor);
  if (make.IsFunction()) {
    printf("make is a function\n");
  }

  SetFunctionAndTsfn(make.As<Napi::Function>(), kTsfnNameMakeKeyPair, manager->makeKeyPairFuncRef, manager->makeKeyPairTsfn);
}

EdhocCryptoManagerWrapper::~EdhocCryptoManagerWrapper() {}

const std::shared_ptr<EdhocCryptoManager>
EdhocCryptoManagerWrapper::GetInternalManager() {
  return manager;
}

void EdhocCryptoManagerWrapper::SetFunctionAndTsfn(
    const Napi::Value& value,
    const std::string& tsfnName,
    Napi::FunctionReference& functionRef,
    Napi::ThreadSafeFunction& tsfn) {
  Napi::Env env = value.Env();
  Napi::HandleScope scope(env);

  if (!value.IsFunction()) {
    Napi::TypeError::New(env, kErrorFunctionExpected)
        .ThrowAsJavaScriptException();
  } else {
    Napi::Function jsFunction = value.As<Napi::Function>();
    functionRef = Napi::Persistent(jsFunction);
    tsfn = Napi::ThreadSafeFunction::New(env, jsFunction, tsfnName, 0, 1);
  }
}

void EdhocCryptoManagerWrapper::SetGenerateKey(const Napi::CallbackInfo& info,
                                               const Napi::Value& value) {
  SetFunctionAndTsfn(value,
                     kTsfnNameGenerateKey,
                     manager->generateKeyFuncRef,
                     manager->generateTsfn);
}

void EdhocCryptoManagerWrapper::SetDestroyKey(const Napi::CallbackInfo& info,
                                              const Napi::Value& value) {
  SetFunctionAndTsfn(value,
                     kTsfnNameDestroyKey,
                     manager->destroyKeyFuncRef,
                     manager->destroyTsfn);
}

void EdhocCryptoManagerWrapper::SetMakeKeyPair(const Napi::CallbackInfo& info,
                                               const Napi::Value& value) {
  SetFunctionAndTsfn(value,
                     kTsfnNameMakeKeyPair,
                     manager->makeKeyPairFuncRef,
                     manager->makeKeyPairTsfn);
}

void EdhocCryptoManagerWrapper::SetKeyAgreement(const Napi::CallbackInfo& info,
                                                const Napi::Value& value) {
  SetFunctionAndTsfn(value,
                     kTsfnNameKeyAgreement,
                     manager->keyAgreementFuncRef,
                     manager->keyAgreementTsfn);
}

void EdhocCryptoManagerWrapper::SetSign(const Napi::CallbackInfo& info,
                                        const Napi::Value& value) {
  SetFunctionAndTsfn(value,
                     kTsfnNameSign,
                     manager->signFuncRef,
                     manager->signTsfn);
}

void EdhocCryptoManagerWrapper::SetVerify(const Napi::CallbackInfo& info,
                                          const Napi::Value& value) {
  SetFunctionAndTsfn(value,
                     kTsfnNameVerify,
                     manager->verifyFuncRef,
                     manager->verifyTsfn);
}

void EdhocCryptoManagerWrapper::SetExtract(const Napi::CallbackInfo& info,
                                           const Napi::Value& value) {
  SetFunctionAndTsfn(value,
                     kTsfnNameExtract,
                     manager->extractFuncRef,
                     manager->extractTsfn);
}

void EdhocCryptoManagerWrapper::SetExpand(const Napi::CallbackInfo& info,
                                          const Napi::Value& value) {
  SetFunctionAndTsfn(value,
                     kTsfnNameExpand,
                     manager->expandFuncRef,
                     manager->expandTsfn);
}

void EdhocCryptoManagerWrapper::SetEncrypt(const Napi::CallbackInfo& info,
                                           const Napi::Value& value) {
  SetFunctionAndTsfn(value,
                     kTsfnNameEncrypt,
                     manager->encryptFuncRef,
                     manager->encryptTsfn);
}

void EdhocCryptoManagerWrapper::SetDecrypt(const Napi::CallbackInfo& info,
                                           const Napi::Value& value) {
  SetFunctionAndTsfn(value,
                     kTsfnNameDecrypt,
                     manager->decryptFuncRef,
                     manager->decryptTsfn);
}

void EdhocCryptoManagerWrapper::SetHash(const Napi::CallbackInfo& info,
                                        const Napi::Value& value) {
  SetFunctionAndTsfn(value,
                     kTsfnNameHash,
                     manager->hashFuncRef,
                     manager->hashTsfn);
}

Napi::Value EdhocCryptoManagerWrapper::GetGenerateKey(
    const Napi::CallbackInfo& info) {
  return manager->generateKeyFuncRef.Value();
}

Napi::Value EdhocCryptoManagerWrapper::GetDestroyKey(
    const Napi::CallbackInfo& info) {
  return manager->destroyKeyFuncRef.Value();
}

Napi::Value EdhocCryptoManagerWrapper::GetMakeKeyPair(
    const Napi::CallbackInfo& info) {
  return manager->makeKeyPairFuncRef.Value();
}

Napi::Value EdhocCryptoManagerWrapper::GetKeyAgreement(
    const Napi::CallbackInfo& info) {
  return manager->keyAgreementFuncRef.Value();
}

Napi::Value EdhocCryptoManagerWrapper::GetSign(const Napi::CallbackInfo& info) {
  return manager->signFuncRef.Value();
}

Napi::Value EdhocCryptoManagerWrapper::GetVerify(
    const Napi::CallbackInfo& info) {
  return manager->verifyFuncRef.Value();
}

Napi::Value EdhocCryptoManagerWrapper::GetExtract(
    const Napi::CallbackInfo& info) {
  return manager->extractFuncRef.Value();
}

Napi::Value EdhocCryptoManagerWrapper::GetExpand(
    const Napi::CallbackInfo& info) {
  return manager->expandFuncRef.Value();
}

Napi::Value EdhocCryptoManagerWrapper::GetEncrypt(
    const Napi::CallbackInfo& info) {
  return manager->encryptFuncRef.Value();
}

Napi::Value EdhocCryptoManagerWrapper::GetDecrypt(
    const Napi::CallbackInfo& info) {
  return manager->decryptFuncRef.Value();
}

Napi::Value EdhocCryptoManagerWrapper::GetHash(const Napi::CallbackInfo& info) {
  return manager->hashFuncRef.Value();
}

Napi::Object EdhocCryptoManagerWrapper::Init(Napi::Env env,
                                             Napi::Object exports) {
  Napi::HandleScope scope(env);

  Napi::Function func = DefineClass(
      env,
      kClassName,
      {InstanceAccessor(kGenerateKeyAccessor,
                        &EdhocCryptoManagerWrapper::GetGenerateKey,
                        &EdhocCryptoManagerWrapper::SetGenerateKey),
       InstanceAccessor(kDestroyKeyAccessor,
                        &EdhocCryptoManagerWrapper::GetDestroyKey,
                        &EdhocCryptoManagerWrapper::SetDestroyKey),
      //  InstanceAccessor(kMakeKeyPairAccessor,
      //                   &EdhocCryptoManagerWrapper::GetMakeKeyPair,
      //                   &EdhocCryptoManagerWrapper::SetMakeKeyPair),
       InstanceAccessor(kKeyAgreementAccessor,
                        &EdhocCryptoManagerWrapper::GetKeyAgreement,
                        &EdhocCryptoManagerWrapper::SetKeyAgreement),
       InstanceAccessor(kSignAccessor,
                        &EdhocCryptoManagerWrapper::GetSign,
                        &EdhocCryptoManagerWrapper::SetSign),
       InstanceAccessor(kVerifyAccessor,
                        &EdhocCryptoManagerWrapper::GetVerify,
                        &EdhocCryptoManagerWrapper::SetVerify),
       InstanceAccessor(kExtractAccessor,
                        &EdhocCryptoManagerWrapper::GetExtract,
                        &EdhocCryptoManagerWrapper::SetExtract),
       InstanceAccessor(kExpandAccessor,
                        &EdhocCryptoManagerWrapper::GetExpand,
                        &EdhocCryptoManagerWrapper::SetExpand),
       InstanceAccessor(kEncryptAccessor,
                        &EdhocCryptoManagerWrapper::GetEncrypt,
                        &EdhocCryptoManagerWrapper::SetEncrypt),
       InstanceAccessor(kDecryptAccessor,
                        &EdhocCryptoManagerWrapper::GetDecrypt,
                        &EdhocCryptoManagerWrapper::SetDecrypt),
       InstanceAccessor(kHashAccessor,
                        &EdhocCryptoManagerWrapper::GetHash,
                        &EdhocCryptoManagerWrapper::SetHash)});

  Napi::FunctionReference* constructor = new Napi::FunctionReference();
  *constructor = Napi::Persistent(func);

  exports.Set(kClassName, func);

  env.SetInstanceData<Napi::FunctionReference>(constructor);

  return exports;
}
