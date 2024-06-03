#include "EdhocCryptoManagerWrapper.h"

EdhocCryptoManagerWrapper::EdhocCryptoManagerWrapper(const Napi::CallbackInfo& info) : Napi::ObjectWrap<EdhocCryptoManagerWrapper>(info) {
    this->manager = std::make_shared<EdhocCryptoManager>();
    this->manager->keys.generate_key = &EdhocCryptoManager::GenerateKey;
    this->manager->keys.destroy_key = &EdhocCryptoManager::DestroyKey;
    this->manager->crypto.make_key_pair = &EdhocCryptoManager::MakeKeyPair;
    this->manager->crypto.key_agreement = &EdhocCryptoManager::KeyAgreement;
    this->manager->crypto.signature = &EdhocCryptoManager::Sign;
    this->manager->crypto.verify = &EdhocCryptoManager::Verify;
    this->manager->crypto.extract = &EdhocCryptoManager::Extract;
    this->manager->crypto.expand = &EdhocCryptoManager::Expand;
    this->manager->crypto.encrypt = &EdhocCryptoManager::Encrypt;
    this->manager->crypto.decrypt = &EdhocCryptoManager::Decrypt;
    this->manager->crypto.hash = &EdhocCryptoManager::Hash;
}

EdhocCryptoManagerWrapper::~EdhocCryptoManagerWrapper() {
    
}

const std::shared_ptr<EdhocCryptoManager> EdhocCryptoManagerWrapper::GetInternalManager() {
    return this->manager;
}

Napi::Value EdhocCryptoManagerWrapper::SetFunctionAndTsfn(
    const Napi::CallbackInfo& info,
    const std::string& tsfnName,
    Napi::FunctionReference& functionRef,
    Napi::ThreadSafeFunction& tsfn) {
    
    Napi::Env env = info.Env();
    Napi::HandleScope scope(env);

    if (!info[0].IsFunction()) {
        Napi::TypeError::New(env, "Function expected").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    Napi::Function jsCallback = info[0].As<Napi::Function>();
    functionRef = Napi::Persistent(jsCallback);
    tsfn = Napi::ThreadSafeFunction::New(env, jsCallback, tsfnName, 0, 1);

    return env.Undefined();
}

Napi::Value EdhocCryptoManagerWrapper::SetGenerateKey(const Napi::CallbackInfo& info) {
    return SetFunctionAndTsfn(info, "GenerateKey", this->manager->generateKeyFuncRef, this->manager->generateTsfn);
}

Napi::Value EdhocCryptoManagerWrapper::SetDestroyKey(const Napi::CallbackInfo& info) {
    return SetFunctionAndTsfn(info, "DestroyKey", this->manager->destroyKeyFuncRef, this->manager->destroyTsfn);
}

Napi::Value EdhocCryptoManagerWrapper::SetMakeKeyPair(const Napi::CallbackInfo& info) {
    return SetFunctionAndTsfn(info, "MakeKeyPair", this->manager->makeKeyPairFuncRef, this->manager->makeKeyPairTsfn);
}

Napi::Value EdhocCryptoManagerWrapper::SetKeyAgreement(const Napi::CallbackInfo& info) {
    return SetFunctionAndTsfn(info, "KeyAgreement", this->manager->keyAgreementFuncRef, this->manager->keyAgreementTsfn);
}

Napi::Value EdhocCryptoManagerWrapper::SetSign(const Napi::CallbackInfo& info) {
    return SetFunctionAndTsfn(info, "Sign", this->manager->signFuncRef, this->manager->signTsfn);
}

Napi::Value EdhocCryptoManagerWrapper::SetVerify(const Napi::CallbackInfo& info) {
    return SetFunctionAndTsfn(info, "Verify", this->manager->verifyFuncRef, this->manager->verifyTsfn);
}

Napi::Value EdhocCryptoManagerWrapper::SetExtract(const Napi::CallbackInfo& info) {
    return SetFunctionAndTsfn(info, "Extract", this->manager->extractFuncRef, this->manager->extractTsfn);
}

Napi::Value EdhocCryptoManagerWrapper::SetExpand(const Napi::CallbackInfo& info) {
    return SetFunctionAndTsfn(info, "Expand", this->manager->expandFuncRef, this->manager->expandTsfn);
}

Napi::Value EdhocCryptoManagerWrapper::SetEncrypt(const Napi::CallbackInfo& info) {
    return SetFunctionAndTsfn(info, "Encrypt", this->manager->encryptFuncRef, this->manager->encryptTsfn);
}

Napi::Value EdhocCryptoManagerWrapper::SetDecrypt(const Napi::CallbackInfo& info) {
    return SetFunctionAndTsfn(info, "Decrypt", this->manager->decryptFuncRef, this->manager->decryptTsfn);
}

Napi::Value EdhocCryptoManagerWrapper::SetHash(const Napi::CallbackInfo& info) {
    return SetFunctionAndTsfn(info, "Hash", this->manager->hashFuncRef, this->manager->hashTsfn);
}

Napi::Object EdhocCryptoManagerWrapper::Init(Napi::Env env, Napi::Object exports) {
    Napi::HandleScope scope(env);

    Napi::Function func = DefineClass(env, "EdhocCryptoManager", {
        InstanceMethod("setGenerateKey", &EdhocCryptoManagerWrapper::SetGenerateKey),
        InstanceMethod("setDestroyKey", &EdhocCryptoManagerWrapper::SetDestroyKey),
        InstanceMethod("setMakeKeyPair", &EdhocCryptoManagerWrapper::SetMakeKeyPair),
        InstanceMethod("setKeyAgreement", &EdhocCryptoManagerWrapper::SetKeyAgreement),
        InstanceMethod("setSign", &EdhocCryptoManagerWrapper::SetSign),
        InstanceMethod("setVerify", &EdhocCryptoManagerWrapper::SetVerify),
        InstanceMethod("setExtract", &EdhocCryptoManagerWrapper::SetExtract),
        InstanceMethod("setExpand", &EdhocCryptoManagerWrapper::SetExpand),
        InstanceMethod("setEncrypt", &EdhocCryptoManagerWrapper::SetEncrypt),
        InstanceMethod("setDecrypt", &EdhocCryptoManagerWrapper::SetDecrypt),
        InstanceMethod("setHash", &EdhocCryptoManagerWrapper::SetHash)
    });

    Napi::FunctionReference* constructor = new Napi::FunctionReference();
    *constructor = Napi::Persistent(func);

    exports.Set("EdhocCryptoManager", func);

    env.SetInstanceData<Napi::FunctionReference>(constructor);

    return exports;
}
