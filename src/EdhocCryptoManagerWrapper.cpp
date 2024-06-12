#include "EdhocCryptoManagerWrapper.h"

EdhocCryptoManagerWrapper::EdhocCryptoManagerWrapper(const Napi::CallbackInfo& info) : Napi::ObjectWrap<EdhocCryptoManagerWrapper>(info) {
    this->manager = std::make_shared<EdhocCryptoManager>();
}

EdhocCryptoManagerWrapper::~EdhocCryptoManagerWrapper() {}

const std::shared_ptr<EdhocCryptoManager> EdhocCryptoManagerWrapper::GetInternalManager() {
    return this->manager;
}

void EdhocCryptoManagerWrapper::SetFunctionAndTsfn(const Napi::Value &value, const std::string& tsfnName, Napi::FunctionReference& functionRef, Napi::ThreadSafeFunction& tsfn) {
    Napi::Env env = value.Env();
    Napi::HandleScope scope(env);

    if (!value.IsFunction()) {
        Napi::TypeError::New(env, "Function expected")
            .ThrowAsJavaScriptException();
    }
    else {
        Napi::Function jsFunction = value.As<Napi::Function>();
        functionRef = Napi::Persistent(jsFunction);
        tsfn = Napi::ThreadSafeFunction::New(env, jsFunction, tsfnName, 0, 1);
    }
}

void EdhocCryptoManagerWrapper::SetGenerateKey(const Napi::CallbackInfo& info, const Napi::Value &value) {
    SetFunctionAndTsfn(value, "GenerateKey", this->manager->generateKeyFuncRef, this->manager->generateTsfn);
}

void EdhocCryptoManagerWrapper::SetDestroyKey(const Napi::CallbackInfo& info, const Napi::Value &value) {
    SetFunctionAndTsfn(value, "DestroyKey", this->manager->destroyKeyFuncRef, this->manager->destroyTsfn);
}

void EdhocCryptoManagerWrapper::SetMakeKeyPair(const Napi::CallbackInfo& info, const Napi::Value &value) {
    return SetFunctionAndTsfn(value, "MakeKeyPair", this->manager->makeKeyPairFuncRef, this->manager->makeKeyPairTsfn);
}

void EdhocCryptoManagerWrapper::SetKeyAgreement(const Napi::CallbackInfo& info, const Napi::Value &value) {
    return SetFunctionAndTsfn(value, "KeyAgreement", this->manager->keyAgreementFuncRef, this->manager->keyAgreementTsfn);
}

void EdhocCryptoManagerWrapper::SetSign(const Napi::CallbackInfo& info, const Napi::Value &value) {
    SetFunctionAndTsfn(value, "Sign", this->manager->signFuncRef, this->manager->signTsfn);
}

void EdhocCryptoManagerWrapper::SetVerify(const Napi::CallbackInfo& info, const Napi::Value &value) {
    SetFunctionAndTsfn(value, "Verify", this->manager->verifyFuncRef, this->manager->verifyTsfn);
}

void EdhocCryptoManagerWrapper::SetExtract(const Napi::CallbackInfo& info, const Napi::Value &value) {
    SetFunctionAndTsfn(value, "Extract", this->manager->extractFuncRef, this->manager->extractTsfn);
}

void EdhocCryptoManagerWrapper::SetExpand(const Napi::CallbackInfo& info, const Napi::Value &value) {
    SetFunctionAndTsfn(value, "Expand", this->manager->expandFuncRef, this->manager->expandTsfn);
}

void EdhocCryptoManagerWrapper::SetEncrypt(const Napi::CallbackInfo& info, const Napi::Value &value) {
    SetFunctionAndTsfn(value, "Encrypt", this->manager->encryptFuncRef, this->manager->encryptTsfn);
}

void EdhocCryptoManagerWrapper::SetDecrypt(const Napi::CallbackInfo& info, const Napi::Value &value) {
    SetFunctionAndTsfn(value, "Decrypt", this->manager->decryptFuncRef, this->manager->decryptTsfn);
}

void EdhocCryptoManagerWrapper::SetHash(const Napi::CallbackInfo& info, const Napi::Value &value) {
    SetFunctionAndTsfn(value, "Hash", this->manager->hashFuncRef, this->manager->hashTsfn);
}

Napi::Value EdhocCryptoManagerWrapper::GetGenerateKey(const Napi::CallbackInfo& info) {
    return this->manager->generateKeyFuncRef.Value();
}

Napi::Value EdhocCryptoManagerWrapper::GetDestroyKey(const Napi::CallbackInfo& info) {
    return this->manager->destroyKeyFuncRef.Value();
}

Napi::Value EdhocCryptoManagerWrapper::GetMakeKeyPair(const Napi::CallbackInfo& info) {
    return this->manager->makeKeyPairFuncRef.Value();
}

Napi::Value EdhocCryptoManagerWrapper::GetKeyAgreement(const Napi::CallbackInfo& info) {
    return this->manager->keyAgreementFuncRef.Value();
}

Napi::Value EdhocCryptoManagerWrapper::GetSign(const Napi::CallbackInfo& info) {
    return this->manager->signFuncRef.Value();
}

Napi::Value EdhocCryptoManagerWrapper::GetVerify(const Napi::CallbackInfo& info) {
    return this->manager->verifyFuncRef.Value();
}

Napi::Value EdhocCryptoManagerWrapper::GetExtract(const Napi::CallbackInfo& info) {
    return this->manager->extractFuncRef.Value();
}

Napi::Value EdhocCryptoManagerWrapper::GetExpand(const Napi::CallbackInfo& info) {
    return this->manager->expandFuncRef.Value();
}

Napi::Value EdhocCryptoManagerWrapper::GetEncrypt(const Napi::CallbackInfo& info) {
    return this->manager->encryptFuncRef.Value();
}

Napi::Value EdhocCryptoManagerWrapper::GetDecrypt(const Napi::CallbackInfo& info) {
    return this->manager->decryptFuncRef.Value();
}

Napi::Value EdhocCryptoManagerWrapper::GetHash(const Napi::CallbackInfo& info) {
    return this->manager->hashFuncRef.Value();
}

Napi::Object EdhocCryptoManagerWrapper::Init(Napi::Env env, Napi::Object exports) {
    Napi::HandleScope scope(env);

    Napi::Function func = DefineClass(env, "EdhocCryptoManager", {
        InstanceAccessor("generateKey", &EdhocCryptoManagerWrapper::GetGenerateKey, &EdhocCryptoManagerWrapper::SetGenerateKey),
        InstanceAccessor("destroyKey", &EdhocCryptoManagerWrapper::GetDestroyKey, &EdhocCryptoManagerWrapper::SetDestroyKey),
        InstanceAccessor("makeKeyPair", &EdhocCryptoManagerWrapper::GetMakeKeyPair, &EdhocCryptoManagerWrapper::SetMakeKeyPair),
        InstanceAccessor("keyAgreement", &EdhocCryptoManagerWrapper::GetKeyAgreement, &EdhocCryptoManagerWrapper::SetKeyAgreement),
        InstanceAccessor("sign", &EdhocCryptoManagerWrapper::GetSign, &EdhocCryptoManagerWrapper::SetSign),
        InstanceAccessor("verify", &EdhocCryptoManagerWrapper::GetVerify, &EdhocCryptoManagerWrapper::SetVerify),
        InstanceAccessor("extract", &EdhocCryptoManagerWrapper::GetExtract, &EdhocCryptoManagerWrapper::SetExtract),
        InstanceAccessor("expand", &EdhocCryptoManagerWrapper::GetExpand, &EdhocCryptoManagerWrapper::SetExpand),
        InstanceAccessor("encrypt", &EdhocCryptoManagerWrapper::GetEncrypt, &EdhocCryptoManagerWrapper::SetEncrypt),
        InstanceAccessor("decrypt", &EdhocCryptoManagerWrapper::GetDecrypt, &EdhocCryptoManagerWrapper::SetDecrypt),
        InstanceAccessor("hash", &EdhocCryptoManagerWrapper::GetHash, &EdhocCryptoManagerWrapper::SetHash)
    });

    Napi::FunctionReference* constructor = new Napi::FunctionReference();
    *constructor = Napi::Persistent(func);

    exports.Set("EdhocCryptoManager", func);

    env.SetInstanceData<Napi::FunctionReference>(constructor);

    return exports;
}
