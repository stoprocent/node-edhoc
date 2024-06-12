#include "EdhocCredentialManagerWrapper.h"

EdhocCredentialManagerWrapper::EdhocCredentialManagerWrapper(const Napi::CallbackInfo& info) : Napi::ObjectWrap<EdhocCredentialManagerWrapper>(info) {
    this->manager = std::make_shared<EdhocCredentialManager>();
}

EdhocCredentialManagerWrapper::~EdhocCredentialManagerWrapper() {}

const std::shared_ptr<EdhocCredentialManager> EdhocCredentialManagerWrapper::GetInternalManager() {
    return this->manager;
}

void EdhocCredentialManagerWrapper::SetFunctionAndTsfn(const Napi::Value &value, const std::string& tsfnName, Napi::FunctionReference& functionRef, Napi::ThreadSafeFunction& tsfn) {
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

void EdhocCredentialManagerWrapper::SetFetch(const Napi::CallbackInfo& info, const Napi::Value &value) {
    SetFunctionAndTsfn(value, "FetchCredentials", this->manager->fetchFuncRef, this->manager->fetchTsfn);
}

void EdhocCredentialManagerWrapper::SetVerify(const Napi::CallbackInfo& info, const Napi::Value &value) {
    SetFunctionAndTsfn(value, "VerifyCredentials", this->manager->verifyFuncRef, this->manager->verifyTsfn);
}

Napi::Value EdhocCredentialManagerWrapper::GetFetch(const Napi::CallbackInfo& info) {
    return this->manager->fetchFuncRef.Value();
}

Napi::Value EdhocCredentialManagerWrapper::GetVerify(const Napi::CallbackInfo& info) {
    return this->manager->verifyFuncRef.Value();
}

Napi::Object EdhocCredentialManagerWrapper::Init(Napi::Env env, Napi::Object exports) {
    Napi::HandleScope scope(env);

    Napi::Function func = DefineClass(env, "EdhocCredentialManager", {
        InstanceAccessor("fetch", &EdhocCredentialManagerWrapper::GetFetch, &EdhocCredentialManagerWrapper::SetFetch),
        InstanceAccessor("verify", &EdhocCredentialManagerWrapper::GetVerify, &EdhocCredentialManagerWrapper::SetVerify),
    });

    Napi::FunctionReference* constructor = new Napi::FunctionReference();
    *constructor = Napi::Persistent(func);

    exports.Set("EdhocCredentialManager", func);

    env.SetInstanceData<Napi::FunctionReference>(constructor);

    return exports;
}
