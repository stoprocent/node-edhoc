#include "EdhocCredentialManagerWrapper.h"

static constexpr const char* kClassName             = "EdhocCredentialManager";
static constexpr const char* kFetchAccessor         = "fetch";
static constexpr const char* kVerifyAccessor        = "verify";
static constexpr const char* kFetchCredentials      = "FetchCredentials";
static constexpr const char* kVerifyCredentials     = "VerifyCredentials";
static constexpr const char* kFunctionExpectedError = "Function expected";

EdhocCredentialManagerWrapper::EdhocCredentialManagerWrapper(const Napi::CallbackInfo& info) : Napi::ObjectWrap<EdhocCredentialManagerWrapper>(info) {
    manager = std::make_shared<EdhocCredentialManager>();
}

EdhocCredentialManagerWrapper::~EdhocCredentialManagerWrapper() {}

const std::shared_ptr<EdhocCredentialManager> EdhocCredentialManagerWrapper::GetInternalManager() {
    return manager;
}

void EdhocCredentialManagerWrapper::SetFunctionAndTsfn(const Napi::Value &value, const std::string& tsfnName, Napi::FunctionReference& functionRef, Napi::ThreadSafeFunction& tsfn) {
    Napi::Env env = value.Env();
    Napi::HandleScope scope(env);

    if (!value.IsFunction()) {
        Napi::TypeError::New(env, kFunctionExpectedError)
            .ThrowAsJavaScriptException();
    }
    else {
        Napi::Function jsFunction = value.As<Napi::Function>();
        functionRef = Napi::Persistent(jsFunction);
        tsfn = Napi::ThreadSafeFunction::New(env, jsFunction, tsfnName, 0, 1);
    }
}

void EdhocCredentialManagerWrapper::SetFetch(const Napi::CallbackInfo& info, const Napi::Value &value) {
    SetFunctionAndTsfn(value, kFetchCredentials, manager->fetchFuncRef, manager->fetchTsfn);
}

void EdhocCredentialManagerWrapper::SetVerify(const Napi::CallbackInfo& info, const Napi::Value &value) {
    SetFunctionAndTsfn(value, kVerifyCredentials, manager->verifyFuncRef, manager->verifyTsfn);
}

Napi::Value EdhocCredentialManagerWrapper::GetFetch(const Napi::CallbackInfo& info) {
    return manager->fetchFuncRef.Value();
}

Napi::Value EdhocCredentialManagerWrapper::GetVerify(const Napi::CallbackInfo& info) {
    return manager->verifyFuncRef.Value();
}

Napi::Object EdhocCredentialManagerWrapper::Init(Napi::Env env, Napi::Object exports) {
    Napi::HandleScope scope(env);

    Napi::Function func = DefineClass(env, kClassName, {
        InstanceAccessor(kFetchAccessor, &EdhocCredentialManagerWrapper::GetFetch, &EdhocCredentialManagerWrapper::SetFetch),
        InstanceAccessor(kVerifyAccessor, &EdhocCredentialManagerWrapper::GetVerify, &EdhocCredentialManagerWrapper::SetVerify),
    });

    Napi::FunctionReference* constructor = new Napi::FunctionReference();
    *constructor = Napi::Persistent(func);

    exports.Set(kClassName, func);

    env.SetInstanceData<Napi::FunctionReference>(constructor);

    return exports;
}
