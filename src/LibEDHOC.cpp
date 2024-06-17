#include <iostream>
#include <thread>

#include "LibEDHOC.h"
#include "Suites.h"
#include "Utils.h"
#include "EdhocCryptoManagerWrapper.h"
#include "EdhocCredentialManagerWrapper.h"
#include "EdhocComposeAsyncWorker.h"
#include "EdhocProcessAsyncWorker.h"
#include "EdhocExportAsyncWorker.h"

using namespace Napi;

LibEDHOC::LibEDHOC(const Napi::CallbackInfo& info) : Napi::ObjectWrap<LibEDHOC>(info) {
    Napi::Env env = info.Env();
    Napi::HandleScope scope(env);

    int ret = EDHOC_ERROR_GENERIC_ERROR;
    
    // Initialize EDHOC context
    this->_context = { };
    ret = edhoc_context_init(&this->_context);

    // Connection ID
    this->SetCID(info, info[0]);
    
    // Method
    this->SetMethod(info, info[1]);

    // Suites
    this->SetCipherSuites(info, info[2]);

    // Crypto Manager
    EdhocCryptoManagerWrapper* cryptoWrapper = Napi::ObjectWrap<EdhocCryptoManagerWrapper>::Unwrap(info[4].As<Napi::Object>());
    std::shared_ptr<EdhocCryptoManager> cryptoManager = cryptoWrapper->GetInternalManager();

    // Keys
	ret = edhoc_bind_keys(&this->_context, cryptoManager.get()->keys);

    // Crypto
	ret = edhoc_bind_crypto(&this->_context, cryptoManager.get()->crypto);

    // Credentials
    EdhocCredentialManagerWrapper* credentialWrapper = Napi::ObjectWrap<EdhocCredentialManagerWrapper>::Unwrap(info[3].As<Napi::Object>());
    std::shared_ptr<EdhocCredentialManager> credentialManager = credentialWrapper->GetInternalManager();

    ret = edhoc_bind_credentials(&this->_context, credentialManager.get()->credentials);

    // EAD
    std::shared_ptr<EdhocEadManager> eadManager = std::make_shared<EdhocEadManager>();
    ret = edhoc_bind_ead(&this->_context, eadManager.get()->ead);

    // Logger
    this->_context.logger = LibEDHOC::Logger;

    // User Context
    this->userContext = std::make_shared<UserContext>(cryptoManager, eadManager, credentialManager);
    this->userContext->parent = Reference<Object>::New(info.This().As<Object>());

    ret = edhoc_set_user_context(&this->_context, static_cast<void*>(this->userContext.get()));
    
    if (ret != EDHOC_SUCCESS) {
        Napi::TypeError::New(env, "Failed to initialize EDHOC context.")
            .ThrowAsJavaScriptException();
    }
}

LibEDHOC::~LibEDHOC() {
    this->_context = { };
}

Napi::Value LibEDHOC::GetCID(const Napi::CallbackInfo &info) {
    return Utils::CreateJsValueFromEdhocCid(info.Env(), this->_cid);
}

void LibEDHOC::SetCID(const Napi::CallbackInfo &info, const Napi::Value &value) {
    this->_cid = Utils::ConvertJsValueToEdhocCid(value);
    int result = edhoc_set_connection_id(&this->_context, this->_cid);
    if (result != EDHOC_SUCCESS) {
        Napi::TypeError::New(info.Env(), "Failed to set EDHOC Connection ID.")
            .ThrowAsJavaScriptException();
    }
}

Napi::Value LibEDHOC::GetPeerCID(const Napi::CallbackInfo &info) {
    return Utils::CreateJsValueFromEdhocCid(info.Env(), this->_context.EDHOC_PRIVATE(peer_cid));
}

Napi::Value LibEDHOC::GetMethod(const Napi::CallbackInfo &info) {
    return Napi::Number::New(info.Env(), static_cast<int>(this->_method));
}

void LibEDHOC::SetMethod(const Napi::CallbackInfo &info, const Napi::Value &value) {
    this->_method = static_cast<edhoc_method>(value.As<Napi::Number>().Int32Value());
    int result = edhoc_set_method(&this->_context, this->_method);
    if (result != EDHOC_SUCCESS) {
        Napi::TypeError::New(info.Env(), "Failed to set EDHOC Method.")
            .ThrowAsJavaScriptException();
    }
}

void LibEDHOC::SetCipherSuites(const Napi::CallbackInfo &info, const Napi::Value &value) {
    Napi::Env env = info.Env();

    if (!value.IsArray()) {
        Napi::TypeError::New(env, "Array of suite indexes expected")
            .ThrowAsJavaScriptException();
        return;
    }

    Napi::Array jsArray = value.As<Napi::Array>();
    std::vector<const struct edhoc_cipher_suite *> selected_suites;
    
    for (uint32_t i = 0; i < jsArray.Length(); i++) {
        uint32_t index = jsArray.Get(i).As<Napi::Number>().Uint32Value();
        if (index < suite_pointers_count && suite_pointers[index] != nullptr) {
            selected_suites.push_back(suite_pointers[index]);
        } else {
            Napi::RangeError::New(env, "Invalid cipher suite index")
                .ThrowAsJavaScriptException();
            return;
        }
    }

    int ret = edhoc_set_cipher_suites(&this->_context, *selected_suites.data(), (size_t)selected_suites.size());
    if (ret != 0) {
        Napi::TypeError::New(env, "Failed to set cipher suites")
            .ThrowAsJavaScriptException();
        return;
    }
}

Napi::Value LibEDHOC::GetCipherSuites(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    Napi::Array result = Napi::Array::New(env, this->_context.EDHOC_PRIVATE(csuite_len));
    for (size_t i = 0; i < this->_context.EDHOC_PRIVATE(csuite_len); i++) {
        result.Set(i, Napi::Number::New(env, this->_context.EDHOC_PRIVATE(csuite)[i].value));
    }
    return result;
}

Napi::Value LibEDHOC::GetLogger(const Napi::CallbackInfo &info) {
    return this->logger.Value();
}

void LibEDHOC::SetLogger(const Napi::CallbackInfo &info, const Napi::Value &value) {
    if (!info[0].IsFunction()) {
        Napi::TypeError::New(info.Env(), "Expected a function")
            .ThrowAsJavaScriptException();
    }
    Napi::Function jsCallback = info[0].As<Napi::Function>();
    this->logger = Napi::Persistent(jsCallback);
    this->userContext->logger = Napi::ThreadSafeFunction::New(info.Env(), jsCallback, "Logger", 0, 1);
}

void LibEDHOC::Logger(void *user_context, const char *name, const uint8_t *buffer, size_t buffer_length) {
    UserContext* context = static_cast<UserContext*>(user_context);
    if (context->logger == nullptr) {
        return;
    }
    context->logger.NonBlockingCall([name, buffer, buffer_length](Napi::Env env, Napi::Function jsCallback) {
        jsCallback.Call({
            Napi::String::New(env, name), 
            Napi::Buffer<uint8_t>::Copy(env, buffer, buffer_length)
        });
    });
}

Napi::Value LibEDHOC::ComposeMessage(const Napi::CallbackInfo& info, enum edhoc_message messageNumber) {
    Napi::Env env = info.Env();
    Napi::HandleScope scope(env);

    if (info[0].IsArray()) {
        try {
            this->userContext->GetEadManager()->StoreEad(messageNumber, info[0].As<Napi::Array>());
        }
        catch (const Napi::Error &e) {
            e.ThrowAsJavaScriptException();
            return env.Null();
        }
    }

    auto deferred = Napi::Promise::Deferred::New(env);

    EdhocComposeAsyncWorker::CallbackType callback = [this, messageNumber](Napi::Env &env) {
        this->userContext->GetEadManager()->ClearEadByMessage(messageNumber);
    };

    EdhocComposeAsyncWorker* worker = new EdhocComposeAsyncWorker(env, deferred, this->_context, messageNumber, callback);
    worker->Queue();

    return deferred.Promise();
}

Napi::Value LibEDHOC::ProcessMessage(const Napi::CallbackInfo &info, enum edhoc_message messageNumber) {
    Napi::Env env = info.Env();
    Napi::HandleScope scope(env);

    if (info.Length() < 1 || !info[0].IsBuffer()) {
        Napi::TypeError::New(env, "Expected first argument to be a Buffer")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Buffer<uint8_t> inputBuffer = info[0].As<Napi::Buffer<uint8_t>>();

    auto deferred = Napi::Promise::Deferred::New(env);

    EdhocProcessAsyncWorker::CallbackType callback = [userContext = this->userContext, messageNumber](Napi::Env &env) {
        Napi::Array EADs = userContext->GetEadManager()->GetEadByMessage(env, messageNumber);
        userContext->GetEadManager()->ClearEadByMessage(messageNumber);
        return EADs;
    };

    EdhocProcessAsyncWorker* worker = new EdhocProcessAsyncWorker(env, deferred, this->_context, messageNumber, inputBuffer, callback);
    worker->Queue();

    return deferred.Promise();
}

Napi::Value LibEDHOC::ComposeMessage1(const Napi::CallbackInfo& info) {
    return ComposeMessage(info, EDHOC_MSG_1);
}

Napi::Value LibEDHOC::ProcessMessage1(const Napi::CallbackInfo &info) {
    return ProcessMessage(info, EDHOC_MSG_1);
}

Napi::Value LibEDHOC::ComposeMessage2(const Napi::CallbackInfo &info) {
    return ComposeMessage(info, EDHOC_MSG_2);
}

Napi::Value LibEDHOC::ProcessMessage2(const Napi::CallbackInfo &info) {
    return ProcessMessage(info, EDHOC_MSG_2);
}

Napi::Value LibEDHOC::ComposeMessage3(const Napi::CallbackInfo &info) {
    return ComposeMessage(info, EDHOC_MSG_3);
}

Napi::Value LibEDHOC::ProcessMessage3(const Napi::CallbackInfo &info) {
    return ProcessMessage(info, EDHOC_MSG_3);
}

Napi::Value LibEDHOC::ComposeMessage4(const Napi::CallbackInfo &info) {
    return ComposeMessage(info, EDHOC_MSG_4);
}

Napi::Value LibEDHOC::ProcessMessage4(const Napi::CallbackInfo &info) {
    return ProcessMessage(info, EDHOC_MSG_4);
}

Napi::Value LibEDHOC::ExportOSCORE(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    Napi::HandleScope scope(env);

    auto deferred = Napi::Promise::Deferred::New(env);

    EdhocExportAsyncWorker* worker = new EdhocExportAsyncWorker(env, deferred, this->_context);
    worker->Queue();

    return deferred.Promise();
}

Napi::Object LibEDHOC::Init(Napi::Env env, Napi::Object exports) {
    Napi::HandleScope scope(env);
    Napi::Function func = DefineClass(env, "LibEDHOC", {
        InstanceAccessor("connectionID", &LibEDHOC::GetCID, &LibEDHOC::SetCID),
        InstanceAccessor<&LibEDHOC::GetPeerCID>("peerConnectionID"),
        InstanceAccessor("method", &LibEDHOC::GetMethod, &LibEDHOC::SetMethod),
        InstanceAccessor("cipherSuites", &LibEDHOC::GetCipherSuites, &LibEDHOC::SetCipherSuites),
        InstanceAccessor("logger", &LibEDHOC::GetLogger, &LibEDHOC::SetLogger),
        InstanceMethod("composeMessage1", &LibEDHOC::ComposeMessage1),
        InstanceMethod("processMessage1", &LibEDHOC::ProcessMessage1),
        InstanceMethod("composeMessage2", &LibEDHOC::ComposeMessage2),
        InstanceMethod("processMessage2", &LibEDHOC::ProcessMessage2),
        InstanceMethod("composeMessage3", &LibEDHOC::ComposeMessage3),
        InstanceMethod("processMessage3", &LibEDHOC::ProcessMessage3),
        InstanceMethod("composeMessage4", &LibEDHOC::ComposeMessage4),
        InstanceMethod("processMessage4", &LibEDHOC::ProcessMessage4),
        InstanceMethod("exportOSCORE", &LibEDHOC::ExportOSCORE),
    });

    Napi::FunctionReference* constructor = new Napi::FunctionReference();
    *constructor = Napi::Persistent(func);
    env.SetInstanceData(constructor);

    exports.Set("LibEDHOC", func);
    return exports;
}
