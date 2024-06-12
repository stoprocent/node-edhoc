#include <iostream>
#include <thread>

#include "LibEDHOC.h"
#include "Utils.h"
#include "ThreadSafeDeferred.h"
#include "EdhocCryptoManagerWrapper.h"
#include "EdhocCredentialManagerWrapper.h"

static const struct edhoc_cipher_suite edhoc_cipher_suite_0 = {
    .value = 2,
    .aead_key_length = 16,
    .aead_tag_length = 8,
    .aead_iv_length = 13,
    .hash_length = 32,
    .mac_length = 8,
    .ecc_key_length = 32,
    .ecc_sign_length = 64,
};

using namespace Napi;

LibEDHOC::LibEDHOC(const Napi::CallbackInfo& info) : Napi::ObjectWrap<LibEDHOC>(info),
taskQueue(std::make_unique<TaskQueue>()) {
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

    info.This().As<Napi::Object>().Set("taskQueue", Napi::External<TaskQueue>::New(env, taskQueue.get()));

    // Suites
    ret = edhoc_set_cipher_suites(&this->_context, &edhoc_cipher_suite_0, 1);

    // Crypto Manager
    EdhocCryptoManagerWrapper* cryptoWrapper = Napi::ObjectWrap<EdhocCryptoManagerWrapper>::Unwrap(info[3].As<Napi::Object>());
    std::shared_ptr<EdhocCryptoManager> cryptoManager = cryptoWrapper->GetInternalManager();

    // Keys
	ret = edhoc_bind_keys(&this->_context, cryptoManager.get()->keys);

    // Crypto
	ret = edhoc_bind_crypto(&this->_context, cryptoManager.get()->crypto);

    // Credentials
    EdhocCredentialManagerWrapper* credentialWrapper = Napi::ObjectWrap<EdhocCredentialManagerWrapper>::Unwrap(info[2].As<Napi::Object>());
    std::shared_ptr<EdhocCredentialManager> credentialManager = credentialWrapper->GetInternalManager();

    ret = edhoc_bind_credentials(&this->_context, credentialManager.get()->credentials);

    // EAD
    std::shared_ptr<EdhocEADManager> eadManager = std::make_shared<EdhocEADManager>();
    ret = edhoc_bind_ead(&this->_context, eadManager.get()->ead);

    // Logger
    this->_context.logger = LibEDHOC::Logger;

    // User Context
    this->userContext = std::make_shared<UserContext>(cryptoManager, eadManager, credentialManager);
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

    this->userContext->edhoc = this;

    auto deferred = new ThreadSafeDeferred(env);

    // Parse input array
    if (!info[0].IsArray()) {
        Napi::TypeError::New(env, "Expected an array as input")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Array inputArray = info[0].As<Napi::Array>();
    size_t arrayLength = inputArray.Length();

    for (size_t i = 0; i < arrayLength; i++) {
        Napi::Value element = inputArray.Get(i);
        if (!element.IsObject()) {
            Napi::TypeError::New(env, "Expected an object as element in the input array")
                .ThrowAsJavaScriptException();
            return env.Null();
        }

        Napi::Object obj = element.As<Napi::Object>();
        Napi::Value labelValue = obj.Get("label");
        Napi::Value bufferValue = obj.Get("value");

        if (!labelValue.IsNumber() || !bufferValue.IsBuffer()) {
            Napi::TypeError::New(env, "Expected 'label' to be a number and 'value' to be a buffer in the input array")
                .ThrowAsJavaScriptException();
            return env.Null();
        }

        int label = labelValue.As<Napi::Number>().Int32Value();
        Napi::Buffer<uint8_t> buffer = bufferValue.As<Napi::Buffer<uint8_t>>();

        this->userContext->GetEADManager()->StoreEADBuffer(messageNumber, label, std::vector<uint8_t>(buffer.Data(), buffer.Data() + buffer.Length()));
    }

    this->taskQueue->EnqueueTask([context = &this->_context, userContext = this->userContext, deferred, messageNumber]() mutable {
        uint8_t composedMessage[EDHOC_MAX_MESSAGE_SIZE] = { 0 };
        size_t composedMessage_length = 0;
        try {
            int ret = 0;
            switch (messageNumber) {
                case EDHOC_MSG_1:
                    ret = edhoc_message_1_compose(context, composedMessage, sizeof(composedMessage), &composedMessage_length);
                    break;
                case EDHOC_MSG_2:
                    ret = edhoc_message_2_compose(context, composedMessage, sizeof(composedMessage), &composedMessage_length);
                    break;
                case EDHOC_MSG_3:
                    ret = edhoc_message_3_compose(context, composedMessage, sizeof(composedMessage), &composedMessage_length);
                    break;
                case EDHOC_MSG_4:
                    ret = edhoc_message_4_compose(context, composedMessage, sizeof(composedMessage), &composedMessage_length);
                    break;
                default:
                    deferred->Reject("Invalid message number");
                    return;
            }

            if (ret != EDHOC_SUCCESS) {
                std::string errorMessage = "Failed to compose EDHOC Message " + std::to_string(messageNumber) + ". Error code: " + std::to_string(ret);
                deferred->Reject(errorMessage);
            } else {
                userContext->GetEADManager()->ClearEADBuffersByMessage(messageNumber);
                deferred->Resolve(THREADSAFE_DEFERRED_RESOLVER(Napi::Buffer<uint8_t>::Copy(env, composedMessage, composedMessage_length)));
            }
        }
        catch (const Napi::Error &e) {
            deferred->Resolve(THREADSAFE_DEFERRED_RESOLVER(e.Value()));
        }
        catch (const std::exception &e) {
            deferred->Reject(e.what());
        }   
    });

    return deferred->Promise();
}

Napi::Value LibEDHOC::ProcessMessage(const Napi::CallbackInfo &info, enum edhoc_message messageNumber) {
    Napi::Env env = info.Env();
    Napi::HandleScope scope(env);

    // Check the number of arguments passed.
    if (info.Length() < 1) {
        Napi::TypeError::New(env, "Expected at least one argument")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    // Check the type of the first argument
    if (!info[0].IsBuffer()) {
        Napi::TypeError::New(env, "Expected first argument to be a Buffer")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    // Extract the buffer and its length
    Napi::Buffer<uint8_t> inputBuffer = info[0].As<Napi::Buffer<uint8_t>>();
    uint8_t* message = inputBuffer.Data();
    size_t message_length = inputBuffer.Length();

    auto deferred = new ThreadSafeDeferred(env);

    this->taskQueue->EnqueueTask([context = &this->_context, userContext = 
    this->userContext, deferred, message, message_length, messageNumber]() mutable {
        try {
            int ret = 0;
            switch (messageNumber) {
                case EDHOC_MSG_1:
                    ret = edhoc_message_1_process(context, message, message_length);
                    break;
                case EDHOC_MSG_2:
                    ret = edhoc_message_2_process(context, message, message_length);
                    break;
                case EDHOC_MSG_3:
                    ret = edhoc_message_3_process(context, message, message_length);
                    break;
                case EDHOC_MSG_4:
                    ret = edhoc_message_4_process(context, message, message_length);
                    break;
                default:
                    deferred->Reject("Invalid message number");
                    return;
            }

            if (ret != EDHOC_SUCCESS) {
                std::string errorMessage = "Failed to process EDHOC Message " + std::to_string(messageNumber) + ". Error code: " + std::to_string(ret);
                deferred->Reject(errorMessage);
            } else {
                auto buffers = userContext->GetEADManager()->GetEADBuffersByMessage(messageNumber);
                deferred->Resolve([userContext, buffers, messageNumber] (const Napi::Env env) {
                    Napi::Array result = Napi::Array::New(env, buffers.size());
                    size_t i = 0;
                    for (auto const& map : buffers) {
                        Napi::Object obj = Napi::Object::New(env);
                        for (auto const& [label, buffer] : map) {
                            obj.Set("label", Napi::Number::New(env, label));
                            obj.Set("value", Napi::Buffer<uint8_t>::Copy(env, buffer.data(), buffer.size()));
                        }
                        result.Set(i++, obj);
                    }
                    userContext->GetEADManager()->ClearEADBuffersByMessage(messageNumber);
                    return result;
                });
            }
        }
        catch (const Napi::Error &e) {
            deferred->Resolve(THREADSAFE_DEFERRED_RESOLVER(e.Value()));
        }
        catch (const std::exception &e) {
            deferred->Reject(e.what());
        }   
    });

    return deferred->Promise();
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


Napi::Object LibEDHOC::Init(Napi::Env env, Napi::Object exports) {
    Napi::HandleScope scope(env);
    Napi::Function func = DefineClass(env, "LibEDHOC", {
        InstanceAccessor("connectionID", &LibEDHOC::GetCID, &LibEDHOC::SetCID),
        InstanceAccessor<&LibEDHOC::GetPeerCID>("peerConnectionID"),
        InstanceAccessor("method", &LibEDHOC::GetMethod, &LibEDHOC::SetMethod),
        InstanceAccessor("logger", &LibEDHOC::GetLogger, &LibEDHOC::SetLogger),
        InstanceMethod("composeMessage1", &LibEDHOC::ComposeMessage1),
        InstanceMethod("processMessage1", &LibEDHOC::ProcessMessage1),
        InstanceMethod("composeMessage2", &LibEDHOC::ComposeMessage2),
        InstanceMethod("processMessage2", &LibEDHOC::ProcessMessage2),
        InstanceMethod("composeMessage3", &LibEDHOC::ComposeMessage3),
        InstanceMethod("processMessage3", &LibEDHOC::ProcessMessage3),
        InstanceMethod("composeMessage4", &LibEDHOC::ComposeMessage4),
        InstanceMethod("processMessage4", &LibEDHOC::ProcessMessage4),
    });

    Napi::FunctionReference* constructor = new Napi::FunctionReference();
    *constructor = Napi::Persistent(func);
    env.SetInstanceData(constructor);

    exports.Set("LibEDHOC", func);
    return exports;
}
