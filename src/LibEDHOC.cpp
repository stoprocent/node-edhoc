#include <iostream>
#include <thread>

#include "LibEDHOC.h"
#include "EdhocCryptoManagerWrapper.h"
#include "Utils.h"
#include "ThreadSafeDeferred.h"

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

void my_logger(void *user_context, const char *name, const uint8_t *buffer, size_t buffer_length) {
    printf("%s:\n", name);
    for (size_t i = 0; i < buffer_length; i++) {
        printf("%02X ", buffer[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n"); // Break line every 16 bytes
        }
    }
    if (buffer_length % 16 != 0) {
        printf("\n"); // Ensure ending with a new line if not exactly multiple of 16
    }
}

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

    this->_context.logger = my_logger;

    // Suites
    ret = edhoc_set_cipher_suites(&this->_context, &edhoc_cipher_suite_0, 1);

    // Crypto Manager
    EdhocCryptoManagerWrapper* managerWrapper = Napi::ObjectWrap<EdhocCryptoManagerWrapper>::Unwrap(info[4].As<Napi::Object>());
    std::shared_ptr<EdhocCryptoManager> cryptoManager = managerWrapper->GetInternalManager();

    // Keys
	ret = edhoc_bind_keys(&this->_context, cryptoManager.get()->keys);

    // Crypto
	ret = edhoc_bind_crypto(&this->_context, cryptoManager.get()->crypto);

    // Credentials
    std::vector<std::string> cred_keys = {"fetch", "verify"};
    auto credentials = Utils::ExtractFunctionsFromObject(env, info[2], cred_keys);

    std::shared_ptr<EdhocCredentialManager> credentialManager = std::make_shared<EdhocCredentialManager>(env, credentials[0], credentials[1]);
    ret = edhoc_bind_credentials(&this->_context, credentialManager.get()->credentials);

    // EAD
    std::vector<std::string> ead_keys = {"compose", "process"};
    auto ead = Utils::ExtractFunctionsFromObject(env, info[3], ead_keys);

    std::shared_ptr<EdhocEADManager> eadManager = std::make_shared<EdhocEADManager>(env, ead[0], ead[1]);
    ret = edhoc_bind_ead(&this->_context, eadManager.get()->ead);

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

Napi::Value LibEDHOC::ComposeMessage1(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::HandleScope scope(env);

    auto deferred = new ThreadSafeDeferred(env);

    this->taskQueue->EnqueueTask([context = &this->_context, deferred]() mutable {
        uint8_t message[EDHOC_MAX_MESSAGE_SIZE] = { 0 };
        size_t message_length = 0;
        try {
            int result = edhoc_message_1_compose(context, message, sizeof(message), &message_length);
            if (result != EDHOC_SUCCESS) {
                std::string error = "Failed to compose EDHOC Message 1. Error code: " + std::to_string(result);
                deferred->Reject(error);
            } else {
                deferred->Resolve(THREADSAFE_DEFERRED_RESOLVER(Napi::Buffer<uint8_t>::Copy(env, message, message_length)));
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

Napi::Value LibEDHOC::ProcessMessage1(const Napi::CallbackInfo &info) {
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
    
    this->taskQueue->EnqueueTask([context = &this->_context, deferred, message, message_length]() mutable {
        try {
            int ret = edhoc_message_1_process(context, message, message_length);

            if (ret != EDHOC_SUCCESS) {
                std::string errorMessage = "Failed to process EDHOC Message 1. Error code: " + std::to_string(ret);
                deferred->Reject(errorMessage);
            } else {
                deferred->Resolve(THREADSAFE_DEFERRED_RESOLVER(Utils::CreateJsValueFromEdhocCid(env, context->EDHOC_PRIVATE(peer_cid))));
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

Napi::Value LibEDHOC::ComposeMessage2(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    Napi::HandleScope scope(env);

    auto deferred = new ThreadSafeDeferred(env);

    this->taskQueue->EnqueueTask([context = &this->_context, deferred]() mutable {
        uint8_t message[EDHOC_MAX_MESSAGE_SIZE] = { 0 };
        size_t message_length = 0;
        try {
            int ret = edhoc_message_2_compose(context, message, ARRAY_SIZE(message), &message_length);
            if (ret != EDHOC_SUCCESS) {
                deferred->Reject("Failed to compose EDHOC Message 2. Error code: " + std::to_string(ret));
            } else {
                deferred->Resolve(THREADSAFE_DEFERRED_RESOLVER(Napi::Buffer<uint8_t>::Copy(env, message, message_length)));
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

Napi::Value LibEDHOC::ProcessMessage2(const Napi::CallbackInfo &info) {
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

    this->taskQueue->EnqueueTask([context = &this->_context, deferred, message, message_length]() mutable {
        try {
            int ret = edhoc_message_2_process(context, message, message_length);

            if (ret != EDHOC_SUCCESS) {
                std::string errorMessage = "Failed to process EDHOC Message 1. Error code: " + std::to_string(ret);
                deferred->Reject(errorMessage);
            } else {
                deferred->Resolve(THREADSAFE_DEFERRED_RESOLVER(Utils::CreateJsValueFromEdhocCid(env, context->EDHOC_PRIVATE(peer_cid))));
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

Napi::Object LibEDHOC::Init(Napi::Env env, Napi::Object exports) {
    Napi::HandleScope scope(env);
    Napi::Function func = DefineClass(env, "LibEDHOC", {
        InstanceAccessor("connectionID", &LibEDHOC::GetCID, &LibEDHOC::SetCID),
        InstanceAccessor("method", &LibEDHOC::GetMethod, &LibEDHOC::SetMethod),
        InstanceMethod("composeMessage1", &LibEDHOC::ComposeMessage1),
        InstanceMethod("processMessage1", &LibEDHOC::ProcessMessage1),
        InstanceMethod("composeMessage2", &LibEDHOC::ComposeMessage2),
        InstanceMethod("processMessage2", &LibEDHOC::ProcessMessage2),
    });

    Napi::FunctionReference* constructor = new Napi::FunctionReference();
    *constructor = Napi::Persistent(func);
    env.SetInstanceData(constructor);

    exports.Set("LibEDHOC", func);
    return exports;
}
