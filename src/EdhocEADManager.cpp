#include <iostream>
#include <future>
#include <exception>
#include <stdexcept>

#include "EdhocEADManager.h"
#include "UserContext.h"
#include "Utils.h"

EdhocEADManager::EdhocEADManager(Napi::Env env, Napi::Function composeCallback, Napi::Function processCallback)
: composeFuncRef(Napi::Persistent(composeCallback)), processFuncRef(Napi::Persistent(processCallback)) {

    this->composeTsfn = Napi::ThreadSafeFunction::New(composeCallback.Env(), composeCallback, "Compose EAD", 0, 1);
    this->processTsfn = Napi::ThreadSafeFunction::New(processCallback.Env(), processCallback, "Process EAD", 0, 1);

    this->ead.compose = ComposeEAD;
    this->ead.process = ProcessEAD;
}

EdhocEADManager::~EdhocEADManager() {
    this->composeFuncRef.Unref();
    this->processFuncRef.Unref();
    this->composeFuncRef.Reset();
    this->processFuncRef.Reset();
    this->composeTsfn.Release();
    this->processTsfn.Release();
}

// Static implementations
int EdhocEADManager::ComposeEAD(void *user_context, enum edhoc_message message, struct edhoc_ead_token *ead_token, size_t ead_token_size, size_t *ead_token_len) {
    UserContext* context = static_cast<UserContext*>(user_context);
    EdhocEADManager* manager = context->GetEADManager();
    return manager->CallComposeEAD(message, ead_token, ead_token_size, ead_token_len);
}

int EdhocEADManager::ProcessEAD(void *user_context, enum edhoc_message message, const struct edhoc_ead_token *ead_token, size_t ead_token_size) {
    UserContext* context = static_cast<UserContext*>(user_context);
    EdhocEADManager* manager = context->GetEADManager();
    return manager->CallProcessEAD(message, ead_token, ead_token_size);
}

int EdhocEADManager::CallComposeEAD(enum edhoc_message message, struct edhoc_ead_token *ead_token, size_t ead_token_size, size_t *ead_token_len) {
    std::promise<int> promise;
    std::future<int> future = promise.get_future();

    this->composeTsfn.BlockingCall([&promise, message, &ead_token, ead_token_size, &ead_token_len, this](Napi::Env env, Napi::Function jsCallback) {
        try {
            std::vector<napi_value> arguments = {
                Napi::Number::New(env, static_cast<int>(message)),
                Napi::Number::New(env, static_cast<int>(ead_token_size)),
            };
            Utils::InvokeJSFunctionWithPromiseHandling(env, jsCallback, arguments, [&promise, message, &ead_token, ead_token_size, &ead_token_len, this](Napi::Env env, Napi::Value result) {
                if (result.IsNull() || result.IsUndefined()) {
                    return promise.set_value(EDHOC_SUCCESS);
                }

                if (!result.IsArray()) {
                    throw Napi::Error::New(env, "Expected an array from JavaScript callback but got something else.");
                }

                Napi::Array eadArray = result.As<Napi::Array>();
                size_t numEADs = eadArray.Length();

                if (numEADs > ead_token_size) {
                    throw Napi::Error::New(env, "The number of EADs provided exceeds the maximum buffer size allowed.");
                }

                for (size_t i = 0; i < numEADs; ++i) {
                    Napi::Value entry = eadArray.Get(i);
                    if (!entry.IsArray()) {
                        throw Napi::TypeError::New(env, "Each EAD entry must be an array [label, buffer].");
                    }
                    Napi::Array entryArray = entry.As<Napi::Array>();

                    if (entryArray.Length() != 2) {
                        throw Napi::Error::New(env, "Each EAD entry array must contain exactly two elements: a label and a buffer.");
                    }

                    Napi::Value labelValue = entryArray.Get(uint32_t(0));
                    Napi::Value bufferValue = entryArray.Get(uint32_t(1));

                    if (!labelValue.IsNumber()) {
                        throw Napi::TypeError::New(env, "Label must be a number.");
                    }

                    if (!bufferValue.IsBuffer()) {
                        throw Napi::TypeError::New(env, "Buffer must be a buffer.");
                    }

                    int32_t label = labelValue.As<Napi::Number>().Int32Value();
                    Napi::Buffer<uint8_t> buffer = bufferValue.As<Napi::Buffer<uint8_t>>();
                
                    this->StoreEADBuffer(message, buffer);

                    ead_token[i].label = label;
                    ead_token[i].value = buffer.Data();
                    ead_token[i].value_len = buffer.Length();
                }

                *ead_token_len = numEADs;

                promise.set_value(EDHOC_SUCCESS); 
            });
        } catch (const Napi::Error &e) {
            e.ThrowAsJavaScriptException();
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
        }
    });

    future.wait();
    return future.get();
}

int EdhocEADManager::CallProcessEAD(enum edhoc_message message, const struct edhoc_ead_token *ead_token, size_t ead_token_size) {
    std::promise<int> promise;
    std::future<int> future = promise.get_future();

    this->processTsfn.BlockingCall([&promise, message, &ead_token, ead_token_size](Napi::Env env, Napi::Function jsCallback) {
        try {
            Napi::Array jsEadTokensArray = Napi::Array::New(env, ead_token_size);

            for (size_t i = 0; i < ead_token_size; ++i) {
                Napi::Array tokenArray = Napi::Array::New(env, 2);
                
                tokenArray.Set(uint32_t(0), Napi::Number::New(env, ead_token[i].label));
                tokenArray.Set(uint32_t(1), Napi::Buffer<uint8_t>::Copy(env, ead_token[i].value, ead_token[i].value_len));
                
                jsEadTokensArray.Set(i, tokenArray);
            }
            Utils::InvokeJSFunctionWithPromiseHandling(env, jsCallback, { jsEadTokensArray }, [&promise](Napi::Env env, Napi::Value result) {
                // Do nothing
                promise.set_value(EDHOC_SUCCESS); 
            });
        } catch (const Napi::Error &e) {
            e.ThrowAsJavaScriptException();
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
        }
    }); 

    future.wait();
    return future.get();
}

void EdhocEADManager::StoreEADBuffer(enum edhoc_message message, Napi::Buffer<uint8_t> buffer) {
    messageEADBuffers[message].push_back(buffer);
}

void EdhocEADManager::ClearEADBuffersByMessage(enum edhoc_message message) {
    if (messageEADBuffers.find(message) != messageEADBuffers.end()) {
        messageEADBuffers[message].clear();
    }
}