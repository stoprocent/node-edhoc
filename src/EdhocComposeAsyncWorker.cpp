#include "EdhocComposeAsyncWorker.h"


EdhocComposeAsyncWorker::EdhocComposeAsyncWorker(Napi::Env& env, Napi::Promise::Deferred deferred, struct edhoc_context &context, int messageNumber, CallbackType callback)
    : Napi::AsyncWorker(env), deferred(deferred), context(context), messageNumber(messageNumber), callback(std::move(callback)) {
}

void EdhocComposeAsyncWorker::Execute() {
    try {
        composedMessage.resize(4096);
        size_t composedMessageLength = 0;

        int ret = 0;
        switch (messageNumber) {
            case EDHOC_MSG_1:
                ret = edhoc_message_1_compose(&context, composedMessage.data(), composedMessage.size(), &composedMessageLength);
                break;
            case EDHOC_MSG_2:
                ret = edhoc_message_2_compose(&context, composedMessage.data(), composedMessage.size(), &composedMessageLength);
                break;
            case EDHOC_MSG_3:
                ret = edhoc_message_3_compose(&context, composedMessage.data(), composedMessage.size(), &composedMessageLength);
                break;
            case EDHOC_MSG_4:
                ret = edhoc_message_4_compose(&context, composedMessage.data(), composedMessage.size(), &composedMessageLength);
                break;
            default:
                SetError("Invalid message number");
                return;
        }

        composedMessage.resize(composedMessageLength);

         if (ret != EDHOC_SUCCESS) {
            std::string errorMessage = "Failed to compose EDHOC message " + std::to_string(messageNumber) + ". Error code: " + std::to_string(ret);
            SetError(errorMessage);
        }

    } catch (const std::exception& e) {
        SetError(e.what());
    }
}

void EdhocComposeAsyncWorker::OnOK() {
    Napi::Env env = Env();
    Napi::HandleScope scope(env);
    deferred.Resolve(Napi::Buffer<uint8_t>::Copy(env, composedMessage.data(), composedMessage.size()));
    callback(env);
}

void EdhocComposeAsyncWorker::OnError(const Napi::Error& error) {
    Napi::Env env = Env();
    Napi::HandleScope scope(env);
    deferred.Reject(Napi::String::New(env, error.Message()));
    callback(env);
}
