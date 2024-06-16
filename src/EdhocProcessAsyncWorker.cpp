#include "EdhocProcessAsyncWorker.h"


EdhocProcessAsyncWorker::EdhocProcessAsyncWorker(Napi::Env& env, Napi::Promise::Deferred deferred, struct edhoc_context &context, int messageNumber, Napi::Buffer<uint8_t> buffer, CallbackType callback)
    : Napi::AsyncWorker(env), deferred(deferred), context(context), messageNumber(messageNumber), messageBuffer(buffer.Data(), buffer.Data() + buffer.Length()), callback(std::move(callback)) { }

void EdhocProcessAsyncWorker::Execute() {
    try {
        uint8_t* message = messageBuffer.data();
        size_t message_length = messageBuffer.size();

        int ret = 0;
        switch (messageNumber) {
            case EDHOC_MSG_1:
                ret = edhoc_message_1_process(&context, message, message_length);
                break;
            case EDHOC_MSG_2:
                ret = edhoc_message_2_process(&context, message, message_length);
                break;
            case EDHOC_MSG_3:
                ret = edhoc_message_3_process(&context, message, message_length);
                break;
            case EDHOC_MSG_4:
                ret = edhoc_message_4_process(&context, message, message_length);
                break;
            default:
                SetError("Invalid message number");
                return;
        }

         if (ret != EDHOC_SUCCESS) {
            std::string errorMessage = "Failed to process EDHOC message " + std::to_string(messageNumber) + ". Error code: " + std::to_string(ret);
            SetError(errorMessage);
        }

    } catch (const std::exception& e) {
        SetError(e.what());
    }
}

void EdhocProcessAsyncWorker::OnOK() {
    Napi::Env env = Env();
    Napi::HandleScope scope(env);
    Napi::Array result = callback(env);
    deferred.Resolve(result);
}

void EdhocProcessAsyncWorker::OnError(const Napi::Error& error) {
    Napi::Env env = Env();
    Napi::HandleScope scope(env);
    deferred.Reject(Napi::String::New(env, error.Message()));
    callback(env);
}
