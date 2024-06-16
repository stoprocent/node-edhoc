// EDHOCAsyncWorker.h
#ifndef EDHOC_PROCESS_ASYNC_WORKER_H
#define EDHOC_PROCESS_ASYNC_WORKER_H

#include <napi.h>
#include <vector>

extern "C" {
    #include "edhoc.h"
}

class EdhocProcessAsyncWorker : public Napi::AsyncWorker {
public:
    using CallbackType = std::function<Napi::Array(Napi::Env&)>;
    EdhocProcessAsyncWorker(Napi::Env& env, Napi::Promise::Deferred deferred, struct edhoc_context &context, int messageNumber, Napi::Buffer<uint8_t> buffer, CallbackType callback);
    void Execute() override;
    void OnOK() override;
    void OnError(const Napi::Error& error) override;

private:
    Napi::Promise::Deferred deferred;
    struct edhoc_context &context;
    int messageNumber;
    std::vector<uint8_t> messageBuffer;
    CallbackType callback;
};

#endif // EDHOC_PROCESS_ASYNC_WORKER_H
