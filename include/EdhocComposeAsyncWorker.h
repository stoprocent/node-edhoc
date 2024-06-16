// EDHOCAsyncWorker.h
#ifndef EDHOC_COMPOSE_ASYNC_WORKER_H
#define EDHOC_COMPOSE_ASYNC_WORKER_H

#include <napi.h>
#include <vector>

extern "C" {
    #include "edhoc.h"
}

class EdhocComposeAsyncWorker : public Napi::AsyncWorker {
public:
    using CallbackType = std::function<void(Napi::Env&)>;
    EdhocComposeAsyncWorker(Napi::Env& env, Napi::Promise::Deferred deferred, struct edhoc_context &context, int messageNumber, CallbackType callback);
    void Execute() override;
    void OnOK() override;
    void OnError(const Napi::Error& error) override;

private:
    Napi::Promise::Deferred deferred;
    struct edhoc_context &context;
    int messageNumber;
    CallbackType callback;
    std::vector<uint8_t> composedMessage;
};

#endif // EDHOC_COMPOSE_ASYNC_WORKER_H
