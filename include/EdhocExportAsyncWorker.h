#ifndef EDHOC_EXPORT_ASYNC_WORKER_H
#define EDHOC_EXPORT_ASYNC_WORKER_H

#include <napi.h>
#include <vector>
#include <functional>

extern "C" {
    #include "edhoc.h"
}

class EdhocExportAsyncWorker : public Napi::AsyncWorker {
public:
    using CallbackType = std::function<void(Napi::Env)>;

    EdhocExportAsyncWorker(Napi::Env& env, 
                           Napi::Promise::Deferred deferred, 
                           struct edhoc_context &context);
                           
    ~EdhocExportAsyncWorker() override;

    void Execute() override;
    void OnOK() override;
    void OnError(const Napi::Error& error) override;

private:
    Napi::Promise::Deferred deferred;
    struct edhoc_context &context;
    std::vector<uint8_t> masterSecret;
    std::vector<uint8_t> masterSalt;
    std::vector<uint8_t> senderId;
    std::vector<uint8_t> recipientId;
};

#endif // EDHOC_EXPORT_ASYNC_WORKER_H
