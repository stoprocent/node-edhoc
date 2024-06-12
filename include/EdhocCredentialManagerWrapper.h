#include <napi.h>
#include "EdhocCredentialManager.h"

class EdhocCredentialManagerWrapper : public Napi::ObjectWrap<EdhocCredentialManagerWrapper> {
public:
    friend class EdhocCredentialManager;
    
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    
    EdhocCredentialManagerWrapper(const Napi::CallbackInfo& info);
    ~EdhocCredentialManagerWrapper();

    const std::shared_ptr<EdhocCredentialManager> GetInternalManager();
    
private:
    std::shared_ptr<EdhocCredentialManager> manager;

    void SetFetch(const Napi::CallbackInfo& info, const Napi::Value &value);
    Napi::Value GetFetch(const Napi::CallbackInfo& info);

    void SetVerify(const Napi::CallbackInfo& info, const Napi::Value &value);
    Napi::Value GetVerify(const Napi::CallbackInfo& info);

    void SetFunctionAndTsfn(const Napi::Value &value, const std::string& tsfnName, Napi::FunctionReference& functionRef, Napi::ThreadSafeFunction& tsfn);
};
