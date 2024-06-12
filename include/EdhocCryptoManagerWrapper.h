#include <napi.h>
#include "EdhocCryptoManager.h"

class EdhocCryptoManagerWrapper : public Napi::ObjectWrap<EdhocCryptoManagerWrapper> {
public:
    friend class EdhocCryptoManager;
    
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    
    EdhocCryptoManagerWrapper(const Napi::CallbackInfo& info);
    ~EdhocCryptoManagerWrapper();

    const std::shared_ptr<EdhocCryptoManager> GetInternalManager();
    
private:
    std::shared_ptr<EdhocCryptoManager> manager;

    void SetGenerateKey(const Napi::CallbackInfo& info, const Napi::Value &value);
    void SetDestroyKey(const Napi::CallbackInfo& info, const Napi::Value &value);
    void SetMakeKeyPair(const Napi::CallbackInfo& info, const Napi::Value &value);
    void SetKeyAgreement(const Napi::CallbackInfo& info, const Napi::Value &value);
    void SetSign(const Napi::CallbackInfo& info, const Napi::Value &value);
    void SetVerify(const Napi::CallbackInfo& info, const Napi::Value &value);
    void SetExtract(const Napi::CallbackInfo& info, const Napi::Value &value);
    void SetExpand(const Napi::CallbackInfo& info, const Napi::Value &value);
    void SetEncrypt(const Napi::CallbackInfo& info, const Napi::Value &value);
    void SetDecrypt(const Napi::CallbackInfo& info, const Napi::Value &value);
    void SetHash(const Napi::CallbackInfo& info, const Napi::Value &value);

    Napi::Value GetGenerateKey(const Napi::CallbackInfo& info);
    Napi::Value GetDestroyKey(const Napi::CallbackInfo& info);
    Napi::Value GetMakeKeyPair(const Napi::CallbackInfo& info);
    Napi::Value GetKeyAgreement(const Napi::CallbackInfo& info);
    Napi::Value GetSign(const Napi::CallbackInfo& info);
    Napi::Value GetVerify(const Napi::CallbackInfo& info);
    Napi::Value GetExtract(const Napi::CallbackInfo& info);
    Napi::Value GetExpand(const Napi::CallbackInfo& info);
    Napi::Value GetEncrypt(const Napi::CallbackInfo& info);
    Napi::Value GetDecrypt(const Napi::CallbackInfo& info);
    Napi::Value GetHash(const Napi::CallbackInfo& info);

   void SetFunctionAndTsfn(const Napi::Value &value, const std::string& tsfnName, Napi::FunctionReference& functionRef, Napi::ThreadSafeFunction& tsfn);
};
