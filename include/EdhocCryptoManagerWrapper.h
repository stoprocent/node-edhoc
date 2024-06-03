#include <napi.h>
#include "EdhocCryptoManager.h"  // Make sure this is the correct path to your class definition

class EdhocCryptoManagerWrapper : public Napi::ObjectWrap<EdhocCryptoManagerWrapper> {
public:
    friend class EdhocCryptoManager;
    
    static Napi::Object Init(Napi::Env env, Napi::Object exports);  // Used to initialize the class
    
    EdhocCryptoManagerWrapper(const Napi::CallbackInfo& info);  // Constructor
    ~EdhocCryptoManagerWrapper();  // Destructor
    const std::shared_ptr<EdhocCryptoManager> GetInternalManager();  // Getter method for internal instance
    
    Napi::Value SetGenerateKey(const Napi::CallbackInfo& info);
    Napi::Value SetDestroyKey(const Napi::CallbackInfo& info);
    Napi::Value SetMakeKeyPair(const Napi::CallbackInfo& info);
    Napi::Value SetKeyAgreement(const Napi::CallbackInfo& info);
    Napi::Value SetSign(const Napi::CallbackInfo& info);
    Napi::Value SetVerify(const Napi::CallbackInfo& info);
    Napi::Value SetExtract(const Napi::CallbackInfo& info);
    Napi::Value SetExpand(const Napi::CallbackInfo& info);
    Napi::Value SetEncrypt(const Napi::CallbackInfo& info);
    Napi::Value SetDecrypt(const Napi::CallbackInfo& info);
    Napi::Value SetHash(const Napi::CallbackInfo& info);
    
private:
    std::shared_ptr<EdhocCryptoManager> manager;

    Napi::Value SetFunctionAndTsfn(
    const Napi::CallbackInfo& info,
    const std::string& tsfnName,
    Napi::FunctionReference& functionRef,
    Napi::ThreadSafeFunction& tsfn);
};
