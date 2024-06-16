#ifndef EDHOC_EAD_MANAGER_H
#define EDHOC_EAD_MANAGER_H

#include <napi.h>
#include <map>
#include <vector>

extern "C" {
    #include "edhoc.h"
}

using EadMap = std::map<int, std::vector<uint8_t>>;
using EadMapVector = std::vector<EadMap>;
using EadBufferMap = std::map<enum edhoc_message, EadMapVector>;

class EdhocEadManager {
public:
    struct edhoc_ead ead;
    
    EdhocEadManager();
    ~EdhocEadManager();
    
    void StoreEad(enum edhoc_message message, int label, const std::vector<uint8_t>& ead);
    void StoreEad(enum edhoc_message message, const Napi::Array& eadArray);

    const EadMapVector* GetEadByMessage(enum edhoc_message message) const;
    Napi::Array GetEadByMessage(Napi::Env& env, enum edhoc_message message) const;

    void ClearEadByMessage(enum edhoc_message message);

private:
    EadBufferMap eadBuffers_;
    
    static int ComposeEad(void *user_context, enum edhoc_message message, struct edhoc_ead_token *ead_token, size_t ead_token_size, size_t *ead_token_len);
    static int ProcessEad(void *user_context, enum edhoc_message message, const struct edhoc_ead_token *ead_token, size_t ead_token_size);
    
    int callComposeEad(enum edhoc_message message, struct edhoc_ead_token *ead_token, size_t ead_token_size, size_t *ead_token_len);
    int callProcessEad(enum edhoc_message message, const struct edhoc_ead_token *ead_token, size_t ead_token_size);
};

#endif // EDHOC_EAD_MANAGER_H
