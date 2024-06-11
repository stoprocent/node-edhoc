#ifndef EDHOC_EAD_MANAGER_H
#define EDHOC_EAD_MANAGER_H

#include <napi.h>  // Include N-API to interact with Node.js
#include <map>
#include <vector>

extern "C" {
    #include "edhoc.h"  // Include EDHOC protocol C headers for cryptographic operations
}

// Define the EdhocEADManager class for managing External Authorization Data (EAD) in EDHOC exchanges.
class EdhocEADManager {
public:
    // EDHOC EAD operations structure used to hold callback pointers for EAD composing and processing.
    struct edhoc_ead ead;

    EdhocEADManager();

    // Destructor to clean up resources, specifically the ThreadSafeFunction objects.
    ~EdhocEADManager();

    // Helper functions to store and clear EAD buffers by EDHOC message type.
    void StoreEADBuffer(enum edhoc_message message, int label, std::vector<uint8_t> ead);
    std::vector<std::map<int, std::vector<uint8_t>>> GetEADBuffersByMessage(enum edhoc_message message);
    void ClearEADBuffersByMessage(enum edhoc_message message);

private:
    
    // Map to store EAD buffers by EDHOC message type.
    std::map<enum edhoc_message, std::vector<std::map<int, std::vector<uint8_t>>>> EadBuffers_;

    // Static methods that serve as C-style callbacks for the EDHOC library to call for composing and processing EAD.
    static int ComposeEAD(void *user_context, enum edhoc_message message, struct edhoc_ead_token *ead_token, size_t ead_token_size, size_t *ead_token_len);
    static int ProcessEAD(void *user_context, enum edhoc_message message, const struct edhoc_ead_token *ead_token, size_t ead_token_size);

    // Methods to invoke the JavaScript callbacks for composing and processing EAD via the N-API ThreadSafeFunction mechanism.
    // These methods handle the asynchronous interaction between C++ and Node.js.
    int CallComposeEAD(enum edhoc_message message, struct edhoc_ead_token *ead_token, size_t ead_token_size, size_t *ead_token_len);
    int CallProcessEAD(enum edhoc_message message, const struct edhoc_ead_token *ead_token, size_t ead_token_size);
 
};

#endif // EDHOC_EAD_MANAGER_H
