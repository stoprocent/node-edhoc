#ifndef USER_CONTEXT_H
#define USER_CONTEXT_H

#include <napi.h>
#include <memory>
#include "EdhocCryptoManager.h" // Include the header for EDHOC Crypto Manager  
#include "EdhocEADManager.h"  // Include the header for EDHOC External Authorization Data Manager
#include "EdhocCredentialManager.h"  // Include the header for EDHOC Credential Manager

// Define an interface UserContext. This interface will be implemented by classes
// that need to provide specific user-context functionalities in EDHOC protocol interactions.
class UserContext {
public:

    Napi::ThreadSafeFunction logger;
    
    void *edhoc;

    // Constructor taking shared pointers to the managers
    UserContext(std::shared_ptr<EdhocCryptoManager> cryptoManager, 
                std::shared_ptr<EdhocEADManager> eadManager, 
                std::shared_ptr<EdhocCredentialManager> credentialManager)
        : cryptoManager_(cryptoManager), eadManager_(eadManager), credentialManager_(credentialManager) {}

    // Virtual destructor to ensure proper cleanup of derived classes when deleting instances via base-class pointers
    ~UserContext() {
        if (logger != nullptr) {
            logger.Release();
        }
    }

    // Pure virtual function to get a pointer to the EDHOC Crypto Manager
    EdhocCryptoManager* GetCryptoManager() {
        return cryptoManager_.get();
    }

    // Pure virtual function to get a pointer to the EDHOC External Authorization Data (EAD) Manager
    EdhocEADManager* GetEADManager() {
        return eadManager_.get();
    }

    // Pure virtual function to get a pointer to the EDHOC Credential Manager
    EdhocCredentialManager* GetCredentialManager() {
        return credentialManager_.get();
    }

    Napi::ObjectReference parent;

protected:
    
    // Protected members to store the shared pointers to the managers
    std::shared_ptr<EdhocCryptoManager> cryptoManager_;
    std::shared_ptr<EdhocEADManager> eadManager_;
    std::shared_ptr<EdhocCredentialManager> credentialManager_;
};

#endif // USER_CONTEXT_H
