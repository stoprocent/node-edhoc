#ifndef USER_CONTEXT_H
#define USER_CONTEXT_H

#include <napi.h>
#include <memory>
#include "EdhocCryptoManager.h"  // Include the header for EDHOC Crypto Manager
#include "EdhocEadManager.h"     // Include the header for EDHOC External Authorization Data Manager
#include "EdhocCredentialManager.h"  // Include the header for EDHOC Credential Manager

// Define an interface UserContext. This interface will be implemented by classes
// that need to provide specific user-context functionalities in EDHOC protocol interactions.
class UserContext {
public:
    // Constructor taking shared pointers to the managers
    UserContext(std::shared_ptr<EdhocCryptoManager> cryptoManager, 
                std::shared_ptr<EdhocEadManager> eadManager, 
                std::shared_ptr<EdhocCredentialManager> credentialManager)
        : cryptoManager_(std::move(cryptoManager)), 
          eadManager_(std::move(eadManager)), 
          credentialManager_(std::move(credentialManager)) {}

    // Virtual destructor to ensure proper cleanup of derived classes when deleting instances via base-class pointers
    virtual ~UserContext() {
        if (logger) {
            logger.Release();
        }
    }

    // Simplify getters with inline definitions and const correctness
    EdhocCryptoManager* GetCryptoManager() const { return cryptoManager_.get(); }
    EdhocEadManager* GetEadManager() const { return eadManager_.get(); }
    EdhocCredentialManager* GetCredentialManager() const { return credentialManager_.get(); }

    Napi::ThreadSafeFunction logger;
    Napi::ObjectReference parent;

protected:
    std::shared_ptr<EdhocCryptoManager> cryptoManager_;
    std::shared_ptr<EdhocEadManager> eadManager_;
    std::shared_ptr<EdhocCredentialManager> credentialManager_;
};

#endif // USER_CONTEXT_H
