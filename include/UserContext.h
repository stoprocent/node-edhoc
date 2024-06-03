#ifndef USER_CONTEXT_H
#define USER_CONTEXT_H

#include <memory>
#include "EdhocCryptoManager.h" // Include the header for EDHOC Crypto Manager  
#include "EdhocEADManager.h"  // Include the header for EDHOC External Authorization Data Manager
#include "EdhocCredentialManager.h"  // Include the header for EDHOC Credential Manager

// Define an interface UserContext. This interface will be implemented by classes
// that need to provide specific user-context functionalities in EDHOC protocol interactions.
class UserContext {
public:
    // Constructor taking shared pointers to the managers
    UserContext(std::shared_ptr<EdhocCryptoManager> cryptoManager, 
                std::shared_ptr<EdhocEADManager> eadManager, 
                std::shared_ptr<EdhocCredentialManager> credentialManager)
        : cryptoManager_(cryptoManager), eadManager_(eadManager), credentialManager_(credentialManager) {}

    // Virtual destructor to ensure proper cleanup of derived classes when deleting instances via base-class pointers
    virtual ~UserContext() {}

    // Pure virtual function to get a pointer to the EDHOC Crypto Manager
    // This function must be implemented by any class that inherits from UserContext
    virtual EdhocCryptoManager* GetCryptoManager() {
        return cryptoManager_.get();
    }

    // Pure virtual function to get a pointer to the EDHOC External Authorization Data (EAD) Manager
    // This function must be implemented by any class that inherits from UserContext
    virtual EdhocEADManager* GetEADManager() {
        return eadManager_.get();
    }

    // Pure virtual function to get a pointer to the EDHOC Credential Manager
    // This function must be implemented by any class that inherits from UserContext
    virtual EdhocCredentialManager* GetCredentialManager() {
        return credentialManager_.get();
    }

protected:
    
    // Protected members to store the shared pointers to the managers
    std::shared_ptr<EdhocCryptoManager> cryptoManager_;
    std::shared_ptr<EdhocEADManager> eadManager_;
    std::shared_ptr<EdhocCredentialManager> credentialManager_;
};

#endif // USER_CONTEXT_H
