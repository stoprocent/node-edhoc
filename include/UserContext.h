#ifndef USER_CONTEXT_H
#define USER_CONTEXT_H

#include <napi.h>
#include <memory>
#include "EdhocCredentialManager.h"
#include "EdhocCryptoManager.h"
#include "EdhocEadManager.h"

/**
 * @class UserContext
 * @brief Represents the user context for the Edhoc protocol.
 *
 * The UserContext class encapsulates the necessary components for the Edhoc
 * protocol, including the crypto manager, EAD manager, and credential manager.
 * It also provides access to a logger and a parent object reference.
 */
class UserContext {
 public:
  /**
   * @brief Constructs a UserContext object with the specified components.
   *
   * @param cryptoManager The shared pointer to the EdhocCryptoManager.
   * @param eadManager The shared pointer to the EdhocEadManager.
   * @param credentialManager The shared pointer to the EdhocCredentialManager.
   */
  UserContext(std::shared_ptr<EdhocCryptoManager> cryptoManager,
              std::shared_ptr<EdhocEadManager> eadManager,
              std::shared_ptr<EdhocCredentialManager> credentialManager)
      : cryptoManager(std::move(cryptoManager)),
        eadManager(std::move(eadManager)),
        credentialManager(std::move(credentialManager)) {}

  /**
   * @brief Destroys the UserContext object.
   *
   * If a logger is present, it will be released.
   */
  virtual ~UserContext() {
    if (logger) {
      logger.Release();
    }
  }

  /**
   * @brief Gets the crypto manager associated with the UserContext.
   *
   * @return A pointer to the EdhocCryptoManager.
   */
  EdhocCryptoManager* GetCryptoManager() const { return cryptoManager.get(); }

  /**
   * @brief Gets the EAD manager associated with the UserContext.
   *
   * @return A pointer to the EdhocEadManager.
   */
  EdhocEadManager* GetEadManager() const { return eadManager.get(); }

  /**
   * @brief Gets the credential manager associated with the UserContext.
   *
   * @return A pointer to the EdhocCredentialManager.
   */
  EdhocCredentialManager* GetCredentialManager() const {
    return credentialManager.get();
  }

  Napi::ThreadSafeFunction logger;  ///< The logger for the UserContext
  Napi::ObjectReference
      parent;  ///< The parent object reference for the UserContext

 protected:
  std::shared_ptr<EdhocCryptoManager> cryptoManager;  ///< The crypto manager
  std::shared_ptr<EdhocEadManager> eadManager;        ///< The EAD manager
  std::shared_ptr<EdhocCredentialManager>
      credentialManager;  ///< The credential manager
};

#endif  // USER_CONTEXT_H
