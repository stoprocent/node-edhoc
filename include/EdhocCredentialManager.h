#ifndef EDHOC_CREDENTIAL_MANAGER_H
#define EDHOC_CREDENTIAL_MANAGER_H

#include <napi.h>

extern "C" {
#include "edhoc.h"
}

class RunningContext;

/**
 * @class EdhocCredentialManager
 * @brief The EdhocCredentialManager class manages the credentials required for
 * EDHOC protocol.
 */
class EdhocCredentialManager {
 public:
  friend class EdhocCredentialManagerWrapper;

  /**
   * @struct edhoc_credentials
   * @brief Edhoc's bind structure for authentication credentials.
   */
  struct edhoc_credentials credentials;

  /**
   * @brief Constructs an EdhocCredentialManager object.
   */
  EdhocCredentialManager(Napi::Object& jsCredentialManager, Napi::Object& jsEdhoc);

  /**
   * @brief Destroys the EdhocCredentialManager object.
   */
  ~EdhocCredentialManager();

  /**
   * @brief Clears any cached credential objects from the previous EDHOC run.
   *
   * This is intended to be called from EDHOC::reset() to avoid leaking
   * credential references across sessions and to ensure exported values
   * reflect only the current session.
   */
  void ClearCachedCredentials();

  /**
   * @brief Returns the last peer credentials object returned from JS verify().
   *
   * @return Napi::Value The cached credentials object, or null if not available.
   */
  Napi::Value GetCachedPeerCredentials(Napi::Env env);

  /**
   * @brief Static function to fetch the credentials.
   * @param user_context The user context.
   * @param credentials Pointer to the edhoc_auth_creds structure to store the
   * fetched credentials.
   * @return EDHOC_SUCCESS if successful, otherwise an error code.
   */
  static int FetchCredentials(void* user_context, struct edhoc_auth_creds* credentials);

  /**
   * @brief Static function to verify the credentials.
   * @param user_context The user context.
   * @param credentials Pointer to the edhoc_auth_creds structure containing the
   * credentials to verify.
   * @param public_key_reference Pointer to the public key reference.
   * @param public_key_length Pointer to the length of the public key.
   * @return EDHOC_SUCCESS if successful, otherwise an error code.
   */
  static int VerifyCredentials(void* user_context,
                               struct edhoc_auth_creds* credentials,
                               const uint8_t** public_key_reference,
                               size_t* public_key_length);

  /**
   * @brief Calls the FetchCredentials function.
   * @param user_context The user context.
   * @param credentials Pointer to the edhoc_auth_creds structure to store the
   * fetched credentials.
   * @return EDHOC_SUCCESS if successful, otherwise an error code.
   */
  int callFetchCredentials(RunningContext* runningContext, struct edhoc_auth_creds* credentials);

  /**
   * @brief Calls the VerifyCredentials function.
   * @param user_context The user context.
   * @param credentials Pointer to the edhoc_auth_creds structure containing the
   * credentials to verify.
   * @param public_key_reference Pointer to the public key reference.
   * @param public_key_length Pointer to the length of the public key.
   * @return EDHOC_SUCCESS if successful, otherwise an error code.
   */
  int callVerifyCredentials(RunningContext* runningContext,
                            struct edhoc_auth_creds* credentials,
                            const uint8_t** public_key_reference,
                            size_t* public_key_length);

 private:
  std::vector<Napi::Reference<Napi::Object>> credentialReferences_;  ///< References to the JS objects
  Napi::ObjectReference credentialManagerRef_;                       ///< Reference to the JS object
  Napi::ObjectReference edhocRef_;
  Napi::ObjectReference cachedPeerCredentialsRef_;                   ///< Cached peer credential (post-verify)
};

#endif  // EDHOC_CREDENTIAL_MANAGER_H
