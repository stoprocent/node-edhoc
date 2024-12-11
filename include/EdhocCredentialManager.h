#ifndef EDHOC_CREDENTIAL_MANAGER_H
#define EDHOC_CREDENTIAL_MANAGER_H

#include <napi.h>

extern "C" {
#include "edhoc.h"
}

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
   * @brief Libedhoc's bind structure for authentication credentials.
   */
  struct edhoc_credentials credentials;

  /**
   * @brief Constructs an EdhocCredentialManager object.
   */
  EdhocCredentialManager(Napi::Object& jsCredentialManager);

  /**
   * @brief Destroys the EdhocCredentialManager object.
   */
  ~EdhocCredentialManager();

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
  int callFetchCredentials(const void* user_context, struct edhoc_auth_creds* credentials);

  /**
   * @brief Calls the VerifyCredentials function.
   * @param user_context The user context.
   * @param credentials Pointer to the edhoc_auth_creds structure containing the
   * credentials to verify.
   * @param public_key_reference Pointer to the public key reference.
   * @param public_key_length Pointer to the length of the public key.
   * @return EDHOC_SUCCESS if successful, otherwise an error code.
   */
  int callVerifyCredentials(const void* user_context,
                            struct edhoc_auth_creds* credentials,
                            const uint8_t** public_key_reference,
                            size_t* public_key_length);

  /**
   * @brief Sets up the async functions.
   */
  void SetupAsyncFunctions();

  /**
   * @brief Releases the async functions.
   */
  void CleanupAsyncFunctions();

 private:
  std::vector<Napi::Reference<Napi::Object>> credentialReferences;  ///< References to the JS objects
  Napi::ObjectReference credentialManagerRef;                       ///< Reference to the JS object
  Napi::ThreadSafeFunction fetchTsfn;                               ///< Thread-safe function for FetchCredentials
  Napi::ThreadSafeFunction verifyTsfn;                              ///< Thread-safe function for VerifyCredentials

  /**
   * @brief Assosciates the thread-safe function with the JS object function.
   * @param name The name of the function in the JS credential manager object.
   * @param tsfn The thread-safe function.
   */
  void SetFunction(const char* name, Napi::ThreadSafeFunction& tsfn);
};

#endif  // EDHOC_CREDENTIAL_MANAGER_H
