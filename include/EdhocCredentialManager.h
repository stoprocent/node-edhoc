#ifndef EDHOC_CREDENTIAL_MANAGER_H
#define EDHOC_CREDENTIAL_MANAGER_H

#include <napi.h>  // Include N-API to interact with Node.js

extern "C" {
    #include "edhoc.h"  // Include EDHOC protocol C headers for cryptographic operations
}

// Define the EdhocCredentialManager class for managing EDHOC authentication credentials.
class EdhocCredentialManager {
public:
    // EDHOC authentication credentials structure that stores pointers to credential fetching and verifying functions.
    struct edhoc_credentials credentials;

    // Constructor to initialize the manager with JavaScript callbacks for credential fetching and verifying.
    // These callbacks are passed by the JavaScript side and used to integrate EDHOC credential management with Node.js.
    EdhocCredentialManager(Napi::Env env, Napi::Function fetchCallback, Napi::Function verifyCallback);

    // Destructor to clean up resources, specifically the ThreadSafeFunction objects.
    ~EdhocCredentialManager();

    // Static methods that serve as C-style callbacks. They are used by the EDHOC library to fetch and verify credentials.
    static int FetchCredentials(void *user_context, struct edhoc_auth_creds *credentials);
    static int VerifyCredentials(void *user_context, struct edhoc_auth_creds *credentials, const uint8_t **public_key_reference, size_t *public_key_length);

    // Methods to invoke the JavaScript callbacks for fetching and verifying credentials via the N-API ThreadSafeFunction mechanism.
    // These methods facilitate the asynchronous interaction between C++ and Node.js.
    int CallFetchCredentials(struct edhoc_auth_creds *credentials);
    int CallVerifyCredentials(struct edhoc_auth_creds *credentials, const uint8_t **public_key_reference, size_t *public_key_length);

private:
    // Map to store credential buffers by credential label.
    std::vector<Napi::Buffer<uint8_t>> credentialBuffers;

    Napi::ThreadSafeFunction fetchTsfn;
    Napi::ThreadSafeFunction verifyTsfn;

    // Napi::FunctionReference objects to hold the JavaScript callbacks for fetching and verifying credentials.
    Napi::FunctionReference fetchFuncRef;
    Napi::FunctionReference verifyFuncRef;
};

#endif // EDHOC_CREDENTIAL_MANAGER_H
