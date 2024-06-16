#ifndef EDHOC_CRYPTO_MANAGER_H
#define EDHOC_CRYPTO_MANAGER_H

#include <napi.h>  // Include N-API to interact with Node.js

extern "C" {
    #include "edhoc.h"  // Include EDHOC protocol C headers for cryptographic operations
}

// Define the EdhocCryptoManager class for managing EDHOC cryptographic operations.
class EdhocCryptoManager {
public:
    friend class EdhocCryptoManagerWrapper;

    // Structures for managing cryptographic operations and keys.
    struct edhoc_crypto crypto;
    struct edhoc_keys keys;

    // Constructor to initialize the manager with JavaScript functions for cryptographic operations.
    EdhocCryptoManager();

    // Destructor to clean up resources, specifically the ThreadSafeFunction objects.
    ~EdhocCryptoManager();

    static int GenerateKey(void *user_context, enum edhoc_key_type key_type, const uint8_t *raw_key, size_t raw_key_length, void *key_id);
    static int DestroyKey(void *user_context, void *key_id);
    static int MakeKeyPair(void *user_context, const void *key_id, uint8_t *private_key, size_t private_key_size, size_t *private_key_length, uint8_t *public_key, size_t public_key_size, size_t *public_key_length);
    static int KeyAgreement(void *user_context, const void *key_id, const uint8_t *peer_public_key, size_t peer_public_key_length, uint8_t *shared_secret, size_t shared_secret_size, size_t *shared_secret_length);
    static int Sign(void *user_context, const void *key_id, const uint8_t *input, size_t input_length, uint8_t *signature, size_t signature_size, size_t *signature_length);
    static int Verify(void *user_context, const void *key_id, const uint8_t *input, size_t input_length, const uint8_t *signature, size_t signature_length);
    static int Extract(void *user_context, const void *key_id, const uint8_t *salt, size_t salt_len, uint8_t *pseudo_random_key, size_t pseudo_random_key_size, size_t *pseudo_random_key_length);
    static int Expand(void *user_context, const void *key_id, const uint8_t *info, size_t info_length, uint8_t *output_keying_material, size_t output_keying_material_length);
    static int Encrypt(void *user_context, const void *key_id, const uint8_t *nonce, size_t nonce_length, const uint8_t *additional_data, size_t additional_data_length, const uint8_t *plaintext, size_t plaintext_length, uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length);
    static int Decrypt(void *user_context, const void *key_id, const uint8_t *nonce, size_t nonce_length, const uint8_t *additional_data, size_t additional_data_length, const uint8_t *ciphertext, size_t ciphertext_length, uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length);
    static int Hash(void *user_context, const uint8_t *input, size_t input_length, uint8_t *hash, size_t hash_size, size_t *hash_length);

    // Instance methods to invoke the JavaScript callbacks for cryptographic operations via the N-API ThreadSafeFunction mechanism.
    int callGenerateKey(const void *user_context, enum edhoc_key_type key_type, const uint8_t *raw_key, size_t raw_key_length, void *key_id);
    int callDestroyKey(const void *user_context, void *key_id);
    int callMakeKeyPair(const void *user_context, const void *key_id, uint8_t *private_key, size_t private_key_size, size_t *private_key_length, uint8_t *public_key, size_t public_key_size, size_t *public_key_length);
    int callKeyAgreement(const void *user_context, const void *key_id, const uint8_t *peer_public_key, size_t peer_public_key_length, uint8_t *shared_secret, size_t shared_secret_size, size_t *shared_secret_length);
    int callSign(const void *user_context, const void *key_id, const uint8_t *input, size_t input_length, uint8_t *signature, size_t signature_size, size_t *signature_length);
    int callVerify(const void *user_context, const void *key_id, const uint8_t *input, size_t input_length, const uint8_t *signature, size_t signature_length);
    int callExtract(const void *user_context, const void *key_id, const uint8_t *salt, size_t salt_len, uint8_t *pseudo_random_key, size_t pseudo_random_key_size, size_t *pseudo_random_key_length);
    int callExpand(const void *user_context, const void *key_id, const uint8_t *info, size_t info_length, uint8_t *output_keying_material, size_t output_keying_material_length);
    int callEncrypt(const void *user_context, const void *key_id, const uint8_t *nonce, size_t nonce_length, const uint8_t *additional_data, size_t additional_data_length, const uint8_t *plaintext, size_t plaintext_length, uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length);
    int callDecrypt(const void *user_context, const void *key_id, const uint8_t *nonce, size_t nonce_length, const uint8_t *additional_data, size_t additional_data_length, const uint8_t *ciphertext, size_t ciphertext_length, uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length);
    int callHash(const void *user_context, const uint8_t *input, size_t input_length, uint8_t *hash, size_t hash_size, size_t *hash_length);
    
private:

    Napi::FunctionReference generateKeyFuncRef, destroyKeyFuncRef, makeKeyPairFuncRef, keyAgreementFuncRef, signFuncRef, verifyFuncRef, extractFuncRef, expandFuncRef, encryptFuncRef, decryptFuncRef, hashFuncRef;
    Napi::ThreadSafeFunction generateTsfn, destroyTsfn, makeKeyPairTsfn, keyAgreementTsfn, signTsfn, verifyTsfn, extractTsfn, expandTsfn, encryptTsfn, decryptTsfn, hashTsfn;

};

#endif // EDHOC_CRYPTO_MANAGER_H
