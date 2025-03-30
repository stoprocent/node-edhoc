#ifndef EDHOC_CRYPTO_MANAGER_H
#define EDHOC_CRYPTO_MANAGER_H

#include <napi.h>

extern "C" {
#include "edhoc.h"
}

class RunningContext;

/**
 * @class EdhocCryptoManager
 * @brief Manages cryptographic operations for EDHOC protocol.
 *
 * The EdhocCryptoManager class provides methods to perform cryptographic
 * operations required for the EDHOC protocol. It includes static callback
 * functions for generating keys, key pairs, key agreement, signing, verifying,
 * extracting, expanding, encrypting, decrypting, and hashing data.
 */
class EdhocCryptoManager {
 public:
  friend class EdhocCryptoManagerWrapper;

  /**
   * @struct edhoc_crypto
   * @brief Edhoc's bind structure for cryptographics operations.
   */
  struct edhoc_crypto crypto;

  /**
   * @struct edhoc_keys
   * @brief Edhoc's bind structure for cryptographic key identifiers.
   */
  struct edhoc_keys keys;

  /**
   * @brief Constructs an EdhocCryptoManager object.
   */
  EdhocCryptoManager(Napi::Object& jsCryptoManager, Napi::Object& jsEdhoc);

  /**
   * @brief Destroys the EdhocCryptoManager object.
   */
  ~EdhocCryptoManager();

  /**
   * @brief Import a key.
   *
   * @param user_context The user context.
   * @param key_type The type of the key to import.
   * @param raw_key The raw key data.
   * @param raw_key_length The length of the raw key data.
   * @param key_id The imported key ID.
   * @return int The result code.
   */
  static int ImportKey(void* user_context,
                       enum edhoc_key_type key_type,
                       const uint8_t* raw_key,
                       size_t raw_key_length,
                       void* key_id);

  /**
   * @brief Destroy a key.
   *
   * @param user_context The user context.
   * @param key_id The key ID to destroy.
   * @return int The result code.
   */
  static int DestroyKey(void* user_context, void* key_id);

  /**
   * @brief Make a key pair.
   *
   * @param user_context The user context.
   * @param key_id The key ID.
   * @param private_key The buffer to store the private key.
   * @param private_key_size The size of the private key buffer.
   * @param private_key_length The length of the generated private key.
   * @param public_key The buffer to store the public key.
   * @param public_key_size The size of the public key buffer.
   * @param public_key_length The length of the generated public key.
   * @return int The result code.
   */
  static int MakeKeyPair(void* user_context,
                         const void* key_id,
                         uint8_t* private_key,
                         size_t private_key_size,
                         size_t* private_key_length,
                         uint8_t* public_key,
                         size_t public_key_size,
                         size_t* public_key_length);

  /**
   * @brief Perform key agreement.
   *
   * @param user_context The user context.
   * @param key_id The key ID.
   * @param peer_public_key The peer's public key.
   * @param peer_public_key_length The length of the peer's public key.
   * @param shared_secret The buffer to store the shared secret.
   * @param shared_secret_size The size of the shared secret buffer.
   * @param shared_secret_length The length of the generated shared secret.
   * @return int The result code.
   */
  static int KeyAgreement(void* user_context,
                          const void* key_id,
                          const uint8_t* peer_public_key,
                          size_t peer_public_key_length,
                          uint8_t* shared_secret,
                          size_t shared_secret_size,
                          size_t* shared_secret_length);

  /**
   * @brief Sign data.
   *
   * @param user_context The user context.
   * @param key_id The key ID.
   * @param input The input data to sign.
   * @param input_length The length of the input data.
   * @param signature The buffer to store the signature.
   * @param signature_size The size of the signature buffer.
   * @param signature_length The length of the generated signature.
   * @return int The result code.
   */
  static int Sign(void* user_context,
                  const void* key_id,
                  const uint8_t* input,
                  size_t input_length,
                  uint8_t* signature,
                  size_t signature_size,
                  size_t* signature_length);

  /**
   * @brief Verify a signature.
   *
   * @param user_context The user context.
   * @param key_id The key ID.
   * @param input The input data.
   * @param input_length The length of the input data.
   * @param signature The signature to verify.
   * @param signature_length The length of the signature.
   * @return int The result code.
   */
  static int Verify(void* user_context,
                    const void* key_id,
                    const uint8_t* input,
                    size_t input_length,
                    const uint8_t* signature,
                    size_t signature_length);

  /**
   * @brief Extract a pseudo-random key.
   *
   * @param user_context The user context.
   * @param key_id The key ID.
   * @param salt The salt data.
   * @param salt_len The length of the salt data.
   * @param pseudo_random_key The buffer to store the pseudo-random key.
   * @param pseudo_random_key_size The size of the pseudo-random key buffer.
   * @param pseudo_random_key_length The length of the generated pseudo-random
   * key.
   * @return int The result code.
   */
  static int Extract(void* user_context,
                     const void* key_id,
                     const uint8_t* salt,
                     size_t salt_len,
                     uint8_t* pseudo_random_key,
                     size_t pseudo_random_key_size,
                     size_t* pseudo_random_key_length);

  /**
   * @brief Expand a key.
   *
   * @param user_context The user context.
   * @param key_id The key ID.
   * @param info The info data.
   * @param info_length The length of the info data.
   * @param output_keying_material The buffer to store the output keying
   * material.
   * @param output_keying_material_length The length of the generated output
   * keying material.
   * @return int The result code.
   */
  static int Expand(void* user_context,
                    const void* key_id,
                    const uint8_t* info,
                    size_t info_length,
                    uint8_t* output_keying_material,
                    size_t output_keying_material_length);

  /**
   * @brief Encrypt data.
   *
   * @param user_context The user context.
   * @param key_id The key ID.
   * @param nonce The nonce data.
   * @param nonce_length The length of the nonce data.
   * @param additional_data The additional data.
   * @param additional_data_length The length of the additional data.
   * @param plaintext The plaintext data to encrypt.
   * @param plaintext_length The length of the plaintext data.
   * @param ciphertext The buffer to store the ciphertext.
   * @param ciphertext_size The size of the ciphertext buffer.
   * @param ciphertext_length The length of the generated ciphertext.
   * @return int The result code.
   */
  static int Encrypt(void* user_context,
                     const void* key_id,
                     const uint8_t* nonce,
                     size_t nonce_length,
                     const uint8_t* additional_data,
                     size_t additional_data_length,
                     const uint8_t* plaintext,
                     size_t plaintext_length,
                     uint8_t* ciphertext,
                     size_t ciphertext_size,
                     size_t* ciphertext_length);

  /**
   * @brief Decrypt data.
   *
   * @param user_context The user context.
   * @param key_id The key ID.
   * @param nonce The nonce data.
   * @param nonce_length The length of the nonce data.
   * @param additional_data The additional data.
   * @param additional_data_length The length of the additional data.
   * @param ciphertext The ciphertext to decrypt.
   * @param ciphertext_length The length of the ciphertext.
   * @param plaintext The buffer to store the plaintext.
   * @param plaintext_size The size of the plaintext buffer.
   * @param plaintext_length The length of the generated plaintext.
   * @return int The result code.
   */
  static int Decrypt(void* user_context,
                     const void* key_id,
                     const uint8_t* nonce,
                     size_t nonce_length,
                     const uint8_t* additional_data,
                     size_t additional_data_length,
                     const uint8_t* ciphertext,
                     size_t ciphertext_length,
                     uint8_t* plaintext,
                     size_t plaintext_size,
                     size_t* plaintext_length);

  /**
   * @brief Hash data.
   *
   * @param user_context The user context.
   * @param input The input data to hash.
   * @param input_length The length of the input data.
   * @param hash The buffer to store the hash.
   * @param hash_size The size of the hash buffer.
   * @param hash_length The length of the generated hash.
   * @return int The result code.
   */
  static int Hash(void* user_context,
                  const uint8_t* input,
                  size_t input_length,
                  uint8_t* hash,
                  size_t hash_size,
                  size_t* hash_length);

  /**
   * @brief Calls the ImportKey function.
   *
   * @param runningContext The running context.
   * @param key_type The type of the key to import.
   * @param raw_key The raw key data.
   * @param raw_key_length The length of the raw key data.
   * @param key_id The imported key ID.
   * @return int The result code.
   */
  int callImportKey(const RunningContext* runningContext,
                    enum edhoc_key_type key_type,
                    const uint8_t* raw_key,
                    size_t raw_key_length,
                    void* key_id);

  /**
   * @brief Calls the DestroyKey function.
   *
   * @param user_context The user context.
   * @param key_id The key ID to destroy.
   * @return int The result code.
   */
  int callDestroyKey(const RunningContext* runningContext, void* key_id);

  /**
   * @brief Calls the MakeKeyPair function.
   *
   * @param runningContext The running context.
   * @param key_id The key ID.
   * @param private_key The buffer to store the private key.
   * @param private_key_size The size of the private key buffer.
   * @param private_key_length The length of the generated private key.
   * @param public_key The buffer to store the public key.
   * @param public_key_size The size of the public key buffer.
   * @param public_key_length The length of the generated public key.
   * @return int The result code.
   */
  int callMakeKeyPair(const RunningContext* runningContext,
                      const void* key_id,
                      uint8_t* private_key,
                      size_t private_key_size,
                      size_t* private_key_length,
                      uint8_t* public_key,
                      size_t public_key_size,
                      size_t* public_key_length);

  /**
   * @brief Calls the KeyAgreement function.
   *
   * @param runningContext The running context.
   * @param key_id The key ID.
   * @param peer_public_key The peer's public key.
   * @param peer_public_key_length The length of the peer's public key.
   * @param shared_secret The buffer to store the shared secret.
   * @param shared_secret_size The size of the shared secret buffer.
   * @param shared_secret_length The length of the generated shared secret.
   * @return int The result code.
   */
  int callKeyAgreement(const RunningContext* runningContext,
                       const void* key_id,
                       const uint8_t* peer_public_key,
                       size_t peer_public_key_length,
                       uint8_t* shared_secret,
                       size_t shared_secret_size,
                       size_t* shared_secret_length);

  /**
   * @brief Calls the Sign function.
   *
   * @param runningContext The running context.
   * @param key_id The key ID.
   * @param input The input data to sign.
   * @param input_length The length of the input data.
   * @param signature The buffer to store the signature.
   * @param signature_size The size of the signature buffer.
   * @param signature_length The length of the generated signature.
   * @return int The result code.
   */
  int callSign(const RunningContext* runningContext,
               const void* key_id,
               const uint8_t* input,
               size_t input_length,
               uint8_t* signature,
               size_t signature_size,
               size_t* signature_length);

  /**
   * @brief Calls the Verify function.
   *
   * @param runningContext The running context.
   * @param key_id The key ID.
   * @param input The input data.
   * @param input_length The length of the input data.
   * @param signature The signature to verify.
   * @param signature_length The length of the signature.
   * @return int The result code.
   */
  int callVerify(const RunningContext* runningContext,
                 const void* key_id,
                 const uint8_t* input,
                 size_t input_length,
                 const uint8_t* signature,
                 size_t signature_length);

  /**
   * @brief Calls the Extract function.
   *
   * @param runningContext The running context.
   * @param key_id The key ID.
   * @param salt The salt data.
   * @param salt_len The length of the salt data.
   * @param pseudo_random_key The buffer to store the pseudo-random key.
   * @param pseudo_random_key_size The size of the pseudo-random key buffer.
   * @param pseudo_random_key_length The length of the generated pseudo-random
   * key.
   * @return int The result code.
   */
  int callExtract(const RunningContext* runningContext,
                  const void* key_id,
                  const uint8_t* salt,
                  size_t salt_len,
                  uint8_t* pseudo_random_key,
                  size_t pseudo_random_key_size,
                  size_t* pseudo_random_key_length);

  /**
   * @brief Calls the Expand function.
   *
   * @param runningContext The running context.
   * @param key_id The key ID.
   * @param info The info data.
   * @param info_length The length of the info data.
   * @param output_keying_material The buffer to store the output keying
   * material.
   * @param output_keying_material_length The length of the generated output
   * keying material.
   * @return int The result code.
   */
  int callExpand(const RunningContext* runningContext,
                 const void* key_id,
                 const uint8_t* info,
                 size_t info_length,
                 uint8_t* output_keying_material,
                 size_t output_keying_material_length);

  /**
   * @brief Calls the Encrypt function.
   *
   * @param runningContext The running context.
   * @param key_id The key ID.
   * @param nonce The nonce data.
   * @param nonce_length The length of the nonce data.
   * @param additional_data The additional data.
   * @param additional_data_length The length of the additional data.
   * @param plaintext The plaintext data to encrypt.
   * @param plaintext_length The length of the plaintext data.
   * @param ciphertext The buffer to store the ciphertext.
   * @param ciphertext_size The size of the ciphertext buffer.
   * @param ciphertext_length The length of the generated ciphertext.
   * @return int The result code.
   */
  int callEncrypt(const RunningContext* runningContext,
                  const void* key_id,
                  const uint8_t* nonce,
                  size_t nonce_length,
                  const uint8_t* additional_data,
                  size_t additional_data_length,
                  const uint8_t* plaintext,
                  size_t plaintext_length,
                  uint8_t* ciphertext,
                  size_t ciphertext_size,
                  size_t* ciphertext_length);

  /**
   * @brief Calls the Decrypt function.
   *
   * @param runningContext The running context.
   * @param key_id The key ID.
   * @param nonce The nonce data.
   * @param nonce_length The length of the nonce data.
   * @param additional_data The additional data.
   * @param additional_data_length The length of the additional data.
   * @param ciphertext The ciphertext to decrypt.
   * @param ciphertext_length The length of the ciphertext.
   * @param plaintext The buffer to store the plaintext.
   * @param plaintext_size The size of the plaintext buffer.
   * @param plaintext_length The length of the generated plaintext.
   * @return int The result code.
   */
  int callDecrypt(const RunningContext* runningContext,
                  const void* key_id,
                  const uint8_t* nonce,
                  size_t nonce_length,
                  const uint8_t* additional_data,
                  size_t additional_data_length,
                  const uint8_t* ciphertext,
                  size_t ciphertext_length,
                  uint8_t* plaintext,
                  size_t plaintext_size,
                  size_t* plaintext_length);

  /**
   * @brief Calls the Hash function.
   *
   * @param runningContext The running context.
   * @param input The input data to hash.
   * @param input_length The length of the input data.
   * @param hash The buffer to store the hash.
   * @param hash_size The size of the hash buffer.
   * @param hash_length The length of the generated hash.
   * @return int The result code.
   */
  int callHash(const RunningContext* runningContext,
               const uint8_t* input,
               size_t input_length,
               uint8_t* hash,
               size_t hash_size,
               size_t* hash_length);

 private:
  Napi::ObjectReference cryptoManagerRef;  ///< Reference to the JS object
  Napi::ObjectReference edhocRef;

  std::vector<Napi::Reference<Napi::Buffer<uint8_t>>> bufferReferences;  ///< References to the JS buffers

};

#endif  // EDHOC_CRYPTO_MANAGER_H
