#include "Suites.h"

// Cipher Suite 0
static const struct edhoc_cipher_suite edhoc_cipher_suite_0 = {
    .value = 0,             // Suite identifier 0
    .aead_key_length = 16,  // Key length for AES-CCM-16-64-128 (16 bytes)
    .aead_tag_length = 8,   // Authentication tag length for AES-CCM (8 bytes)
    .aead_iv_length = 13,   // Initialization vector length for AES-CCM (13 bytes)
    .hash_length = 32,      // Output length for SHA-256 (32 bytes)
    .mac_length = 8,        // MAC length (8 bytes)
    .ecc_key_length = 32,   // Elliptic curve key length for X25519 (32 bytes)
    .ecc_sign_length = 64,  // Signature length for EdDSA using X25519 (64 bytes)
};

// Cipher Suite 1
static const struct edhoc_cipher_suite edhoc_cipher_suite_1 = {
    .value = 1,             // Suite identifier 1
    .aead_key_length = 16,  // Key length for AES-CCM-16-128-128 (16 bytes)
    .aead_tag_length = 16,  // Authentication tag length for AES-CCM (16 bytes)
    .aead_iv_length = 13,   // Initialization vector length for AES-CCM (13 bytes)
    .hash_length = 32,      // Output length for SHA-256 (32 bytes)
    .mac_length = 16,       // MAC length (16 bytes)
    .ecc_key_length = 32,   // Elliptic curve key length for X25519 (32 bytes)
    .ecc_sign_length = 64,  // Signature length for EdDSA using X25519 (64 bytes)
};

// Cipher Suite 2
static const struct edhoc_cipher_suite edhoc_cipher_suite_2 = {
    .value = 2,             // Suite identifier 2
    .aead_key_length = 16,  // Key length for AES-CCM-16-64-128 (16 bytes)
    .aead_tag_length = 8,   // Authentication tag length for AES-CCM (8 bytes)
    .aead_iv_length = 13,   // Initialization vector length for AES-CCM (13 bytes)
    .hash_length = 32,      // Output length for SHA-256 (32 bytes)
    .mac_length = 8,        // MAC length (8 bytes)
    .ecc_key_length = 32,   // Elliptic curve key length for P-256 (32 bytes)
    .ecc_sign_length = 64,  // Signature length for ES256 using P-256 (64 bytes)
};

// Cipher Suite 3
static const struct edhoc_cipher_suite edhoc_cipher_suite_3 = {
    .value = 3,             // Suite identifier 3
    .aead_key_length = 16,  // Key length for AES-CCM-16-128-128 (16 bytes)
    .aead_tag_length = 16,  // Authentication tag length for AES-CCM (16 bytes)
    .aead_iv_length = 13,   // Initialization vector length for AES-CCM (13 bytes)
    .hash_length = 32,      // Output length for SHA-256 (32 bytes)
    .mac_length = 16,       // MAC length (16 bytes)
    .ecc_key_length = 32,   // Elliptic curve key length for P-256 (32 bytes)
    .ecc_sign_length = 64,  // Signature length for ES256 using P-256 (64 bytes)
};

// Cipher Suite 4
static const struct edhoc_cipher_suite edhoc_cipher_suite_4 = {
    .value = 4,             // Suite identifier 4
    .aead_key_length = 32,  // Key length for ChaCha20 (32 bytes)
    .aead_tag_length = 16,  // Authentication tag length for Poly1305 (16 bytes)
    .aead_iv_length = 12,   // Nonce length for ChaCha20 (12 bytes)
    .hash_length = 32,      // Output length for SHA-256 (32 bytes)
    .mac_length = 16,       // MAC length (16 bytes)
    .ecc_key_length = 32,   // Elliptic curve key length for X25519 (32 bytes)
    .ecc_sign_length = 64,  // Signature length for EdDSA using X25519 (64 bytes)
};

// Cipher Suite 5
static const struct edhoc_cipher_suite edhoc_cipher_suite_5 = {
    .value = 5,             // Suite identifier 5
    .aead_key_length = 32,  // Key length for ChaCha20 (32 bytes)
    .aead_tag_length = 16,  // Authentication tag length for Poly1305 (16 bytes)
    .aead_iv_length = 12,   // Nonce length for ChaCha20 (12 bytes)
    .hash_length = 32,      // Output length for SHA-256 (32 bytes)
    .mac_length = 16,       // MAC length (16 bytes)
    .ecc_key_length = 32,   // Elliptic curve key length for P-256 (32 bytes)
    .ecc_sign_length = 64,  // Signature length for ES256 using P-256 (64 bytes)
};

// Cipher Suite 6
static const struct edhoc_cipher_suite edhoc_cipher_suite_6 = {
    .value = 6,             // Suite identifier 6
    .aead_key_length = 16,  // Key length for A128GCM (16 bytes)
    .aead_tag_length = 16,  // Authentication tag length for A128GCM (16 bytes)
    .aead_iv_length = 12,   // Initialization vector length for A128GCM (12 bytes)
    .hash_length = 32,      // Output length for SHA-256 (32 bytes)
    .mac_length = 16,       // MAC length (16 bytes)
    .ecc_key_length = 32,   // Elliptic curve key length for X25519 (32 bytes)
    .ecc_sign_length = 64,  // Signature length for ES256 using X25519 (64 bytes)
};

// Cipher Suite 24
static const struct edhoc_cipher_suite edhoc_cipher_suite_24 = {
    .value = 24,            // Suite identifier 24
    .aead_key_length = 32,  // Key length for A256GCM (32 bytes)
    .aead_tag_length = 16,  // Authentication tag length for A256GCM (16 bytes)
    .aead_iv_length = 12,   // Initialization vector length for A256GCM (12 bytes)
    .hash_length = 48,      // Output length for SHA-384 (48 bytes)
    .mac_length = 16,       // MAC length (16 bytes)
    .ecc_key_length = 48,   // Elliptic curve key length for P-384 (48 bytes)
    .ecc_sign_length = 96,  // Signature length for ES384 using P-384 (96 bytes)
};

// Cipher Suite 25
static const struct edhoc_cipher_suite edhoc_cipher_suite_25 = {
    .value = 25,             // Suite identifier 25
    .aead_key_length = 32,   // Key length for ChaCha20 (32 bytes)
    .aead_tag_length = 16,   // Authentication tag length for Poly1305 (16 bytes)
    .aead_iv_length = 12,    // Nonce length for ChaCha20 (12 bytes)
    .hash_length = 64,       // Output length for SHAKE256 (64 bytes)
    .mac_length = 16,        // MAC length (16 bytes)
    .ecc_key_length = 56,    // Elliptic curve key length for X448 (56 bytes)
    .ecc_sign_length = 114,  // Signature length for EdDSA using X448 (114 bytes)
};

const struct edhoc_cipher_suite* suite_pointers[] = {
    &edhoc_cipher_suite_0, &edhoc_cipher_suite_1, &edhoc_cipher_suite_2, &edhoc_cipher_suite_3, &edhoc_cipher_suite_4,
    &edhoc_cipher_suite_5, &edhoc_cipher_suite_6,
    // 7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr,
    // 24, 25
    &edhoc_cipher_suite_24, &edhoc_cipher_suite_25};

const size_t suite_pointers_count = sizeof(suite_pointers) / sizeof(suite_pointers[0]);
