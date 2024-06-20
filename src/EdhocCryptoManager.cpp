#include <exception>
#include <future>
#include <iostream>
#include <stdexcept>

#include "EdhocCryptoManager.h"
#include "UserContext.h"
#include "Utils.h"

static constexpr const char *kErrorInvalidUint8ArrayLength =
    "Returned Uint8Array length exceeds buffer length.";
static constexpr const char *kErrorEncodedUint32Length =
    "Encoded uint32 exceeds buffer length.";
static constexpr const char *kErrorExpectUint8ArrayOrNumber =
    "Function must return a Uint8Array or a Number.";
static constexpr const char *kErrorExpectBoolean =
    "Expected boolean return value from destroyKey function";
static constexpr const char *kErrorExpectArray = "Expected an array";
static constexpr const char *kErrorArrayTooShort =
    "Array must contain at least two elements";
static constexpr const char *kErrorFirstElementBuffer =
    "First element must be a Buffer";
static constexpr const char *kErrorKeyLengthExceeds =
    "Returned private key length exceeds buffer length.";
static constexpr const char *kErrorPublicKeyBuffer =
    "Second element must be a Buffer";
static constexpr const char *kErrorPublicKeyLengthExceeds =
    "Returned public key length exceeds buffer length.";
static constexpr const char *kErrorExpectBuffer =
    "Expected the result to be a Buffer";
static constexpr const char *kErrorExpectBooleanVerify =
    "Expected boolean value as a result from verify function";
static constexpr const char *kErrorSecretLengthExceeds =
    "Returned shared secret length exceeds buffer length.";
static constexpr const char *kErrorSignatureLengthExceeds =
    "Returned signature length exceeds buffer length.";
static constexpr const char *kErrorBufferTooSmall =
    "Returned ciphertext length exceeds buffer length.";
static constexpr const char *kErrorPlaintextLengthExceeds =
    "Returned plaintext length exceeds buffer length.";
static constexpr const char *kErrorHashLengthExceeds =
    "Returned hash length exceeds buffer length.";
static constexpr const char *kErrorPseudoRandpmLengthExceeds =
    "Returned pseudo random key length exceeds buffer length.";
static constexpr const char *kErrorKeyingMaterialLengthExceeds =
    "Returned output keying material length exceeds buffer length.";

EdhocCryptoManager::EdhocCryptoManager() {
  keys.generate_key = &EdhocCryptoManager::GenerateKey;
  keys.destroy_key = &EdhocCryptoManager::DestroyKey;
  crypto.make_key_pair = &EdhocCryptoManager::MakeKeyPair;
  crypto.key_agreement = &EdhocCryptoManager::KeyAgreement;
  crypto.signature = &EdhocCryptoManager::Sign;
  crypto.verify = &EdhocCryptoManager::Verify;
  crypto.extract = &EdhocCryptoManager::Extract;
  crypto.expand = &EdhocCryptoManager::Expand;
  crypto.encrypt = &EdhocCryptoManager::Encrypt;
  crypto.decrypt = &EdhocCryptoManager::Decrypt;
  crypto.hash = &EdhocCryptoManager::Hash;
}

EdhocCryptoManager::~EdhocCryptoManager() {
  Utils::ResetAndRelease(generateKeyFuncRef, generateTsfn);
  Utils::ResetAndRelease(destroyKeyFuncRef, destroyTsfn);
  Utils::ResetAndRelease(makeKeyPairFuncRef, makeKeyPairTsfn);
  Utils::ResetAndRelease(keyAgreementFuncRef, keyAgreementTsfn);
  Utils::ResetAndRelease(signFuncRef, signTsfn);
  Utils::ResetAndRelease(verifyFuncRef, verifyTsfn);
  Utils::ResetAndRelease(extractFuncRef, extractTsfn);
  Utils::ResetAndRelease(expandFuncRef, expandTsfn);
  Utils::ResetAndRelease(encryptFuncRef, encryptTsfn);
  Utils::ResetAndRelease(decryptFuncRef, decryptTsfn);
  Utils::ResetAndRelease(hashFuncRef, hashTsfn);
}

int EdhocCryptoManager::GenerateKey(void *user_context,
                                    enum edhoc_key_type key_type,
                                    const uint8_t *raw_key,
                                    size_t raw_key_length, void *key_id) {
  UserContext *userContext = static_cast<UserContext *>(user_context);
  EdhocCryptoManager *cryptoManager = userContext->GetCryptoManager();
  return cryptoManager->callGenerateKey(user_context, key_type, raw_key,
                                        raw_key_length, key_id);
}

int EdhocCryptoManager::DestroyKey(void *user_context, void *key_id) {
  UserContext *userContext = static_cast<UserContext *>(user_context);
  EdhocCryptoManager *cryptoManager = userContext->GetCryptoManager();
  return cryptoManager->callDestroyKey(user_context, key_id);
}

int EdhocCryptoManager::MakeKeyPair(void *user_context, const void *key_id,
                                    uint8_t *private_key,
                                    size_t private_key_size,
                                    size_t *private_key_length,
                                    uint8_t *public_key, size_t public_key_size,
                                    size_t *public_key_length) {
  UserContext *userContext = static_cast<UserContext *>(user_context);
  EdhocCryptoManager *cryptoManager = userContext->GetCryptoManager();
  return cryptoManager->callMakeKeyPair(
      user_context, key_id, private_key, private_key_size, private_key_length,
      public_key, public_key_size, public_key_length);
}

int EdhocCryptoManager::KeyAgreement(void *user_context, const void *key_id,
                                     const uint8_t *peer_public_key,
                                     size_t peer_public_key_length,
                                     uint8_t *shared_secret,
                                     size_t shared_secret_size,
                                     size_t *shared_secret_length) {
  UserContext *userContext = static_cast<UserContext *>(user_context);
  EdhocCryptoManager *cryptoManager = userContext->GetCryptoManager();
  return cryptoManager->callKeyAgreement(
      user_context, key_id, peer_public_key, peer_public_key_length,
      shared_secret, shared_secret_size, shared_secret_length);
}

int EdhocCryptoManager::Sign(void *user_context, const void *key_id,
                             const uint8_t *input, size_t input_length,
                             uint8_t *signature, size_t signature_size,
                             size_t *signature_length) {
  UserContext *userContext = static_cast<UserContext *>(user_context);
  EdhocCryptoManager *cryptoManager = userContext->GetCryptoManager();
  return cryptoManager->callSign(user_context, key_id, input, input_length,
                                 signature, signature_size, signature_length);
}

int EdhocCryptoManager::Verify(void *user_context, const void *key_id,
                               const uint8_t *input, size_t input_length,
                               const uint8_t *signature,
                               size_t signature_length) {
  UserContext *userContext = static_cast<UserContext *>(user_context);
  EdhocCryptoManager *cryptoManager = userContext->GetCryptoManager();
  return cryptoManager->callVerify(user_context, key_id, input, input_length,
                                   signature, signature_length);
}

int EdhocCryptoManager::Extract(void *user_context, const void *key_id,
                                const uint8_t *salt, size_t salt_len,
                                uint8_t *pseudo_random_key,
                                size_t pseudo_random_key_size,
                                size_t *pseudo_random_key_length) {
  UserContext *userContext = static_cast<UserContext *>(user_context);
  EdhocCryptoManager *cryptoManager = userContext->GetCryptoManager();
  return cryptoManager->callExtract(user_context, key_id, salt, salt_len,
                                    pseudo_random_key, pseudo_random_key_size,
                                    pseudo_random_key_length);
}

int EdhocCryptoManager::Expand(void *user_context, const void *key_id,
                               const uint8_t *info, size_t info_length,
                               uint8_t *output_keying_material,
                               size_t output_keying_material_length) {
  UserContext *userContext = static_cast<UserContext *>(user_context);
  EdhocCryptoManager *cryptoManager = userContext->GetCryptoManager();
  return cryptoManager->callExpand(user_context, key_id, info, info_length,
                                   output_keying_material,
                                   output_keying_material_length);
}

int EdhocCryptoManager::Encrypt(void *user_context, const void *key_id,
                                const uint8_t *nonce, size_t nonce_length,
                                const uint8_t *additional_data,
                                size_t additional_data_length,
                                const uint8_t *plaintext,
                                size_t plaintext_length, uint8_t *ciphertext,
                                size_t ciphertext_size,
                                size_t *ciphertext_length) {
  UserContext *userContext = static_cast<UserContext *>(user_context);
  EdhocCryptoManager *cryptoManager = userContext->GetCryptoManager();
  return cryptoManager->callEncrypt(user_context, key_id, nonce, nonce_length,
                                    additional_data, additional_data_length,
                                    plaintext, plaintext_length, ciphertext,
                                    ciphertext_size, ciphertext_length);
}

int EdhocCryptoManager::Decrypt(void *user_context, const void *key_id,
                                const uint8_t *nonce, size_t nonce_length,
                                const uint8_t *additional_data,
                                size_t additional_data_length,
                                const uint8_t *ciphertext,
                                size_t ciphertext_length, uint8_t *plaintext,
                                size_t plaintext_size,
                                size_t *plaintext_length) {
  UserContext *userContext = static_cast<UserContext *>(user_context);
  EdhocCryptoManager *cryptoManager = userContext->GetCryptoManager();
  return cryptoManager->callDecrypt(user_context, key_id, nonce, nonce_length,
                                    additional_data, additional_data_length,
                                    ciphertext, ciphertext_length, plaintext,
                                    plaintext_size, plaintext_length);
}

int EdhocCryptoManager::Hash(void *user_context, const uint8_t *input,
                             size_t input_length, uint8_t *hash,
                             size_t hash_size, size_t *hash_length) {
  UserContext *userContext = static_cast<UserContext *>(user_context);
  EdhocCryptoManager *cryptoManager = userContext->GetCryptoManager();
  return cryptoManager->callHash(user_context, input, input_length, hash,
                                 hash_size, hash_length);
}

int EdhocCryptoManager::callGenerateKey(const void *user_context,
                                        enum edhoc_key_type key_type,
                                        const uint8_t *raw_key,
                                        size_t raw_key_length,
                                        void *key_id_ptr) {
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  generateTsfn.BlockingCall([&user_context, &promise, key_type, &raw_key,
                             raw_key_length, &key_id_ptr](
                                Napi::Env env, Napi::Function jsCallback) {
    std::vector<napi_value> arguments = {
        static_cast<const UserContext *>(user_context)->parent.Value(),
        Napi::Number::New(env, static_cast<int>(key_type)),
        Napi::Buffer<uint8_t>::New(env, const_cast<uint8_t *>(raw_key),
                                   raw_key_length)};
    Utils::InvokeJSFunctionWithPromiseHandling(
        env, jsCallback, arguments,
        [&promise, &key_id_ptr](Napi::Env env, Napi::Value result) {
          uint8_t *key_id = static_cast<uint8_t *>(key_id_ptr);
          if (result.IsTypedArray()) {
            Napi::Uint8Array resultArray = result.As<Napi::Uint8Array>();
            if (resultArray.ElementLength() > EDHOC_KID_LEN) {
              promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
              throw Napi::TypeError::New(env, kErrorInvalidUint8ArrayLength);
            }
            memcpy(key_id, resultArray.Data(), resultArray.ElementLength());
            promise.set_value(EDHOC_SUCCESS);
          } else if (result.IsNumber()) {
            uint32_t num = result.As<Napi::Number>().Int64Value();
            uint8_t tempBuffer[EDHOC_KID_LEN];
            size_t encodedLength = 0;
            Utils::EncodeInt64ToBuffer(num, tempBuffer, &encodedLength);

            if (encodedLength > EDHOC_KID_LEN) {
              promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
              throw Napi::TypeError::New(env, kErrorEncodedUint32Length);
            }
            memcpy(key_id, tempBuffer, encodedLength);
            memset(key_id + encodedLength, 0, EDHOC_KID_LEN - encodedLength);
            promise.set_value(EDHOC_SUCCESS);
          } else {
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
            throw Napi::TypeError::New(env, kErrorExpectUint8ArrayOrNumber);
          }
        });
  });

  future.wait();
  return future.get();
}

int EdhocCryptoManager::callDestroyKey(const void *user_context, void *key_id) {
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  destroyTsfn.BlockingCall([&user_context, &promise,
                            &key_id](Napi::Env env, Napi::Function jsCallback) {
    std::vector<napi_value> arguments = {
        static_cast<const UserContext *>(user_context)->parent.Value(),
        Napi::Buffer<uint8_t>::Copy(env, static_cast<uint8_t *>(key_id),
                                    EDHOC_KID_LEN)};
    Utils::InvokeJSFunctionWithPromiseHandling(
        env, jsCallback, arguments,
        [&promise](Napi::Env env, Napi::Value result) {
          if (!result.IsBoolean()) {
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
            throw Napi::TypeError::New(env, kErrorExpectBoolean);
          }
          promise.set_value(result.As<Napi::Boolean>().Value()
                                ? EDHOC_SUCCESS
                                : EDHOC_ERROR_GENERIC_ERROR);
        });
  });

  future.wait();
  return future.get();
}

int EdhocCryptoManager::callMakeKeyPair(
    const void *user_context, const void *key_id, uint8_t *private_key,
    size_t private_key_size, size_t *private_key_length, uint8_t *public_key,
    size_t public_key_size, size_t *public_key_length) {
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  makeKeyPairTsfn.BlockingCall([&user_context, &promise, &key_id, &private_key,
                                private_key_size, &private_key_length,
                                &public_key, public_key_size,
                                &public_key_length](Napi::Env env,
                                                    Napi::Function jsCallback) {
    std::vector<napi_value> arguments = {
        static_cast<const UserContext *>(user_context)->parent.Value(),
        Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t *>(key_id),
                                    EDHOC_KID_LEN),
        Napi::Number::New(env, static_cast<size_t>(private_key_size)),
        Napi::Number::New(env, static_cast<size_t>(public_key_size))};
    Utils::InvokeJSFunctionWithPromiseHandling(
        env, jsCallback, arguments,
        [&promise, &private_key, private_key_size, &private_key_length,
         &public_key, public_key_size,
         &public_key_length](Napi::Env env, Napi::Value result) {
          if (!result.IsArray()) {
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
            throw Napi::TypeError::New(env, kErrorExpectArray);
          }

          Napi::Array resultArray = result.As<Napi::Array>();

          if (resultArray.Length() < 2) {
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
            throw Napi::TypeError::New(env, kErrorArrayTooShort);
          }

          Napi::Value privateKeyValue = resultArray.Get((uint32_t)0);
          if (!privateKeyValue.IsBuffer()) {
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
            throw Napi::TypeError::New(env, kErrorFirstElementBuffer);
          }

          Napi::Buffer<uint8_t> privateKeyBuffer =
              privateKeyValue.As<Napi::Buffer<uint8_t>>();

          if (privateKeyBuffer.Length() > private_key_size) {
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
            throw Napi::TypeError::New(env, kErrorKeyLengthExceeds);
          }

          memcpy(private_key, privateKeyBuffer.Data(),
                 privateKeyBuffer.Length());
          *private_key_length = privateKeyBuffer.Length();

          Napi::Value publicKeyValue = resultArray.Get((uint32_t)1);
          if (!publicKeyValue.IsBuffer()) {
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
            throw Napi::TypeError::New(env, kErrorPublicKeyBuffer);
          }

          Napi::Buffer<uint8_t> publicKeyBuffer =
              publicKeyValue.As<Napi::Buffer<uint8_t>>();

          if (publicKeyBuffer.Length() > public_key_size) {
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
            throw Napi::TypeError::New(env, kErrorPublicKeyLengthExceeds);
          }

          memcpy(public_key, publicKeyBuffer.Data(), publicKeyBuffer.Length());
          *public_key_length = publicKeyBuffer.Length();

          promise.set_value(EDHOC_SUCCESS);
        });
  });

  future.wait();
  return future.get();
}

int EdhocCryptoManager::callKeyAgreement(const void *user_context,
                                         const void *key_id,
                                         const uint8_t *peer_public_key,
                                         size_t peer_public_key_length,
                                         uint8_t *shared_secret,
                                         size_t shared_secret_size,
                                         size_t *shared_secret_length) {
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  keyAgreementTsfn.BlockingCall(
      [&user_context, &promise, &key_id, &peer_public_key,
       peer_public_key_length, &shared_secret, shared_secret_size,
       &shared_secret_length](Napi::Env env, Napi::Function jsCallback) {
        std::vector<napi_value> arguments = {
            static_cast<const UserContext *>(user_context)->parent.Value(),
            Napi::Buffer<uint8_t>::Copy(
                env, static_cast<const uint8_t *>(key_id), EDHOC_KID_LEN),
            Napi::Buffer<uint8_t>::Copy(env, peer_public_key,
                                        peer_public_key_length),
            Napi::Number::New(env, static_cast<size_t>(shared_secret_size)),
        };

        Utils::InvokeJSFunctionWithPromiseHandling(
            env, jsCallback, arguments,
            [&promise, &shared_secret, shared_secret_size,
             &shared_secret_length](Napi::Env env, Napi::Value result) {
              if (!result.IsBuffer()) {
                promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
                throw Napi::TypeError::New(env, kErrorExpectBuffer);
              }

              Napi::Buffer<uint8_t> sharedSecretBuffer =
                  result.As<Napi::Buffer<uint8_t>>();

              if (sharedSecretBuffer.Length() > shared_secret_size) {
                promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
                throw Napi::TypeError::New(env, kErrorSecretLengthExceeds);
              }

              memcpy(shared_secret, sharedSecretBuffer.Data(),
                     sharedSecretBuffer.Length());
              *shared_secret_length = sharedSecretBuffer.Length();

              promise.set_value(EDHOC_SUCCESS);
            });
      });

  future.wait();
  return future.get();
}

int EdhocCryptoManager::callSign(const void *user_context, const void *key_id,
                                 const uint8_t *input, size_t input_length,
                                 uint8_t *signature, size_t signature_size,
                                 size_t *signature_length) {
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  const uint8_t *kid = static_cast<const uint8_t *>(key_id);

  signTsfn.BlockingCall([&user_context, &promise, kid, &input, input_length,
                         &signature, signature_size, &signature_length](
                            Napi::Env env, Napi::Function jsCallback) {
    std::vector<napi_value> arguments = {
        static_cast<const UserContext *>(user_context)->parent.Value(),
        Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t *>(kid),
                                    EDHOC_KID_LEN),
        Napi::Buffer<uint8_t>::Copy(env, input, input_length),
        Napi::Number::New(env, static_cast<size_t>(signature_size))};
    Utils::InvokeJSFunctionWithPromiseHandling(
        env, jsCallback, arguments,
        [&promise, &signature, signature_size,
         &signature_length](Napi::Env env, Napi::Value result) {
          if (!result.IsBuffer()) {
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
            throw Napi::TypeError::New(env, kErrorExpectBuffer);
          }

          Napi::Buffer<uint8_t> signatureBuffer =
              result.As<Napi::Buffer<uint8_t>>();

          if (signatureBuffer.Length() > signature_size) {
            promise.set_value(EDHOC_ERROR_BUFFER_TOO_SMALL);
            throw Napi::TypeError::New(env, kErrorSignatureLengthExceeds);
          }

          memcpy(signature, signatureBuffer.Data(), signatureBuffer.Length());
          *signature_length = signatureBuffer.Length();

          promise.set_value(EDHOC_SUCCESS);
        });
  });

  future.wait();
  return future.get();
}

int EdhocCryptoManager::callVerify(const void *user_context, const void *key_id,
                                   const uint8_t *input, size_t input_length,
                                   const uint8_t *signature,
                                   size_t signature_length) {
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  verifyTsfn.BlockingCall(
      [&user_context, &promise, &key_id, &input, input_length, &signature,
       signature_length](Napi::Env env, Napi::Function jsCallback) {
        std::vector<napi_value> arguments = {
            static_cast<const UserContext *>(user_context)->parent.Value(),
            Napi::Buffer<uint8_t>::Copy(
                env, static_cast<const uint8_t *>(key_id), EDHOC_KID_LEN),
            Napi::Buffer<uint8_t>::Copy(env, input, input_length),
            Napi::Buffer<uint8_t>::Copy(env, signature, signature_length),
        };
        Utils::InvokeJSFunctionWithPromiseHandling(
            env, jsCallback, arguments,
            [&promise](Napi::Env env, Napi::Value result) {
              if (!result.IsBoolean()) {
                promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
                throw Napi::TypeError::New(env, kErrorExpectBooleanVerify);
              }
              promise.set_value(result.As<Napi::Boolean>().Value()
                                    ? EDHOC_SUCCESS
                                    : EDHOC_ERROR_CRYPTO_FAILURE);
            });
      });

  future.wait();
  return future.get();
}

int EdhocCryptoManager::callExtract(const void *user_context,
                                    const void *key_id, const uint8_t *salt,
                                    size_t salt_len, uint8_t *pseudo_random_key,
                                    size_t pseudo_random_key_size,
                                    size_t *pseudo_random_key_length) {
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  extractTsfn.BlockingCall([&user_context, &promise, &key_id, &salt, salt_len,
                            &pseudo_random_key, pseudo_random_key_size,
                            &pseudo_random_key_length](
                               Napi::Env env, Napi::Function jsCallback) {
    std::vector<napi_value> arguments = {
        static_cast<const UserContext *>(user_context)->parent.Value(),
        Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t *>(key_id),
                                    EDHOC_KID_LEN),
        Napi::Buffer<uint8_t>::Copy(env, salt, salt_len),
        Napi::Number::New(env, static_cast<size_t>(pseudo_random_key_size))};
    Utils::InvokeJSFunctionWithPromiseHandling(
        env, jsCallback, arguments,
        [&promise, &pseudo_random_key, pseudo_random_key_size,
         &pseudo_random_key_length](Napi::Env env, Napi::Value result) {
          if (!result.IsBuffer()) {
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
            throw Napi::TypeError::New(env, kErrorExpectBuffer);
          }

          Napi::Buffer<uint8_t> randomKeyBuffer =
              result.As<Napi::Buffer<uint8_t>>();

          if (randomKeyBuffer.Length() > pseudo_random_key_size) {
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
            throw Napi::TypeError::New(env, kErrorPseudoRandpmLengthExceeds);
          }

          memcpy(pseudo_random_key, randomKeyBuffer.Data(),
                 randomKeyBuffer.Length());
          *pseudo_random_key_length = randomKeyBuffer.Length();

          promise.set_value(EDHOC_SUCCESS);
        });
  });

  future.wait();
  return future.get();
}

int EdhocCryptoManager::callExpand(const void *user_context, const void *key_id,
                                   const uint8_t *info, size_t info_length,
                                   uint8_t *output_keying_material,
                                   size_t output_keying_material_length) {
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  expandTsfn.BlockingCall([&user_context, &promise, &key_id, &info, info_length,
                           &output_keying_material,
                           output_keying_material_length](
                              Napi::Env env, Napi::Function jsCallback) {
    std::vector<napi_value> arguments = {
        static_cast<const UserContext *>(user_context)->parent.Value(),
        Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t *>(key_id),
                                    EDHOC_KID_LEN),
        Napi::Buffer<uint8_t>::Copy(env, info, info_length),
        Napi::Number::New(env,
                          static_cast<size_t>(output_keying_material_length))};
    Utils::InvokeJSFunctionWithPromiseHandling(
        env, jsCallback, arguments,
        [&promise, &output_keying_material,
         output_keying_material_length](Napi::Env env, Napi::Value result) {
          if (!result.IsBuffer()) {
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
            throw Napi::TypeError::New(env, kErrorExpectBuffer);
          }

          Napi::Buffer<uint8_t> outputBuffer =
              result.As<Napi::Buffer<uint8_t>>();
          if (outputBuffer.Length() > output_keying_material_length) {
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
            throw Napi::TypeError::New(env, kErrorKeyingMaterialLengthExceeds);
          }

          memcpy(output_keying_material, outputBuffer.Data(),
                 outputBuffer.Length());

          promise.set_value(EDHOC_SUCCESS);
        });
  });

  future.wait();
  return future.get();
}

int EdhocCryptoManager::callEncrypt(
    const void *user_context, const void *key_id, const uint8_t *nonce,
    size_t nonce_length, const uint8_t *additional_data,
    size_t additional_data_length, const uint8_t *plaintext,
    size_t plaintext_length, uint8_t *ciphertext, size_t ciphertext_size,
    size_t *ciphertext_length) {
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  encryptTsfn.BlockingCall(
      [&user_context, &promise, &key_id, &nonce, nonce_length, &additional_data,
       additional_data_length, &plaintext, plaintext_length, &ciphertext,
       ciphertext_size,
       &ciphertext_length](Napi::Env env, Napi::Function jsCallback) {
        std::vector<napi_value> arguments = {
            static_cast<const UserContext *>(user_context)->parent.Value(),
            Napi::Buffer<uint8_t>::Copy(
                env, static_cast<const uint8_t *>(key_id), EDHOC_KID_LEN),
            Napi::Buffer<uint8_t>::Copy(env, nonce, nonce_length),
            Napi::Buffer<uint8_t>::Copy(env, additional_data,
                                        additional_data_length),
            Napi::Buffer<uint8_t>::Copy(env, plaintext, plaintext_length),
            Napi::Number::New(env, static_cast<size_t>(ciphertext_size))};
        Utils::InvokeJSFunctionWithPromiseHandling(
            env, jsCallback, arguments,
            [&promise, &ciphertext, ciphertext_size,
             &ciphertext_length](Napi::Env env, Napi::Value result) {
              if (!result.IsBuffer()) {
                promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
                throw Napi::TypeError::New(env, kErrorExpectBuffer);
              }

              Napi::Buffer<uint8_t> ciphertextBuffer =
                  result.As<Napi::Buffer<uint8_t>>();
              if (ciphertextBuffer.Length() > ciphertext_size) {
                promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
                throw Napi::TypeError::New(env, kErrorBufferTooSmall);
              }

              memcpy(ciphertext, ciphertextBuffer.Data(),
                     ciphertextBuffer.Length());
              *ciphertext_length = ciphertextBuffer.Length();

              promise.set_value(EDHOC_SUCCESS);
            });
      });

  future.wait();
  return future.get();
}

int EdhocCryptoManager::callDecrypt(
    const void *user_context, const void *key_id, const uint8_t *nonce,
    size_t nonce_length, const uint8_t *additional_data,
    size_t additional_data_length, const uint8_t *ciphertext,
    size_t ciphertext_length, uint8_t *plaintext, size_t plaintext_size,
    size_t *plaintext_length) {
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  decryptTsfn.BlockingCall([&user_context, &promise, &key_id, &nonce,
                            nonce_length, &additional_data,
                            additional_data_length, &ciphertext,
                            &ciphertext_length, &plaintext, plaintext_size,
                            plaintext_length](Napi::Env env,
                                              Napi::Function jsCallback) {
    std::vector<napi_value> arguments = {
        static_cast<const UserContext *>(user_context)->parent.Value(),
        Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t *>(key_id),
                                    EDHOC_KID_LEN),
        Napi::Buffer<uint8_t>::Copy(env, nonce, nonce_length),
        Napi::Buffer<uint8_t>::Copy(env, additional_data,
                                    additional_data_length),
        Napi::Buffer<uint8_t>::Copy(env, ciphertext, ciphertext_length),
        Napi::Number::New(env, static_cast<size_t>(plaintext_size))};
    Utils::InvokeJSFunctionWithPromiseHandling(
        env, jsCallback, arguments,
        [&promise, &plaintext, plaintext_size,
         plaintext_length](Napi::Env env, Napi::Value result) {
          if (!result.IsBuffer()) {
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
            throw Napi::TypeError::New(env, kErrorExpectBuffer);
          }

          Napi::Buffer<uint8_t> plaintextBuffer =
              result.As<Napi::Buffer<uint8_t>>();
          if (plaintextBuffer.Length() > plaintext_size) {
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
            throw Napi::TypeError::New(env, kErrorPlaintextLengthExceeds);
          }

          memcpy(plaintext, plaintextBuffer.Data(), plaintextBuffer.Length());
          *plaintext_length = plaintextBuffer.Length();

          promise.set_value(EDHOC_SUCCESS);
        });
  });

  future.wait();
  return future.get();
}

int EdhocCryptoManager::callHash(const void *user_context, const uint8_t *input,
                                 size_t input_length, uint8_t *hash,
                                 size_t hash_size, size_t *hash_length) {
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  hashTsfn.BlockingCall([&user_context, &promise, &input, input_length, &hash,
                         hash_size, &hash_length](Napi::Env env,
                                                  Napi::Function jsCallback) {
    std::vector<napi_value> arguments = {
        static_cast<const UserContext *>(user_context)->parent.Value(),
        Napi::Buffer<uint8_t>::Copy(env, input, input_length),
        Napi::Number::New(env, static_cast<size_t>(hash_size)),
    };
    Utils::InvokeJSFunctionWithPromiseHandling(
        env, jsCallback, arguments,
        [&promise, &hash, hash_size, &hash_length](Napi::Env env,
                                                   Napi::Value result) {
          if (!result.IsBuffer()) {
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
            throw Napi::TypeError::New(env, kErrorExpectBuffer);
          }
          Napi::Buffer<uint8_t> hashBuffer = result.As<Napi::Buffer<uint8_t>>();

          if (hashBuffer.Length() > hash_size) {
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
            throw Napi::TypeError::New(env, kErrorHashLengthExceeds);
          }

          memcpy(hash, hashBuffer.Data(), hashBuffer.Length());
          *hash_length = hashBuffer.Length();

          promise.set_value(EDHOC_SUCCESS);
        });
  });

  future.wait();
  return future.get();
}
