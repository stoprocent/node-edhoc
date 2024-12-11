#include "EdhocCryptoManager.h"

#include <exception>
#include <future>
#include <iostream>
#include <stdexcept>
#include <thread>

#include "UserContext.h"
#include "Utils.h"

static constexpr const char* kErrorInvalidUint8ArrayLength = "Returned Uint8Array length exceeds buffer length.";
static constexpr const char* kErrorEncodedUint32Length = "Encoded uint32 exceeds buffer length.";
static constexpr const char* kErrorExpectUint8ArrayOrNumber = "Function must return a Uint8Array or a Number.";
static constexpr const char* kErrorExpectBoolean = "Expected boolean return value from destroyKey function";
static constexpr const char* kErrorPublicKeyLengthExceeds = "Returned public key length exceeds buffer length.";
static constexpr const char* kErrorExpectBuffer = "Expected the result to be a Buffer";
static constexpr const char* kErrorExpectBooleanVerify = "Expected boolean value as a result from verify function";
static constexpr const char* kErrorSecretLengthExceeds = "Returned shared secret length exceeds buffer length.";
static constexpr const char* kErrorSignatureLengthExceeds = "Returned signature length exceeds buffer length.";
static constexpr const char* kErrorBufferTooSmall = "Returned ciphertext length exceeds buffer length.";
static constexpr const char* kErrorPlaintextLengthExceeds = "Returned plaintext length exceeds buffer length.";
static constexpr const char* kErrorHashLengthExceeds = "Returned hash length exceeds buffer length.";
static constexpr const char* kErrorPseudoRandpmLengthExceeds =
    "Returned pseudo random key length exceeds buffer length.";
static constexpr const char* kErrorKeyingMaterialLengthExceeds =
    "Returned output keying material length exceeds buffer length.";
static constexpr const char* kErrorResultObjectExpected = "Expected result to be an object.";
static constexpr const char* kErrorKeysExpectedAsBuffers = "Expected keys to be buffers.";
static constexpr const char* kErrorPrivateKeyLengthExceeds = "Private key length exceeds buffer size.";
static constexpr const char* kErrorObjectExpected = "Object expected";
static constexpr const char* kErrorFunctionExpected = "Function expected";
static constexpr const char* kImportKey = "importKey";
static constexpr const char* kDestroyKey = "destroyKey";
static constexpr const char* kMakeKeyPair = "makeKeyPair";
static constexpr const char* kKeyAgreement = "keyAgreement";
static constexpr const char* kSign = "sign";
static constexpr const char* kVerify = "verify";
static constexpr const char* kExtract = "extract";
static constexpr const char* kExpand = "expand";
static constexpr const char* kEncrypt = "encrypt";
static constexpr const char* kDecrypt = "decrypt";
static constexpr const char* kHash = "hash";

EdhocCryptoManager::EdhocCryptoManager(Napi::Object& jsCryptoManager) {
  if (!jsCryptoManager.IsObject()) {
    Napi::Error::New(jsCryptoManager.Env(), kErrorObjectExpected).ThrowAsJavaScriptException();
  }
  cryptoManagerRef = Napi::Persistent(jsCryptoManager);

  keys.import_key = &EdhocCryptoManager::ImportKey;
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
  cryptoManagerRef.Reset();
  for (auto& ref : bufferReferences) {
    ref.Reset();
  }
  bufferReferences.clear();
}

void EdhocCryptoManager::SetupAsyncFunctions() {
  SetFunction(kImportKey, importTsfn);
  SetFunction(kDestroyKey, destroyTsfn);
  SetFunction(kMakeKeyPair, makeKeyPairTsfn);
  SetFunction(kKeyAgreement, keyAgreementTsfn);
  SetFunction(kSign, signTsfn);
  SetFunction(kVerify, verifyTsfn);
  SetFunction(kExtract, extractTsfn);
  SetFunction(kExpand, expandTsfn);
  SetFunction(kEncrypt, encryptTsfn);
  SetFunction(kDecrypt, decryptTsfn);
  SetFunction(kHash, hashTsfn);
}

void EdhocCryptoManager::CleanupAsyncFunctions() {
  importTsfn.Release();
  destroyTsfn.Release();
  makeKeyPairTsfn.Release();
  keyAgreementTsfn.Release();
  signTsfn.Release();
  verifyTsfn.Release();
  extractTsfn.Release();
  expandTsfn.Release();
  encryptTsfn.Release();
  decryptTsfn.Release();
  hashTsfn.Release();
}

void EdhocCryptoManager::SetFunction(const char* name, Napi::ThreadSafeFunction& tsfn) {
  Napi::Env env = cryptoManagerRef.Env();
  Napi::HandleScope scope(env);
  Napi::Function jsFunction = cryptoManagerRef.Value().Get(name).As<Napi::Function>();
  if (!jsFunction.IsFunction()) {
    Napi::Error::New(env, kErrorFunctionExpected).ThrowAsJavaScriptException();
  }
  tsfn = Napi::ThreadSafeFunction::New(env, jsFunction, name, 0, 1);
}

int EdhocCryptoManager::ImportKey(void* user_context,
                                  enum edhoc_key_type key_type,
                                  const uint8_t* raw_key,
                                  size_t raw_key_length,
                                  void* key_id) {
  UserContext* userContext = static_cast<UserContext*>(user_context);
  EdhocCryptoManager* cryptoManager = userContext->GetCryptoManager();
  return cryptoManager->callImportKey(user_context, key_type, raw_key, raw_key_length, key_id);
}

int EdhocCryptoManager::DestroyKey(void* user_context, void* key_id) {
  UserContext* userContext = static_cast<UserContext*>(user_context);
  EdhocCryptoManager* cryptoManager = userContext->GetCryptoManager();
  return cryptoManager->callDestroyKey(user_context, key_id);
}

int EdhocCryptoManager::MakeKeyPair(void* user_context,
                                    const void* key_id,
                                    uint8_t* private_key,
                                    size_t private_key_size,
                                    size_t* private_key_length,
                                    uint8_t* public_key,
                                    size_t public_key_size,
                                    size_t* public_key_length) {
  UserContext* userContext = static_cast<UserContext*>(user_context);
  EdhocCryptoManager* cryptoManager = userContext->GetCryptoManager();
  return cryptoManager->callMakeKeyPair(user_context, key_id, private_key, private_key_size, private_key_length,
                                        public_key, public_key_size, public_key_length);
}

int EdhocCryptoManager::KeyAgreement(void* user_context,
                                     const void* key_id,
                                     const uint8_t* peer_public_key,
                                     size_t peer_public_key_length,
                                     uint8_t* shared_secret,
                                     size_t shared_secret_size,
                                     size_t* shared_secret_length) {
  UserContext* userContext = static_cast<UserContext*>(user_context);
  EdhocCryptoManager* cryptoManager = userContext->GetCryptoManager();
  return cryptoManager->callKeyAgreement(user_context, key_id, peer_public_key, peer_public_key_length, shared_secret,
                                         shared_secret_size, shared_secret_length);
}

int EdhocCryptoManager::Sign(void* user_context,
                             const void* key_id,
                             const uint8_t* input,
                             size_t input_length,
                             uint8_t* signature,
                             size_t signature_size,
                             size_t* signature_length) {
  UserContext* userContext = static_cast<UserContext*>(user_context);
  EdhocCryptoManager* cryptoManager = userContext->GetCryptoManager();
  return cryptoManager->callSign(user_context, key_id, input, input_length, signature, signature_size,
                                 signature_length);
}

int EdhocCryptoManager::Verify(void* user_context,
                               const void* key_id,
                               const uint8_t* input,
                               size_t input_length,
                               const uint8_t* signature,
                               size_t signature_length) {
  UserContext* userContext = static_cast<UserContext*>(user_context);
  EdhocCryptoManager* cryptoManager = userContext->GetCryptoManager();
  return cryptoManager->callVerify(user_context, key_id, input, input_length, signature, signature_length);
}

int EdhocCryptoManager::Extract(void* user_context,
                                const void* key_id,
                                const uint8_t* salt,
                                size_t salt_len,
                                uint8_t* pseudo_random_key,
                                size_t pseudo_random_key_size,
                                size_t* pseudo_random_key_length) {
  UserContext* userContext = static_cast<UserContext*>(user_context);
  EdhocCryptoManager* cryptoManager = userContext->GetCryptoManager();
  return cryptoManager->callExtract(user_context, key_id, salt, salt_len, pseudo_random_key, pseudo_random_key_size,
                                    pseudo_random_key_length);
}

int EdhocCryptoManager::Expand(void* user_context,
                               const void* key_id,
                               const uint8_t* info,
                               size_t info_length,
                               uint8_t* output_keying_material,
                               size_t output_keying_material_length) {
  UserContext* userContext = static_cast<UserContext*>(user_context);
  EdhocCryptoManager* cryptoManager = userContext->GetCryptoManager();
  return cryptoManager->callExpand(user_context, key_id, info, info_length, output_keying_material,
                                   output_keying_material_length);
}

int EdhocCryptoManager::Encrypt(void* user_context,
                                const void* key_id,
                                const uint8_t* nonce,
                                size_t nonce_length,
                                const uint8_t* additional_data,
                                size_t additional_data_length,
                                const uint8_t* plaintext,
                                size_t plaintext_length,
                                uint8_t* ciphertext,
                                size_t ciphertext_size,
                                size_t* ciphertext_length) {
  UserContext* userContext = static_cast<UserContext*>(user_context);
  EdhocCryptoManager* cryptoManager = userContext->GetCryptoManager();
  return cryptoManager->callEncrypt(user_context, key_id, nonce, nonce_length, additional_data, additional_data_length,
                                    plaintext, plaintext_length, ciphertext, ciphertext_size, ciphertext_length);
}

int EdhocCryptoManager::Decrypt(void* user_context,
                                const void* key_id,
                                const uint8_t* nonce,
                                size_t nonce_length,
                                const uint8_t* additional_data,
                                size_t additional_data_length,
                                const uint8_t* ciphertext,
                                size_t ciphertext_length,
                                uint8_t* plaintext,
                                size_t plaintext_size,
                                size_t* plaintext_length) {
  UserContext* userContext = static_cast<UserContext*>(user_context);
  EdhocCryptoManager* cryptoManager = userContext->GetCryptoManager();
  return cryptoManager->callDecrypt(user_context, key_id, nonce, nonce_length, additional_data, additional_data_length,
                                    ciphertext, ciphertext_length, plaintext, plaintext_size, plaintext_length);
}

int EdhocCryptoManager::Hash(void* user_context,
                             const uint8_t* input,
                             size_t input_length,
                             uint8_t* hash,
                             size_t hash_size,
                             size_t* hash_length) {
  UserContext* userContext = static_cast<UserContext*>(user_context);
  EdhocCryptoManager* cryptoManager = userContext->GetCryptoManager();
  return cryptoManager->callHash(user_context, input, input_length, hash, hash_size, hash_length);
}

int EdhocCryptoManager::callImportKey(const void* user_context,
                                      enum edhoc_key_type key_type,
                                      const uint8_t* raw_key,
                                      size_t raw_key_length,
                                      void* key_id_ptr) {
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  auto successHandler = [&promise, &key_id_ptr](Napi::Env env, Napi::Value result) {
    Napi::HandleScope scope(env);
    uint8_t* key_id = static_cast<uint8_t*>(key_id_ptr);

    if (result.IsTypedArray()) {
      Napi::Uint8Array resultArray = result.As<Napi::Uint8Array>();
      if (resultArray.ElementLength() > CONFIG_LIBEDHOC_KEY_ID_LEN) {
        throw std::runtime_error(kErrorInvalidUint8ArrayLength);
      }
      memcpy(key_id, resultArray.Data(), resultArray.ElementLength());
      promise.set_value(EDHOC_SUCCESS);
    } else if (result.IsNumber()) {
      uint32_t num = result.As<Napi::Number>().Int64Value();
      uint8_t tempBuffer[CONFIG_LIBEDHOC_KEY_ID_LEN];
      size_t encodedLength = 0;
      Utils::EncodeInt64ToBuffer(num, tempBuffer, &encodedLength);

      if (encodedLength > CONFIG_LIBEDHOC_KEY_ID_LEN) {
        throw std::runtime_error(kErrorEncodedUint32Length);
      }

      memcpy(key_id, tempBuffer, encodedLength);
      memset(key_id + encodedLength, 0, CONFIG_LIBEDHOC_KEY_ID_LEN - encodedLength);
      promise.set_value(EDHOC_SUCCESS);
    } else {
      throw std::runtime_error(kErrorExpectUint8ArrayOrNumber);
    }
  };

  auto blockingCallHandler = [this, &user_context, &promise, key_type, &raw_key, raw_key_length, successHandler](
                                 Napi::Env env, Napi::Function jsCallback) {
    Napi::HandleScope scope(env);

    std::vector<napi_value> args = {static_cast<const UserContext*>(user_context)->parent.Value(),
                                    Napi::Number::New(env, static_cast<int>(key_type)),
                                    Napi::Buffer<uint8_t>::New(env, const_cast<uint8_t*>(raw_key), raw_key_length)};
    auto errorHandler = Utils::CreatePromiseErrorHandler<int>(promise, EDHOC_ERROR_GENERIC_ERROR);
    Utils::InvokeJSFunctionWithPromiseHandling(env, cryptoManagerRef.Value(), jsCallback, args, successHandler,
                                               errorHandler);
  };

  importTsfn.BlockingCall(blockingCallHandler);

  future.wait();
  return future.get();
}

int EdhocCryptoManager::callDestroyKey(const void* user_context, void* key_id) {
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  // Timeout thread to ensure the callback is called
  std::shared_ptr<bool> callbackCompleted = std::make_shared<bool>(false);
  std::thread timeoutThread([callbackCompleted, &promise]() {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    if (!*callbackCompleted) {
      promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
    }
  });
  timeoutThread.detach();

  auto successHandler = [&promise](Napi::Env env, Napi::Value result) {
    Napi::HandleScope scope(env);
    if (!result.IsBoolean()) {
      throw std::runtime_error(kErrorExpectBoolean);
    }
    promise.set_value(result.As<Napi::Boolean>().Value() ? EDHOC_SUCCESS : EDHOC_ERROR_GENERIC_ERROR);
  };

  auto blockingCallHandler = [this, &user_context, &promise, &key_id, callbackCompleted, successHandler](
                                 Napi::Env env, Napi::Function jsCallback) {
    *callbackCompleted = true;
    Napi::HandleScope scope(env);
    std::vector<napi_value> args = {
        static_cast<const UserContext*>(user_context)->parent.Value(),
        Napi::Buffer<uint8_t>::Copy(env, static_cast<uint8_t*>(key_id), CONFIG_LIBEDHOC_KEY_ID_LEN)};
    auto errorHandler = Utils::CreatePromiseErrorHandler<int>(promise, EDHOC_ERROR_GENERIC_ERROR);
    Utils::InvokeJSFunctionWithPromiseHandling(env, cryptoManagerRef.Value(), jsCallback, args, successHandler,
                                               errorHandler);
  };

  destroyTsfn.BlockingCall(blockingCallHandler);

  future.wait();
  return future.get();
}

int EdhocCryptoManager::callMakeKeyPair(const void* user_context,
                                        const void* key_id,
                                        uint8_t* private_key,
                                        size_t private_key_size,
                                        size_t* private_key_length,
                                        uint8_t* public_key,
                                        size_t public_key_size,
                                        size_t* public_key_length) {
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  auto successHandler = [&promise, &private_key, private_key_size, &private_key_length, &public_key, public_key_size,
                         &public_key_length](Napi::Env env, Napi::Value result) {
    Napi::HandleScope scope(env);
    if (!result.IsObject()) {
      throw std::runtime_error(kErrorResultObjectExpected);
    }

    Napi::Object resultObject = result.As<Napi::Object>();
    Napi::Value privateKeyValue = resultObject.Get("privateKey");
    Napi::Value publicKeyValue = resultObject.Get("publicKey");

    if (!privateKeyValue.IsBuffer() || !publicKeyValue.IsBuffer()) {
      throw std::runtime_error(kErrorKeysExpectedAsBuffers);
    }

    Napi::Buffer<uint8_t> privateKeyBuffer = privateKeyValue.As<Napi::Buffer<uint8_t>>();
    Napi::Buffer<uint8_t> publicKeyBuffer = publicKeyValue.As<Napi::Buffer<uint8_t>>();

    if (privateKeyBuffer.Length() > private_key_size) {
      throw std::runtime_error(kErrorPrivateKeyLengthExceeds);
    }

    if (publicKeyBuffer.Length() > public_key_size) {
      throw std::runtime_error(kErrorPublicKeyLengthExceeds);
    }

    memcpy(private_key, privateKeyBuffer.Data(), privateKeyBuffer.Length());
    *private_key_length = privateKeyBuffer.Length();
    memcpy(public_key, publicKeyBuffer.Data(), publicKeyBuffer.Length());
    *public_key_length = publicKeyBuffer.Length();

    promise.set_value(EDHOC_SUCCESS);
  };

  auto blockingCallHandler = [this, &user_context, &promise, &key_id, private_key_size, public_key_size,
                              successHandler](Napi::Env env, Napi::Function jsCallback) {
    Napi::HandleScope scope(env);
    std::vector<napi_value> args = {
        static_cast<const UserContext*>(user_context)->parent.Value(),
        Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t*>(key_id), CONFIG_LIBEDHOC_KEY_ID_LEN),
        Napi::Number::New(env, static_cast<size_t>(private_key_size)),
        Napi::Number::New(env, static_cast<size_t>(public_key_size))};
    auto errorHandler = Utils::CreatePromiseErrorHandler<int>(promise, EDHOC_ERROR_GENERIC_ERROR);
    Utils::InvokeJSFunctionWithPromiseHandling(env, cryptoManagerRef.Value(), jsCallback, args, successHandler,
                                               errorHandler);
  };

  makeKeyPairTsfn.BlockingCall(blockingCallHandler);

  future.wait();
  return future.get();
}

int EdhocCryptoManager::callKeyAgreement(const void* user_context,
                                         const void* key_id,
                                         const uint8_t* peer_public_key,
                                         size_t peer_public_key_length,
                                         uint8_t* shared_secret,
                                         size_t shared_secret_size,
                                         size_t* shared_secret_length) {
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  auto successHandler = [&promise, &shared_secret, shared_secret_size, &shared_secret_length](Napi::Env env,
                                                                                              Napi::Value result) {
    Napi::HandleScope scope(env);
    if (!result.IsBuffer()) {
      throw std::runtime_error(kErrorExpectBuffer);
    }
    Napi::Buffer<uint8_t> sharedSecretBuffer = result.As<Napi::Buffer<uint8_t>>();
    if (sharedSecretBuffer.Length() > shared_secret_size) {
      throw std::runtime_error(kErrorSecretLengthExceeds);
    }
    memcpy(shared_secret, sharedSecretBuffer.Data(), sharedSecretBuffer.Length());
    *shared_secret_length = sharedSecretBuffer.Length();

    promise.set_value(EDHOC_SUCCESS);
  };

  auto blockingCallHandler = [this, &user_context, &promise, &key_id, &peer_public_key, peer_public_key_length,
                              shared_secret_size, successHandler](Napi::Env env, Napi::Function jsCallback) {
    Napi::HandleScope scope(env);
    std::vector<napi_value> args = {
        static_cast<const UserContext*>(user_context)->parent.Value(),
        Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t*>(key_id), CONFIG_LIBEDHOC_KEY_ID_LEN),
        Napi::Buffer<uint8_t>::Copy(env, peer_public_key, peer_public_key_length),
        Napi::Number::New(env, static_cast<size_t>(shared_secret_size)),
    };
    auto errorHandler = Utils::CreatePromiseErrorHandler<int>(promise, EDHOC_ERROR_GENERIC_ERROR);
    Utils::InvokeJSFunctionWithPromiseHandling(env, cryptoManagerRef.Value(), jsCallback, args, successHandler,
                                               errorHandler);
  };

  keyAgreementTsfn.BlockingCall(blockingCallHandler);

  future.wait();
  return future.get();
}

int EdhocCryptoManager::callSign(const void* user_context,
                                 const void* key_id,
                                 const uint8_t* input,
                                 size_t input_length,
                                 uint8_t* signature,
                                 size_t signature_size,
                                 size_t* signature_length) {
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  const uint8_t* kid = static_cast<const uint8_t*>(key_id);

  auto successHandler = [&promise, &signature, signature_size, &signature_length](Napi::Env env, Napi::Value result) {
    Napi::HandleScope scope(env);
    if (!result.IsBuffer()) {
      throw std::runtime_error(kErrorExpectBuffer);
    }
    Napi::Buffer<uint8_t> signatureBuffer = result.As<Napi::Buffer<uint8_t>>();
    if (signatureBuffer.Length() > signature_size) {
      throw std::runtime_error(kErrorSignatureLengthExceeds);
    }
    memcpy(signature, signatureBuffer.Data(), signatureBuffer.Length());
    *signature_length = signatureBuffer.Length();

    promise.set_value(EDHOC_SUCCESS);
  };

  auto blockingCallHandler = [this, &user_context, &promise, kid, &input, input_length, signature_size, successHandler](
                                 Napi::Env env, Napi::Function jsCallback) {
    Napi::HandleScope scope(env);
    std::vector<napi_value> args = {
        static_cast<const UserContext*>(user_context)->parent.Value(),
        Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t*>(kid), CONFIG_LIBEDHOC_KEY_ID_LEN),
        Napi::Buffer<uint8_t>::Copy(env, input, input_length),
        Napi::Number::New(env, static_cast<size_t>(signature_size))};
    auto errorHandler = Utils::CreatePromiseErrorHandler<int>(promise, EDHOC_ERROR_GENERIC_ERROR);
    Utils::InvokeJSFunctionWithPromiseHandling(env, cryptoManagerRef.Value(), jsCallback, args, successHandler,
                                               errorHandler);
  };

  signTsfn.BlockingCall(blockingCallHandler);

  future.wait();
  return future.get();
}

int EdhocCryptoManager::callVerify(const void* user_context,
                                   const void* key_id,
                                   const uint8_t* input,
                                   size_t input_length,
                                   const uint8_t* signature,
                                   size_t signature_length) {
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  auto successHandler = [&promise](Napi::Env env, Napi::Value result) {
    Napi::HandleScope scope(env);
    if (!result.IsBoolean()) {
      throw std::runtime_error(kErrorExpectBooleanVerify);
    }
    promise.set_value(result.As<Napi::Boolean>().Value() ? EDHOC_SUCCESS : EDHOC_ERROR_CRYPTO_FAILURE);
  };

  auto blockingCallHandler = [this, &user_context, &promise, &key_id, &input, input_length, &signature,
                              signature_length, successHandler](Napi::Env env, Napi::Function jsCallback) {
    Napi::HandleScope scope(env);
    std::vector<napi_value> args = {
        static_cast<const UserContext*>(user_context)->parent.Value(),
        Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t*>(key_id), CONFIG_LIBEDHOC_KEY_ID_LEN),
        Napi::Buffer<uint8_t>::Copy(env, input, input_length),
        Napi::Buffer<uint8_t>::Copy(env, signature, signature_length),
    };
    auto errorHandler = Utils::CreatePromiseErrorHandler<int>(promise, EDHOC_ERROR_GENERIC_ERROR);
    Utils::InvokeJSFunctionWithPromiseHandling(env, cryptoManagerRef.Value(), jsCallback, args, successHandler,
                                               errorHandler);
  };

  verifyTsfn.BlockingCall(blockingCallHandler);

  future.wait();
  return future.get();
}

int EdhocCryptoManager::callExtract(const void* user_context,
                                    const void* key_id,
                                    const uint8_t* salt,
                                    size_t salt_len,
                                    uint8_t* pseudo_random_key,
                                    size_t pseudo_random_key_size,
                                    size_t* pseudo_random_key_length) {
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  auto successHandler = [&promise, &pseudo_random_key, pseudo_random_key_size, &pseudo_random_key_length](
                            Napi::Env env, Napi::Value result) {
    Napi::HandleScope scope(env);
    if (!result.IsBuffer()) {
      throw std::runtime_error(kErrorExpectBuffer);
    }
    Napi::Buffer<uint8_t> randomKeyBuffer = result.As<Napi::Buffer<uint8_t>>();
    if (randomKeyBuffer.Length() > pseudo_random_key_size) {
      throw std::runtime_error(kErrorPseudoRandpmLengthExceeds);
    }
    memcpy(pseudo_random_key, randomKeyBuffer.Data(), randomKeyBuffer.Length());
    *pseudo_random_key_length = randomKeyBuffer.Length();

    promise.set_value(EDHOC_SUCCESS);
  };

  auto blockingCallHandler = [this, &user_context, &promise, &key_id, &salt, salt_len, pseudo_random_key_size,
                              successHandler](Napi::Env env, Napi::Function jsCallback) {
    Napi::HandleScope scope(env);
    std::vector<napi_value> args = {
        static_cast<const UserContext*>(user_context)->parent.Value(),
        Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t*>(key_id), CONFIG_LIBEDHOC_KEY_ID_LEN),
        Napi::Buffer<uint8_t>::Copy(env, salt, salt_len),
        Napi::Number::New(env, static_cast<size_t>(pseudo_random_key_size))};
    auto errorHandler = Utils::CreatePromiseErrorHandler<int>(promise, EDHOC_ERROR_GENERIC_ERROR);
    Utils::InvokeJSFunctionWithPromiseHandling(env, cryptoManagerRef.Value(), jsCallback, args, successHandler,
                                               errorHandler);
  };

  extractTsfn.BlockingCall(blockingCallHandler);

  future.wait();
  return future.get();
}

int EdhocCryptoManager::callExpand(const void* user_context,
                                   const void* key_id,
                                   const uint8_t* info,
                                   size_t info_length,
                                   uint8_t* output_keying_material,
                                   size_t output_keying_material_length) {
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  auto successHandler = [&promise, &output_keying_material, output_keying_material_length](Napi::Env env,
                                                                                           Napi::Value result) {
    Napi::HandleScope scope(env);
    if (!result.IsBuffer()) {
      throw std::runtime_error(kErrorExpectBuffer);
    }
    Napi::Buffer<uint8_t> outputBuffer = result.As<Napi::Buffer<uint8_t>>();
    if (outputBuffer.Length() > output_keying_material_length) {
      throw std::runtime_error(kErrorKeyingMaterialLengthExceeds);
    }
    memcpy(output_keying_material, outputBuffer.Data(), outputBuffer.Length());

    promise.set_value(EDHOC_SUCCESS);
  };

  auto blockingCallHandler = [this, &user_context, &promise, &key_id, &info, info_length, output_keying_material_length,
                              successHandler](Napi::Env env, Napi::Function jsCallback) {
    Napi::HandleScope scope(env);
    std::vector<napi_value> args = {
        static_cast<const UserContext*>(user_context)->parent.Value(),
        Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t*>(key_id), CONFIG_LIBEDHOC_KEY_ID_LEN),
        Napi::Buffer<uint8_t>::Copy(env, info, info_length),
        Napi::Number::New(env, static_cast<size_t>(output_keying_material_length))};
    auto errorHandler = Utils::CreatePromiseErrorHandler<int>(promise, EDHOC_ERROR_GENERIC_ERROR);
    Utils::InvokeJSFunctionWithPromiseHandling(env, cryptoManagerRef.Value(), jsCallback, args, successHandler,
                                               errorHandler);
  };

  expandTsfn.BlockingCall(blockingCallHandler);

  future.wait();
  return future.get();
}

int EdhocCryptoManager::callEncrypt(const void* user_context,
                                    const void* key_id,
                                    const uint8_t* nonce,
                                    size_t nonce_length,
                                    const uint8_t* additional_data,
                                    size_t additional_data_length,
                                    const uint8_t* plaintext,
                                    size_t plaintext_length,
                                    uint8_t* ciphertext,
                                    size_t ciphertext_size,
                                    size_t* ciphertext_length) {
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  auto successHandler = [&promise, &ciphertext, ciphertext_size, &ciphertext_length](Napi::Env env,
                                                                                     Napi::Value result) {
    Napi::HandleScope scope(env);
    if (!result.IsBuffer()) {
      throw std::runtime_error(kErrorExpectBuffer);
    }
    Napi::Buffer<uint8_t> ciphertextBuffer = result.As<Napi::Buffer<uint8_t>>();
    if (ciphertextBuffer.Length() > ciphertext_size) {
      throw std::runtime_error(kErrorBufferTooSmall);
    }
    memcpy(ciphertext, ciphertextBuffer.Data(), ciphertextBuffer.Length());
    *ciphertext_length = ciphertextBuffer.Length();

    promise.set_value(EDHOC_SUCCESS);
  };

  auto blockingCallHandler = [this, &user_context, &promise, &key_id, &nonce, nonce_length, &additional_data,
                              additional_data_length, &plaintext, plaintext_length, ciphertext_size,
                              successHandler](Napi::Env env, Napi::Function jsCallback) {
    Napi::HandleScope scope(env);
    std::vector<napi_value> args = {
        static_cast<const UserContext*>(user_context)->parent.Value(),
        Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t*>(key_id), CONFIG_LIBEDHOC_KEY_ID_LEN),
        Napi::Buffer<uint8_t>::Copy(env, nonce, nonce_length),
        Napi::Buffer<uint8_t>::Copy(env, additional_data, additional_data_length),
        Napi::Buffer<uint8_t>::Copy(env, plaintext, plaintext_length),
        Napi::Number::New(env, static_cast<size_t>(ciphertext_size))};
    auto errorHandler = Utils::CreatePromiseErrorHandler<int>(promise, EDHOC_ERROR_GENERIC_ERROR);
    Utils::InvokeJSFunctionWithPromiseHandling(env, cryptoManagerRef.Value(), jsCallback, args, successHandler,
                                               errorHandler);
  };

  encryptTsfn.BlockingCall(blockingCallHandler);

  future.wait();
  return future.get();
}

int EdhocCryptoManager::callDecrypt(const void* user_context,
                                    const void* key_id,
                                    const uint8_t* nonce,
                                    size_t nonce_length,
                                    const uint8_t* additional_data,
                                    size_t additional_data_length,
                                    const uint8_t* ciphertext,
                                    size_t ciphertext_length,
                                    uint8_t* plaintext,
                                    size_t plaintext_size,
                                    size_t* plaintext_length) {
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  auto successHandler = [&promise, &plaintext, plaintext_size, plaintext_length](Napi::Env env, Napi::Value result) {
    Napi::HandleScope scope(env);
    if (!result.IsBuffer()) {
      throw std::runtime_error(kErrorExpectBuffer);
    }
    Napi::Buffer<uint8_t> plaintextBuffer = result.As<Napi::Buffer<uint8_t>>();
    if (plaintextBuffer.Length() > plaintext_size) {
      throw std::runtime_error(kErrorPlaintextLengthExceeds);
    }
    memcpy(plaintext, plaintextBuffer.Data(), plaintextBuffer.Length());
    *plaintext_length = plaintextBuffer.Length();

    promise.set_value(EDHOC_SUCCESS);
  };

  auto blockingCallHandler = [this, &user_context, &promise, &key_id, &nonce, nonce_length, &additional_data,
                              additional_data_length, &ciphertext, &ciphertext_length, plaintext_size,
                              successHandler](Napi::Env env, Napi::Function jsCallback) {
    Napi::HandleScope scope(env);
    std::vector<napi_value> arguments = {
        static_cast<const UserContext*>(user_context)->parent.Value(),
        Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t*>(key_id), CONFIG_LIBEDHOC_KEY_ID_LEN),
        Napi::Buffer<uint8_t>::Copy(env, nonce, nonce_length),
        Napi::Buffer<uint8_t>::Copy(env, additional_data, additional_data_length),
        Napi::Buffer<uint8_t>::Copy(env, ciphertext, ciphertext_length),
        Napi::Number::New(env, static_cast<size_t>(plaintext_size))};
    auto errorHandler = Utils::CreatePromiseErrorHandler<int>(promise, EDHOC_ERROR_GENERIC_ERROR);
    Utils::InvokeJSFunctionWithPromiseHandling(env, cryptoManagerRef.Value(), jsCallback, arguments, successHandler,
                                               errorHandler);
  };

  decryptTsfn.BlockingCall(blockingCallHandler);

  future.wait();
  return future.get();
}

int EdhocCryptoManager::callHash(const void* user_context,
                                 const uint8_t* input,
                                 size_t input_length,
                                 uint8_t* hash,
                                 size_t hash_size,
                                 size_t* hash_length) {
  std::promise<int> promise;
  std::future<int> future = promise.get_future();

  auto successHandler = [&promise, &hash, hash_size, &hash_length](Napi::Env env, Napi::Value result) {
    Napi::HandleScope scope(env);
    if (!result.IsBuffer()) {
      throw std::runtime_error(kErrorExpectBuffer);
    }
    Napi::Buffer<uint8_t> hashBuffer = result.As<Napi::Buffer<uint8_t>>();
    if (hashBuffer.Length() > hash_size) {
      throw std::runtime_error(kErrorHashLengthExceeds);
    }
    memcpy(hash, hashBuffer.Data(), hashBuffer.Length());
    *hash_length = hashBuffer.Length();

    promise.set_value(EDHOC_SUCCESS);
  };

  auto blockingCallHandler = [this, &user_context, &promise, &input, input_length, hash_size, successHandler](
                                 Napi::Env env, Napi::Function jsCallback) {
    Napi::HandleScope scope(env);
    std::vector<napi_value> arguments = {
        static_cast<const UserContext*>(user_context)->parent.Value(),
        Napi::Buffer<uint8_t>::Copy(env, input, input_length),
        Napi::Number::New(env, static_cast<size_t>(hash_size)),
    };
    auto errorHandler = Utils::CreatePromiseErrorHandler<int>(promise, EDHOC_ERROR_GENERIC_ERROR);
    Utils::InvokeJSFunctionWithPromiseHandling(env, cryptoManagerRef.Value(), jsCallback, arguments, successHandler,
                                               errorHandler);
  };

  hashTsfn.BlockingCall(blockingCallHandler);

  future.wait();
  return future.get();
}
