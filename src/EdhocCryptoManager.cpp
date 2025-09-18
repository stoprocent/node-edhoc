#include "EdhocCryptoManager.h"

#include <exception>
#include <future>
#include <iostream>
#include <stdexcept>
#include <thread>

#include "RunningContext.h"
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

EdhocCryptoManager::EdhocCryptoManager(Napi::Object& jsCryptoManager, Napi::Object& jsEdhoc) {
  if (!jsCryptoManager.IsObject() || !jsEdhoc.IsObject()) {
    Napi::Error::New(jsCryptoManager.Env(), kErrorObjectExpected).ThrowAsJavaScriptException();
  }
  cryptoManagerRef = Napi::Persistent(jsCryptoManager);
  edhocRef = Napi::Weak(jsEdhoc);

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
  edhocRef.Reset();
  for (auto& ref : bufferReferences) {
    ref.Reset();
  }
  bufferReferences.clear();
}

int EdhocCryptoManager::ImportKey(void* user_context,
                                  enum edhoc_key_type key_type,
                                  const uint8_t* raw_key,
                                  size_t raw_key_length,
                                  void* key_id) {
  RunningContext* context = static_cast<RunningContext*>(const_cast<void*>(user_context));
  return context->GetCryptoManager()->callImportKey(context, key_type, raw_key, raw_key_length, key_id);
}

int EdhocCryptoManager::DestroyKey(void* user_context, void* key_id) {
  RunningContext* context = static_cast<RunningContext*>(const_cast<void*>(user_context));
  return context->GetCryptoManager()->callDestroyKey(context, key_id);
}

int EdhocCryptoManager::MakeKeyPair(void* user_context,
                                    const void* key_id,
                                    uint8_t* private_key,
                                    size_t private_key_size,
                                    size_t* private_key_length,
                                    uint8_t* public_key,
                                    size_t public_key_size,
                                    size_t* public_key_length) {
  RunningContext* context = static_cast<RunningContext*>(const_cast<void*>(user_context));
  return context->GetCryptoManager()->callMakeKeyPair(context, key_id, private_key, private_key_size, private_key_length,
                                        public_key, public_key_size, public_key_length);
}

int EdhocCryptoManager::KeyAgreement(void* user_context,
                                     const void* key_id,
                                     const uint8_t* peer_public_key,
                                     size_t peer_public_key_length,
                                     uint8_t* shared_secret,
                                     size_t shared_secret_size,
                                     size_t* shared_secret_length) {
  RunningContext* context = static_cast<RunningContext*>(const_cast<void*>(user_context));
  return context->GetCryptoManager()->callKeyAgreement(context, key_id, peer_public_key, peer_public_key_length, shared_secret,
                                         shared_secret_size, shared_secret_length);
}

int EdhocCryptoManager::Sign(void* user_context,
                             const void* key_id,
                             const uint8_t* input,
                             size_t input_length,
                             uint8_t* signature,
                             size_t signature_size,
                             size_t* signature_length) {
  RunningContext* context = static_cast<RunningContext*>(const_cast<void*>(user_context));
  return context->GetCryptoManager()->callSign(context, key_id, input, input_length, signature, signature_size,
                                 signature_length);
}

int EdhocCryptoManager::Verify(void* user_context,
                               const void* key_id,
                               const uint8_t* input,
                               size_t input_length,
                               const uint8_t* signature,
                               size_t signature_length) {
  RunningContext* context = static_cast<RunningContext*>(const_cast<void*>(user_context));
  return context->GetCryptoManager()->callVerify(context, key_id, input, input_length, signature, signature_length);
}

int EdhocCryptoManager::Extract(void* user_context,
                                const void* key_id,
                                const uint8_t* salt,
                                size_t salt_len,
                                uint8_t* pseudo_random_key,
                                size_t pseudo_random_key_size,
                                size_t* pseudo_random_key_length) {
  RunningContext* context = static_cast<RunningContext*>(const_cast<void*>(user_context));
  return context->GetCryptoManager()->callExtract(context, key_id, salt, salt_len, pseudo_random_key,
                                                pseudo_random_key_size, pseudo_random_key_length);
}

int EdhocCryptoManager::Expand(void* user_context,
                               const void* key_id,
                               const uint8_t* info,
                               size_t info_length,
                               uint8_t* output_keying_material,
                               size_t output_keying_material_length) {
  RunningContext* context = static_cast<RunningContext*>(const_cast<void*>(user_context));
  return context->GetCryptoManager()->callExpand(context, key_id, info, info_length, output_keying_material,
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
  RunningContext* context = static_cast<RunningContext*>(const_cast<void*>(user_context));
  return context->GetCryptoManager()->callEncrypt(context, key_id, nonce, nonce_length, additional_data, additional_data_length,
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
  RunningContext* context = static_cast<RunningContext*>(const_cast<void*>(user_context));
  return context->GetCryptoManager()->callDecrypt(context, key_id, nonce, nonce_length, additional_data, additional_data_length,
                                    ciphertext, ciphertext_length, plaintext, plaintext_size, plaintext_length);
}

int EdhocCryptoManager::Hash(void* user_context,
                             const uint8_t* input,
                             size_t input_length,
                             uint8_t* hash,
                             size_t hash_size,
                             size_t* hash_length) {
  RunningContext* context = static_cast<RunningContext*>(const_cast<void*>(user_context));
  return context->GetCryptoManager()->callHash(context, input, input_length, hash, hash_size, hash_length);
}

int EdhocCryptoManager::callImportKey(RunningContext* runningContext,
                                      enum edhoc_key_type key_type,
                                      const uint8_t* raw_key,
                                      size_t raw_key_length,
                                      void* key_id_ptr) {

  auto successHandler = [&key_id_ptr](Napi::Env env, Napi::Value result) {
    Napi::HandleScope scope(env);
    uint8_t* key_id = static_cast<uint8_t*>(key_id_ptr);

    if (result.IsTypedArray()) {
      Napi::Uint8Array resultArray = result.As<Napi::Uint8Array>();
      if (resultArray.ElementLength() > CONFIG_LIBEDHOC_KEY_ID_LEN) {
        throw std::runtime_error(kErrorInvalidUint8ArrayLength);
      }
      memcpy(key_id, resultArray.Data(), resultArray.ElementLength());
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
    } else {
      throw std::runtime_error(kErrorExpectUint8ArrayOrNumber);
    }
    return EDHOC_SUCCESS;
  };

  auto argumentsHandler = [this, key_type, raw_key, raw_key_length](Napi::Env env) {
    return std::vector<napi_value> {
      this->edhocRef.Value(),
      Napi::Number::New(env, static_cast<int>(key_type)),
      Napi::Buffer<uint8_t>::Copy(env, const_cast<uint8_t*>(raw_key), raw_key_length)
    };
  };

  return runningContext->ThreadSafeBlockingCall(cryptoManagerRef, "importKey", argumentsHandler, successHandler);
}

int EdhocCryptoManager::callDestroyKey(RunningContext* runningContext, void* key_id) {
  // Timeout thread to ensure the callback is called
  std::shared_ptr<bool> callbackCompleted = std::make_shared<bool>(false);
  // std::thread timeoutThread([callbackCompleted]() {
  //   std::this_thread::sleep_for(std::chrono::milliseconds(200));
  //   if (!*callbackCompleted) {
  //     promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
  //   }
  // });
  // timeoutThread.detach();

  auto successHandler = [](Napi::Env env, Napi::Value result) {
    Napi::HandleScope scope(env);
    if (!result.IsBoolean()) {
      throw std::runtime_error(kErrorExpectBoolean);
    }
    return result.As<Napi::Boolean>().Value() ? EDHOC_SUCCESS : EDHOC_ERROR_GENERIC_ERROR;
  };

  auto argumentsHandler = [this, &key_id, callbackCompleted](Napi::Env env) {
    *callbackCompleted = true;
    return std::vector<napi_value> {
      this->edhocRef.Value(),
      Napi::Buffer<uint8_t>::Copy(env, static_cast<uint8_t*>(key_id), CONFIG_LIBEDHOC_KEY_ID_LEN)
    };
  };

  return runningContext->ThreadSafeBlockingCall(cryptoManagerRef, "destroyKey", argumentsHandler, successHandler);
}

int EdhocCryptoManager::callMakeKeyPair(RunningContext* runningContext,
                                        const void* key_id,
                                        uint8_t* private_key,
                                        size_t private_key_size,
                                        size_t* private_key_length,
                                        uint8_t* public_key,
                                        size_t public_key_size,
                                        size_t* public_key_length) {

  auto successHandler = [&private_key, private_key_size, &private_key_length, &public_key, public_key_size, &public_key_length](Napi::Env env, Napi::Value result) {
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

    return EDHOC_SUCCESS;
  };

  auto argumentsHandler = [this, &key_id, private_key_size, public_key_size](Napi::Env env) {
    return std::vector<napi_value> {
      this->edhocRef.Value(),
      Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t*>(key_id), CONFIG_LIBEDHOC_KEY_ID_LEN),
      Napi::Number::New(env, static_cast<size_t>(private_key_size)),
      Napi::Number::New(env, static_cast<size_t>(public_key_size))
    };
  };

  return runningContext->ThreadSafeBlockingCall(cryptoManagerRef, "makeKeyPair", argumentsHandler, successHandler);
}

int EdhocCryptoManager::callKeyAgreement(RunningContext* runningContext,
                                         const void* key_id,
                                         const uint8_t* peer_public_key,
                                         size_t peer_public_key_length,
                                         uint8_t* shared_secret,
                                         size_t shared_secret_size,
                                         size_t* shared_secret_length) {

  auto successHandler = [&shared_secret, shared_secret_size, &shared_secret_length](Napi::Env env, Napi::Value result) {
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

    return EDHOC_SUCCESS;
  };

  auto argumentsHandler = [this, &key_id, &peer_public_key, peer_public_key_length, shared_secret_size](Napi::Env env) {
    return std::vector<napi_value> {
      this->edhocRef.Value(),
      Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t*>(key_id), CONFIG_LIBEDHOC_KEY_ID_LEN),
      Napi::Buffer<uint8_t>::Copy(env, peer_public_key, peer_public_key_length),
      Napi::Number::New(env, static_cast<size_t>(shared_secret_size))
    };
  };

  return runningContext->ThreadSafeBlockingCall(cryptoManagerRef, "keyAgreement", argumentsHandler, successHandler);
}

int EdhocCryptoManager::callSign(RunningContext* runningContext,
                                 const void* key_id,
                                 const uint8_t* input,
                                 size_t input_length,
                                 uint8_t* signature,
                                 size_t signature_size,
                                 size_t* signature_length) {

  auto successHandler = [&signature, signature_size, &signature_length](Napi::Env env, Napi::Value result) {
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

    return EDHOC_SUCCESS;
  };

  auto argumentsHandler = [this, &key_id, &input, input_length, signature_size](Napi::Env env) {
    return std::vector<napi_value> {
      this->edhocRef.Value(),
      Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t*>(key_id), CONFIG_LIBEDHOC_KEY_ID_LEN),
      Napi::Buffer<uint8_t>::Copy(env, input, input_length),
      Napi::Number::New(env, static_cast<size_t>(signature_size))
    };
  };

  return runningContext->ThreadSafeBlockingCall(cryptoManagerRef, "sign", argumentsHandler, successHandler);
}

int EdhocCryptoManager::callVerify(RunningContext* runningContext,
                                   const void* key_id,
                                   const uint8_t* input,
                                   size_t input_length,
                                   const uint8_t* signature,
                                   size_t signature_length) {

  auto successHandler = [](Napi::Env env, Napi::Value result) {
    Napi::HandleScope scope(env);
    if (!result.IsBoolean()) {
      throw std::runtime_error(kErrorExpectBooleanVerify);
    }
    return result.As<Napi::Boolean>().Value() ? EDHOC_SUCCESS : EDHOC_ERROR_CRYPTO_FAILURE;
  };

  auto argumentsHandler = [this, &key_id, &input, input_length, &signature, signature_length](Napi::Env env) {
    return std::vector<napi_value> {
      this->edhocRef.Value(),
      Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t*>(key_id), CONFIG_LIBEDHOC_KEY_ID_LEN),
      Napi::Buffer<uint8_t>::Copy(env, input, input_length),
      Napi::Buffer<uint8_t>::Copy(env, signature, signature_length)
    };
  };

  return runningContext->ThreadSafeBlockingCall(cryptoManagerRef, "verify", argumentsHandler, successHandler);
}

int EdhocCryptoManager::callExtract(RunningContext* runningContext,
                                    const void* key_id,
                                    const uint8_t* salt,
                                    size_t salt_len,
                                    uint8_t* pseudo_random_key,
                                    size_t pseudo_random_key_size,
                                    size_t* pseudo_random_key_length) {
  auto successHandler = [&pseudo_random_key, pseudo_random_key_size, &pseudo_random_key_length](Napi::Env env, Napi::Value result) {
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

    return EDHOC_SUCCESS;
  };

  auto argumentsHandler = [this, &key_id, &salt, salt_len, pseudo_random_key_size](Napi::Env env) {
    return std::vector<napi_value> {
      this->edhocRef.Value(),
      Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t*>(key_id), CONFIG_LIBEDHOC_KEY_ID_LEN),
      Napi::Buffer<uint8_t>::Copy(env, salt, salt_len),
      Napi::Number::New(env, static_cast<size_t>(pseudo_random_key_size))
    };
  };

  return runningContext->ThreadSafeBlockingCall(cryptoManagerRef, "extract", argumentsHandler, successHandler);
}

int EdhocCryptoManager::callExpand(RunningContext* runningContext,
                                   const void* key_id,
                                   const uint8_t* info,
                                   size_t info_length,
                                   uint8_t* output_keying_material,
                                   size_t output_keying_material_length) {
  auto successHandler = [&output_keying_material, output_keying_material_length](Napi::Env env, Napi::Value result) {
    Napi::HandleScope scope(env);
    if (!result.IsBuffer()) {
      throw std::runtime_error(kErrorExpectBuffer);
    }
    Napi::Buffer<uint8_t> outputBuffer = result.As<Napi::Buffer<uint8_t>>();
    if (outputBuffer.Length() > output_keying_material_length) {
      throw std::runtime_error(kErrorKeyingMaterialLengthExceeds);
    }
    memcpy(output_keying_material, outputBuffer.Data(), outputBuffer.Length());

    return EDHOC_SUCCESS;
  };

  auto argumentsHandler = [this, &key_id, &info, info_length, output_keying_material_length](Napi::Env env) {
    return std::vector<napi_value> {
      this->edhocRef.Value(),
      Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t*>(key_id), CONFIG_LIBEDHOC_KEY_ID_LEN),
      Napi::Buffer<uint8_t>::Copy(env, info, info_length),
      Napi::Number::New(env, static_cast<size_t>(output_keying_material_length))
    };
  };

  return runningContext->ThreadSafeBlockingCall(cryptoManagerRef, "expand", argumentsHandler, successHandler);
}

int EdhocCryptoManager::callEncrypt(RunningContext* runningContext,
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
  auto successHandler = [&ciphertext, ciphertext_size, &ciphertext_length](Napi::Env env, Napi::Value result) {
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

    return EDHOC_SUCCESS;
  };

  auto argumentsHandler = [this, &key_id, &nonce, nonce_length, &additional_data,
                              additional_data_length, &plaintext, plaintext_length, ciphertext_size](Napi::Env env) {
    return std::vector<napi_value> {
      this->edhocRef.Value(),
      Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t*>(key_id), CONFIG_LIBEDHOC_KEY_ID_LEN),
      Napi::Buffer<uint8_t>::Copy(env, nonce, nonce_length),
      Napi::Buffer<uint8_t>::Copy(env, additional_data, additional_data_length),
      Napi::Buffer<uint8_t>::Copy(env, plaintext, plaintext_length),
      Napi::Number::New(env, static_cast<size_t>(ciphertext_size))
    };
  };

  return runningContext->ThreadSafeBlockingCall(cryptoManagerRef, "encrypt", argumentsHandler, successHandler);
}

int EdhocCryptoManager::callDecrypt(RunningContext* runningContext,
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
  auto successHandler = [&plaintext, plaintext_size, &plaintext_length](Napi::Env env, Napi::Value result) {
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

    return EDHOC_SUCCESS;
  };

  auto argumentsHandler = [this, &key_id, &nonce, nonce_length, &additional_data,
                              additional_data_length, &ciphertext, &ciphertext_length, plaintext_size](Napi::Env env) {
    return std::vector<napi_value> {
      this->edhocRef.Value(),
      Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t*>(key_id), CONFIG_LIBEDHOC_KEY_ID_LEN),
      Napi::Buffer<uint8_t>::Copy(env, nonce, nonce_length),
      Napi::Buffer<uint8_t>::Copy(env, additional_data, additional_data_length),
      Napi::Buffer<uint8_t>::Copy(env, ciphertext, ciphertext_length),
      Napi::Number::New(env, static_cast<size_t>(plaintext_size))
    };
  };

  return runningContext->ThreadSafeBlockingCall(cryptoManagerRef, "decrypt", argumentsHandler, successHandler);
}

int EdhocCryptoManager::callHash(RunningContext* runningContext,
                                 const uint8_t* input,
                                 size_t input_length,
                                 uint8_t* hash,
                                 size_t hash_size,
                                 size_t* hash_length) {
  auto successHandler = [&hash, hash_size, &hash_length](Napi::Env env, Napi::Value result) {
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

    return EDHOC_SUCCESS;
  };

  auto argumentsHandler = [this, &input, input_length, hash_size](Napi::Env env) {
    return std::vector<napi_value> {
      this->edhocRef.Value(),
      Napi::Buffer<uint8_t>::Copy(env, input, input_length),
      Napi::Number::New(env, static_cast<size_t>(hash_size))
    };
  };

  return runningContext->ThreadSafeBlockingCall(cryptoManagerRef, "hash", argumentsHandler, successHandler);
}
