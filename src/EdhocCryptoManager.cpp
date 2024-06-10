#include <iostream>
#include <future>
#include <exception>
#include <stdexcept>

#include "EdhocCryptoManager.h"
#include "UserContext.h"
#include "Utils.h"

EdhocCryptoManager::EdhocCryptoManager() {
    // Constructor implementation
}

EdhocCryptoManager::~EdhocCryptoManager() {
    if (!generateKeyFuncRef.IsEmpty()) generateKeyFuncRef.Reset();
    if (!destroyKeyFuncRef.IsEmpty()) destroyKeyFuncRef.Reset();
    if (!makeKeyPairFuncRef.IsEmpty()) makeKeyPairFuncRef.Reset();
    if (!keyAgreementFuncRef.IsEmpty()) keyAgreementFuncRef.Reset();
    if (!signFuncRef.IsEmpty()) signFuncRef.Reset();
    if (!verifyFuncRef.IsEmpty()) verifyFuncRef.Reset();
    if (!extractFuncRef.IsEmpty()) extractFuncRef.Reset();
    if (!expandFuncRef.IsEmpty()) expandFuncRef.Reset();
    if (!encryptFuncRef.IsEmpty()) encryptFuncRef.Reset();
    if (!decryptFuncRef.IsEmpty()) decryptFuncRef.Reset();
    if (!hashFuncRef.IsEmpty()) hashFuncRef.Reset();

    if (generateTsfn != nullptr) generateTsfn.Release(), generateTsfn = nullptr;
    if (destroyTsfn != nullptr) destroyTsfn.Release(), destroyTsfn = nullptr;
    if (makeKeyPairTsfn != nullptr) makeKeyPairTsfn.Release(), makeKeyPairTsfn = nullptr;
    if (keyAgreementTsfn != nullptr) keyAgreementTsfn.Release(), keyAgreementTsfn = nullptr;
    if (signTsfn != nullptr) signTsfn.Release(), signTsfn = nullptr;
    if (verifyTsfn != nullptr) verifyTsfn.Release(), verifyTsfn = nullptr;
    if (extractTsfn != nullptr) extractTsfn.Release(), extractTsfn = nullptr;
    if (expandTsfn != nullptr) expandTsfn.Release(), expandTsfn = nullptr;
    if (encryptTsfn != nullptr) encryptTsfn.Release(), encryptTsfn = nullptr;
    if (decryptTsfn != nullptr) decryptTsfn.Release(), decryptTsfn = nullptr;
    if (hashTsfn != nullptr) hashTsfn.Release(), hashTsfn = nullptr;
}

int EdhocCryptoManager::GenerateKey(void *user_context, enum edhoc_key_type key_type, const uint8_t *raw_key, size_t raw_key_length, void *key_id) {
    UserContext* userContext = static_cast<UserContext*>(user_context);
    EdhocCryptoManager* cryptoManager = userContext->GetCryptoManager();
    return cryptoManager->CallGenerateKey(key_type, raw_key, raw_key_length, key_id);
}

int EdhocCryptoManager::DestroyKey(void *user_context, void *key_id) {
    UserContext* userContext = static_cast<UserContext*>(user_context);
    EdhocCryptoManager* cryptoManager = userContext->GetCryptoManager();
    return cryptoManager->CallDestroyKey(key_id);
}

int EdhocCryptoManager::MakeKeyPair(void *user_context, const void *key_id, uint8_t *private_key, size_t private_key_size, size_t *private_key_length, uint8_t *public_key, size_t public_key_size, size_t *public_key_length) {
    UserContext* userContext = static_cast<UserContext*>(user_context);
    EdhocCryptoManager* cryptoManager = userContext->GetCryptoManager();
    return cryptoManager->CallMakeKeyPair(key_id, private_key, private_key_size, private_key_length, public_key, public_key_size, public_key_length);
}

int EdhocCryptoManager::KeyAgreement(void *user_context, const void *key_id, const uint8_t *peer_public_key, size_t peer_public_key_length, uint8_t *shared_secret, size_t shared_secret_size, size_t *shared_secret_length) {
    UserContext* userContext = static_cast<UserContext*>(user_context);
    EdhocCryptoManager* cryptoManager = userContext->GetCryptoManager();
    return cryptoManager->CallKeyAgreement(key_id, peer_public_key, peer_public_key_length, shared_secret, shared_secret_size, shared_secret_length);
}

int EdhocCryptoManager::Sign(void *user_context, const void *key_id, const uint8_t *input, size_t input_length, uint8_t *signature, size_t signature_size, size_t *signature_length) {
    UserContext* userContext = static_cast<UserContext*>(user_context);
    EdhocCryptoManager* cryptoManager = userContext->GetCryptoManager();
    return cryptoManager->CallSign(key_id, input, input_length, signature, signature_size, signature_length);
}

int EdhocCryptoManager::Verify(void *user_context, const void *key_id, const uint8_t *input, size_t input_length, const uint8_t *signature, size_t signature_length) {
    UserContext* userContext = static_cast<UserContext*>(user_context);
    EdhocCryptoManager* cryptoManager = userContext->GetCryptoManager();
    return cryptoManager->CallVerify(key_id, input, input_length, signature, signature_length);
}

int EdhocCryptoManager::Extract(void *user_context, const void *key_id, const uint8_t *salt, size_t salt_len, uint8_t *pseudo_random_key, size_t pseudo_random_key_size, size_t *pseudo_random_key_length) {
    UserContext* userContext = static_cast<UserContext*>(user_context);
    EdhocCryptoManager* cryptoManager = userContext->GetCryptoManager();
    return cryptoManager->CallExtract(key_id, salt, salt_len, pseudo_random_key, pseudo_random_key_size, pseudo_random_key_length);
}


int EdhocCryptoManager::Expand(void *user_context, const void *key_id, const uint8_t *info, size_t info_length, uint8_t *output_keying_material, size_t output_keying_material_length) {
    UserContext* userContext = static_cast<UserContext*>(user_context);
    EdhocCryptoManager* cryptoManager = userContext->GetCryptoManager();
    return cryptoManager->CallExpand(key_id, info, info_length, output_keying_material, output_keying_material_length);
}


int EdhocCryptoManager::Encrypt(void *user_context, const void *key_id, const uint8_t *nonce, size_t nonce_length, const uint8_t *additional_data, size_t additional_data_length, const uint8_t *plaintext, size_t plaintext_length, uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length) {
    UserContext* userContext = static_cast<UserContext*>(user_context);
    EdhocCryptoManager* cryptoManager = userContext->GetCryptoManager();
    return cryptoManager->CallEncrypt(key_id, nonce, nonce_length, additional_data, additional_data_length, plaintext, plaintext_length, ciphertext, ciphertext_size, ciphertext_length);
}


int EdhocCryptoManager::Decrypt(void *user_context, const void *key_id, const uint8_t *nonce, size_t nonce_length, const uint8_t *additional_data, size_t additional_data_length, const uint8_t *ciphertext, size_t ciphertext_length, uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length) {
    UserContext* userContext = static_cast<UserContext*>(user_context);
    EdhocCryptoManager* cryptoManager = userContext->GetCryptoManager();
    return cryptoManager->CallDecrypt(key_id, nonce, nonce_length, additional_data, additional_data_length, ciphertext, ciphertext_length, plaintext, plaintext_size, plaintext_length);
}


int EdhocCryptoManager::Hash(void *user_context, const uint8_t *input, size_t input_length, uint8_t *hash, size_t hash_size, size_t *hash_length) {
    UserContext* userContext = static_cast<UserContext*>(user_context);
    EdhocCryptoManager* cryptoManager = userContext->GetCryptoManager();
    return cryptoManager->CallHash(input, input_length, hash, hash_size, hash_length);
}

int EdhocCryptoManager::CallGenerateKey(enum edhoc_key_type key_type, const uint8_t *raw_key, size_t raw_key_length, void *key_id_ptr) {
    std::promise<int> promise;
    std::future<int> future = promise.get_future();

    this->generateTsfn.BlockingCall([&promise, key_type, &raw_key, raw_key_length, &key_id_ptr](Napi::Env env, Napi::Function jsCallback) {
        try {
            std::vector<napi_value> arguments = {
                Napi::Number::New(env, static_cast<int>(key_type)),
                Napi::Buffer<uint8_t>::New(env, const_cast<uint8_t*>(raw_key), raw_key_length)
            };
            Utils::InvokeJSFunctionWithPromiseHandling(env, jsCallback, arguments, [&promise, &key_id_ptr](Napi::Env env, Napi::Value result) {
                uint8_t* key_id = static_cast<uint8_t*>(key_id_ptr); 
                if (result.IsTypedArray()) {
                    Napi::Uint8Array resultArray = result.As<Napi::Uint8Array>();
                    if (resultArray.ElementLength() > EDHOC_KID_LEN) {
                        throw Napi::TypeError::New(env, "Returned Uint8Array length exceeds buffer length.");
                    }
                    memcpy(key_id, resultArray.Data(), resultArray.ElementLength());
                    promise.set_value(EDHOC_SUCCESS);
                } else if (result.IsNumber()) {
                    uint32_t num = result.As<Napi::Number>().Int64Value();
                    uint8_t tempBuffer[EDHOC_KID_LEN];
                    size_t encodedLength = 0;
                    Utils::EncodeUint64ToBuffer(num, tempBuffer, &encodedLength);

                    if (encodedLength > EDHOC_KID_LEN) {
                        throw Napi::TypeError::New(env, "Encoded uint32 exceeds buffer length.");
                    }
                    memcpy(key_id, tempBuffer, encodedLength);
                    memset(key_id + encodedLength, 0, EDHOC_KID_LEN - encodedLength);
                    promise.set_value(EDHOC_SUCCESS);
                } else {
                    throw Napi::TypeError::New(env, "Function must return a Uint8Array or a Number.");
                }
            });
        } catch (const Napi::Error &e) {
            e.ThrowAsJavaScriptException();
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
        }
    });

    future.wait();
    return future.get();
}

int EdhocCryptoManager::CallDestroyKey(void *key_id) {
    std::promise<int> promise;
    std::future<int> future = promise.get_future();

    this->destroyTsfn.BlockingCall([&promise, &key_id](Napi::Env env, Napi::Function jsCallback) {
        try {
            std::vector<napi_value> arguments = {
                Napi::Buffer<uint8_t>::Copy(env, static_cast<uint8_t*>(key_id), EDHOC_KID_LEN)
            };
            Utils::InvokeJSFunctionWithPromiseHandling(env, jsCallback, arguments, [&promise](Napi::Env env, Napi::Value result) {
                if (!result.IsBoolean()) {
                    throw Napi::TypeError::New(env, "Expected boolean return value from destroyKey function");
                }
                promise.set_value( result.As<Napi::Boolean>().Value() ? EDHOC_SUCCESS : EDHOC_ERROR_GENERIC_ERROR );
            });        
        } catch (const Napi::Error &e) {
            e.ThrowAsJavaScriptException();
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
        }
    });

    future.wait();
    return future.get();
}

int EdhocCryptoManager::CallMakeKeyPair(const void *key_id, uint8_t *private_key, size_t private_key_size, size_t *private_key_length, uint8_t *public_key, size_t public_key_size, size_t *public_key_length) {
    std::promise<int> promise;
    std::future<int> future = promise.get_future();

    this->makeKeyPairTsfn.BlockingCall([&promise, &key_id, &private_key, private_key_size, &private_key_length, &public_key, public_key_size, &public_key_length](Napi::Env env, Napi::Function jsCallback) {
        try {
            std::vector<napi_value> arguments = {
                Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t*>(key_id), EDHOC_KID_LEN),
                Napi::Number::New(env, static_cast<size_t>(private_key_size)),
                Napi::Number::New(env, static_cast<size_t>(public_key_size))
            };
            Utils::InvokeJSFunctionWithPromiseHandling(env, jsCallback, arguments, [&promise, &key_id, &private_key, private_key_size, &private_key_length, &public_key, public_key_size, &public_key_length](Napi::Env env, Napi::Value result) {
                if (!result.IsArray()) {
                    throw Napi::TypeError::New(env, "Expected an array");
                }

                Napi::Array resultArray = result.As<Napi::Array>();
                
                if (resultArray.Length() < 2) {
                    throw Napi::TypeError::New(env, "Array must contain at least two elements");
                }

                Napi::Value privateKeyValue = resultArray.Get((uint32_t)0);
                if (!privateKeyValue.IsBuffer()) {
                    throw Napi::TypeError::New(env, "First element must be a Buffer");
                }
                
                Napi::Buffer<uint8_t> privateKeyBuffer = privateKeyValue.As<Napi::Buffer<uint8_t>>();
                
                if (privateKeyBuffer.Length() > private_key_size) {
                    throw Napi::TypeError::New(env, "Returned private key length exceeds buffer length.");
                }

                memcpy(private_key, privateKeyBuffer.Data(), privateKeyBuffer.Length());
                *private_key_length = privateKeyBuffer.Length();

                Napi::Value publicKeyValue = resultArray.Get((uint32_t)1);
                if (!publicKeyValue.IsBuffer()) {
                    throw Napi::TypeError::New(env, "Second element must be a Buffer");
                }

                Napi::Buffer<uint8_t> publicKeyBuffer = publicKeyValue.As<Napi::Buffer<uint8_t>>();

                if (publicKeyBuffer.Length() > public_key_size) {
                    throw Napi::TypeError::New(env, "Returned public key length exceeds buffer length.");
                }

                memcpy(public_key, publicKeyBuffer.Data(), publicKeyBuffer.Length());
                *public_key_length = publicKeyBuffer.Length();

                promise.set_value(EDHOC_SUCCESS);
            });
        } catch (const Napi::Error &e) {
            e.ThrowAsJavaScriptException();
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
        }
    });

    future.wait();
    return future.get();
}

int EdhocCryptoManager::CallKeyAgreement(const void *key_id, const uint8_t *peer_public_key, size_t peer_public_key_length, uint8_t *shared_secret, size_t shared_secret_size, size_t *shared_secret_length) {
    std::promise<int> promise;
    std::future<int> future = promise.get_future();

    this->keyAgreementTsfn.BlockingCall([&promise, &key_id, &peer_public_key, peer_public_key_length, &shared_secret, shared_secret_size, &shared_secret_length](Napi::Env env, Napi::Function jsCallback) {
        try {
            std::vector<napi_value> arguments = {
                Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t*>(key_id), EDHOC_KID_LEN),
                Napi::Buffer<uint8_t>::Copy(env, peer_public_key, peer_public_key_length),
                Napi::Number::New(env, static_cast<size_t>(shared_secret_size)),
            };

            Utils::InvokeJSFunctionWithPromiseHandling(env, jsCallback, arguments, [&promise, &key_id, &peer_public_key, peer_public_key_length, &shared_secret, shared_secret_size, &shared_secret_length](Napi::Env env, Napi::Value result) {
                if (!result.IsBuffer()) {
                    throw Napi::TypeError::New(env, "Expected the result to be a Buffer");
                }

                Napi::Buffer<uint8_t> sharedSecretBuffer = result.As<Napi::Buffer<uint8_t>>();

                if (sharedSecretBuffer.Length() > shared_secret_size) {
                    throw Napi::TypeError::New(env, "Returned shared secret length exceeds buffer length.");
                }

                memcpy(shared_secret, sharedSecretBuffer.Data(), sharedSecretBuffer.Length());
                *shared_secret_length = sharedSecretBuffer.Length();  // Set the output hash length

                promise.set_value(EDHOC_SUCCESS);
            });
        } catch (const Napi::Error &e) {
            e.ThrowAsJavaScriptException();
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
        }
    });

    future.wait();
    return future.get();
}

int EdhocCryptoManager::CallSign(const void *key_id, const uint8_t *input, size_t input_length, uint8_t *signature, size_t signature_size, size_t *signature_length) {
    std::promise<int> promise;
    std::future<int> future = promise.get_future();

    const uint8_t * kid = static_cast<const uint8_t*>(key_id);

    this->signTsfn.BlockingCall([&promise, &key_id, kid, &input, input_length, &signature, signature_size, &signature_length](Napi::Env env, Napi::Function jsCallback) {
        try {
            std::vector<napi_value> arguments = {
                Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t*>(kid), EDHOC_KID_LEN),
                Napi::Buffer<uint8_t>::Copy(env, input, input_length),
                Napi::Number::New(env, static_cast<size_t>(signature_size))
            };
            Utils::InvokeJSFunctionWithPromiseHandling(env, jsCallback, arguments, [&promise, &key_id, &signature, signature_size, &signature_length](Napi::Env env, Napi::Value result) {
                if (!result.IsBuffer()) {
                    Napi::TypeError::New(env, "Expected the result to be a Buffer").ThrowAsJavaScriptException();
                    return promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
                }

                Napi::Buffer<uint8_t> signatureBuffer = result.As<Napi::Buffer<uint8_t>>();

                if (signatureBuffer.Length() > signature_size) {
                    Napi::TypeError::New(env, "Returned signature length exceeds buffer length.").ThrowAsJavaScriptException();
                    return promise.set_value(EDHOC_ERROR_BUFFER_TOO_SMALL);
                }

                memcpy(signature, signatureBuffer.Data(), signatureBuffer.Length());
                *signature_length = signatureBuffer.Length();

                promise.set_value(EDHOC_SUCCESS);
            });
        } catch (const Napi::Error &e) {
            e.ThrowAsJavaScriptException();
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
        }
    });

    future.wait();
    return future.get();
}

int EdhocCryptoManager::CallVerify(const void *key_id, const uint8_t *input, size_t input_length, const uint8_t *signature, size_t signature_length) {
std::promise<int> promise;
    std::future<int> future = promise.get_future();

    this->verifyTsfn.BlockingCall([&promise, &key_id, &input, input_length, &signature, signature_length](Napi::Env env, Napi::Function jsCallback) {
        try {
            std::vector<napi_value> arguments = {
                Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t*>(key_id), EDHOC_KID_LEN),
                Napi::Buffer<uint8_t>::Copy(env, input, input_length),
                Napi::Buffer<uint8_t>::Copy(env, signature, signature_length),
            };
            Utils::InvokeJSFunctionWithPromiseHandling(env, jsCallback, arguments, [&promise](Napi::Env env, Napi::Value result) {
                if (!result.IsBoolean()) {
                    throw Napi::TypeError::New(env, "Expected boolean value as a result from verify function");
                }
                promise.set_value( result.As<Napi::Boolean>().Value() ? EDHOC_SUCCESS : EDHOC_ERROR_CRYPTO_FAILURE );
            });
        } catch (const Napi::Error &e) {
            e.ThrowAsJavaScriptException();
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
        }
    });
    
    future.wait();
    return future.get();
}

int EdhocCryptoManager::CallExtract(const void *key_id, const uint8_t *salt, size_t salt_len, uint8_t *pseudo_random_key, size_t pseudo_random_key_size, size_t *pseudo_random_key_length) {
    std::promise<int> promise;
    std::future<int> future = promise.get_future();

    this->extractTsfn.BlockingCall([&promise, &key_id, &salt, salt_len, &pseudo_random_key, pseudo_random_key_size, &pseudo_random_key_length](Napi::Env env, Napi::Function jsCallback) {
        try {
            std::vector<napi_value> arguments = {
                Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t*>(key_id), EDHOC_KID_LEN),
                Napi::Buffer<uint8_t>::Copy(env, salt, salt_len),
                Napi::Number::New(env, static_cast<size_t>(pseudo_random_key_size))
            };
            // Call the JavaScript function with the input buffer as argument
            Utils::InvokeJSFunctionWithPromiseHandling(env, jsCallback, arguments, [&promise, &pseudo_random_key, pseudo_random_key_size, &pseudo_random_key_length](Napi::Env env, Napi::Value result) {
                // Validate the result is a buffer
                if (!result.IsBuffer()) {
                    Napi::TypeError::New(env, "Expected the result to be a Buffer").ThrowAsJavaScriptException();
                    return promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
                }
                Napi::Buffer<uint8_t> randomKeyBuffer = result.As<Napi::Buffer<uint8_t>>();
                
                // Ensure the received pseudo random key buffer doesn't exceed the allocated hash buffer size
                if (randomKeyBuffer.Length() > pseudo_random_key_size) {
                    Napi::TypeError::New(env, "Returned pseudo random key length exceeds buffer length.").ThrowAsJavaScriptException();
                    promise.set_value(EDHOC_ERROR_BUFFER_TOO_SMALL);
                }

                // Copy the pseudo random key buffer to the pseudo random key array
                memcpy(pseudo_random_key, randomKeyBuffer.Data(), randomKeyBuffer.Length());
                *pseudo_random_key_length = randomKeyBuffer.Length();  // Set the output hash length

                promise.set_value(EDHOC_SUCCESS);
            });
        } catch (const Napi::Error &e) {
            e.ThrowAsJavaScriptException();
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
        }
    });
    
    future.wait();
    return future.get();
}

int EdhocCryptoManager::CallExpand(const void *key_id, const uint8_t *info, size_t info_length, uint8_t *output_keying_material, size_t output_keying_material_length) {
    std::promise<int> promise;
    std::future<int> future = promise.get_future();

    this->expandTsfn.BlockingCall([&promise, &key_id, &info, info_length, &output_keying_material, output_keying_material_length](Napi::Env env, Napi::Function jsCallback) {
        try {
            std::vector<napi_value> arguments = {
                Napi::Buffer<uint8_t>::Copy(env, static_cast<const uint8_t*>(key_id), EDHOC_KID_LEN),
                Napi::Buffer<uint8_t>::Copy(env, info, info_length),
                Napi::Number::New(env, static_cast<size_t>(output_keying_material_length))
            };
            Utils::InvokeJSFunctionWithPromiseHandling(env, jsCallback, arguments, [&promise, &key_id, &output_keying_material, output_keying_material_length](Napi::Env env, Napi::Value result) {
                if (!result.IsBuffer()) {
                    throw Napi::TypeError::New(env, "Expected the result to be a Buffer");
                }
                
                Napi::Buffer<uint8_t> outputBuffer = result.As<Napi::Buffer<uint8_t>>();
                if (outputBuffer.Length() > output_keying_material_length) {
                    throw Napi::TypeError::New(env, "Returned output keying material length exceeds buffer length.");
                }

                memcpy(output_keying_material, outputBuffer.Data(), outputBuffer.Length());

                promise.set_value(EDHOC_SUCCESS);
            });
        } catch (const Napi::Error &e) {
            e.ThrowAsJavaScriptException();
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
        }
    });
        
    future.wait();
    return future.get();
}

int EdhocCryptoManager::CallEncrypt(const void *key_id, const uint8_t *nonce, size_t nonce_length, const uint8_t *additional_data, size_t additional_data_length, const uint8_t *plaintext, size_t plaintext_length, uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length) {
    // Implementation of CallEncrypt
}

int EdhocCryptoManager::CallDecrypt(const void *key_id, const uint8_t *nonce, size_t nonce_length, const uint8_t *additional_data, size_t additional_data_length, const uint8_t *ciphertext, size_t ciphertext_length, uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length) {
    // Implementation of CallDecrypt
}

int EdhocCryptoManager::CallHash(const uint8_t *input, size_t input_length, uint8_t *hash, size_t hash_size, size_t *hash_length) {
    std::promise<int> promise;
    std::future<int> future = promise.get_future();

    this->hashTsfn.BlockingCall([&promise, &input, input_length, &hash, hash_size, &hash_length](Napi::Env env, Napi::Function jsCallback) {
        try {
            std::vector<napi_value> arguments = {
                Napi::Buffer<uint8_t>::Copy(env, input, input_length),
                Napi::Number::New(env, static_cast<size_t>(hash_size)),
            };
            Utils::InvokeJSFunctionWithPromiseHandling(env, jsCallback, arguments, [&promise, &hash, hash_size, &hash_length](Napi::Env env, Napi::Value result) {
                if (!result.IsBuffer()) {
                    throw Napi::TypeError::New(env, "Expected the result to be a Buffer");
                }
                Napi::Buffer<uint8_t> hashBuffer = result.As<Napi::Buffer<uint8_t>>();
                
                // Ensure the received hash buffer doesn't exceed the allocated hash buffer size
                if (hashBuffer.Length() > hash_size) {
                    throw Napi::TypeError::New(env, "Returned hash length exceeds buffer length.");
                }

                // Copy the hash buffer to the hash array
                memcpy(hash, hashBuffer.Data(), hashBuffer.Length());
                *hash_length = hashBuffer.Length();  // Set the output hash length

                promise.set_value(EDHOC_SUCCESS);
            });
        } catch (const Napi::Error &e) {
            e.ThrowAsJavaScriptException();
            promise.set_value(EDHOC_ERROR_GENERIC_ERROR);
        }
    });

    future.wait();
    return future.get();
}
