#ifndef EDHOC_CRYPTO_MANAGER_WRAPPER_H
#define EDHOC_CRYPTO_MANAGER_WRAPPER_H

#include <napi.h>
#include "EdhocCryptoManager.h"

/**
 * @class EdhocCryptoManagerWrapper
 * @brief Wrapper class for EdhocCryptoManager.
 *
 * This class provides a JavaScript interface for interacting with the
 * EdhocCryptoManager class. It allows users to access and utilize the
 * cryptographic functionalities provided by EdhocCryptoManager.
 */
class EdhocCryptoManagerWrapper
    : public Napi::ObjectWrap<EdhocCryptoManagerWrapper> {
 public:
  friend class EdhocCryptoManager;

  /**
   * @brief Initializes the EdhocCryptoManagerWrapper class.
   *
   * This static method is used to initialize the EdhocCryptoManagerWrapper
   * class and bind it to the provided JavaScript environment.
   *
   * @param env The Napi::Env representing the JavaScript environment.
   * @param exports The Napi::Object representing the exports object in the
   * JavaScript module.
   * @return Napi::Object The initialized EdhocCryptoManagerWrapper class.
   */
  static Napi::Object Init(Napi::Env env, Napi::Object exports);

  /**
   * @brief Constructs a new instance of EdhocCryptoManagerWrapper.
   *
   * This constructor is used to create a new instance of
   * EdhocCryptoManagerWrapper.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   */
  EdhocCryptoManagerWrapper(const Napi::CallbackInfo& info);

  /**
   * @brief Destroys the EdhocCryptoManagerWrapper instance.
   *
   * This destructor is used to destroy the EdhocCryptoManagerWrapper instance.
   */
  ~EdhocCryptoManagerWrapper();

  /**
   * @brief Retrieves the internal EdhocCryptoManager instance.
   *
   * This method is used to retrieve the internal EdhocCryptoManager instance.
   *
   * @return std::shared_ptr<EdhocCryptoManager> The internal EdhocCryptoManager
   * instance.
   */
  const std::shared_ptr<EdhocCryptoManager> GetInternalManager();

 private:
  /**
   * @brief The internal EdhocCryptoManager instance.
   */
  std::shared_ptr<EdhocCryptoManager> manager;

  /**
   * @brief Sets the generateKey function.
   *
   * This method is used to set the generateKey function.
   *
   * @param info The Napi::CallbackInfo object containing the function argument.
   * @param value The Napi::Value representing the generateKey function.
   */
  void SetGenerateKey(const Napi::CallbackInfo& info, const Napi::Value& value);

  /**
   * @brief Gets the generateKey function.
   *
   * This method is used to get the generateKey function.
   *
   * @param info The Napi::CallbackInfo object.
   * @return Napi::Value The generateKey function.
   */
  void SetDestroyKey(const Napi::CallbackInfo& info, const Napi::Value& value);

  /**
   * @brief Sets the makeKeyPair function.
   *
   * This method is used to set the makeKeyPair function.
   *
   * @param info The Napi::CallbackInfo object containing the function argument.
   * @param value The Napi::Value representing the makeKeyPair function.
   */
  void SetMakeKeyPair(const Napi::CallbackInfo& info, const Napi::Value& value);

  /**
   * @brief Sets the keyAgreement function.
   *
   * This method is used to set the keyAgreement function.
   *
   * @param info The Napi::CallbackInfo object containing the function argument.
   * @param value The Napi::Value representing the keyAgreement function.
   */
  void SetKeyAgreement(const Napi::CallbackInfo& info,
                       const Napi::Value& value);

  /**
   * @brief Sets the sign function.
   *
   * This method is used to set the sign function.
   *
   * @param info The Napi::CallbackInfo object containing the function argument.
   * @param value The Napi::Value representing the sign function.
   */
  void SetSign(const Napi::CallbackInfo& info, const Napi::Value& value);

  /**
   * @brief Sets the verify function.
   *
   * This method is used to set the verify function.
   *
   * @param info The Napi::CallbackInfo object containing the function argument.
   * @param value The Napi::Value representing the verify function.
   */
  void SetVerify(const Napi::CallbackInfo& info, const Napi::Value& value);

  /**
   * @brief Sets the extract function.
   *
   * This method is used to set the extract function.
   *
   * @param info The Napi::CallbackInfo object containing the function argument.
   * @param value The Napi::Value representing the extract function.
   */
  void SetExtract(const Napi::CallbackInfo& info, const Napi::Value& value);

  /**
   * @brief Sets the expand function.
   *
   * This method is used to set the expand function.
   *
   * @param info The Napi::CallbackInfo object containing the function argument.
   * @param value The Napi::Value representing the expand function.
   */
  void SetExpand(const Napi::CallbackInfo& info, const Napi::Value& value);

  /**
   * @brief Sets the encrypt function.
   *
   * This method is used to set the encrypt function.
   *
   * @param info The Napi::CallbackInfo object containing the function argument.
   * @param value The Napi::Value representing the encrypt function.
   */
  void SetEncrypt(const Napi::CallbackInfo& info, const Napi::Value& value);

  /**
   * @brief Sets the decrypt function.
   *
   * This method is used to set the decrypt function.
   *
   * @param info The Napi::CallbackInfo object containing the function argument.
   * @param value The Napi::Value representing the decrypt function.
   */
  void SetDecrypt(const Napi::CallbackInfo& info, const Napi::Value& value);

  /**
   * @brief Sets the hash function.
   *
   * This method is used to set the hash function.
   *
   * @param info The Napi::CallbackInfo object containing the function argument.
   * @param value The Napi::Value representing the hash function.
   */
  void SetHash(const Napi::CallbackInfo& info, const Napi::Value& value);

  /**
   * @brief Gets the generateKey function.
   *
   * This method is used to get the generateKey function.
   *
   * @param info The Napi::CallbackInfo object.
   * @return Napi::Value The generateKey function.
   */
  Napi::Value GetGenerateKey(const Napi::CallbackInfo& info);

  /**
   * @brief Gets the destroyKey function.
   *
   * This method is used to get the destroyKey function.
   *
   * @param info The Napi::CallbackInfo object.
   * @return Napi::Value The destroyKey function.
   */
  Napi::Value GetDestroyKey(const Napi::CallbackInfo& info);

  /**
   * @brief Gets the makeKeyPair function.
   *
   * This method is used to get the makeKeyPair function.
   *
   * @param info The Napi::CallbackInfo object.
   * @return Napi::Value The makeKeyPair function.
   */
  Napi::Value GetMakeKeyPair(const Napi::CallbackInfo& info);

  /**
   * @brief Gets the keyAgreement function.
   *
   * This method is used to get the keyAgreement function.
   *
   * @param info The Napi::CallbackInfo object.
   * @return Napi::Value The keyAgreement function.
   */
  Napi::Value GetKeyAgreement(const Napi::CallbackInfo& info);

  /**
   * @brief Gets the sign function.
   *
   * This method is used to get the sign function.
   *
   * @param info The Napi::CallbackInfo object.
   * @return Napi::Value The sign function.
   */
  Napi::Value GetSign(const Napi::CallbackInfo& info);

  /**
   * @brief Gets the verify function.
   *
   * This method is used to get the verify function.
   *
   * @param info The Napi::CallbackInfo object.
   * @return Napi::Value The verify function.
   */
  Napi::Value GetVerify(const Napi::CallbackInfo& info);

  /**
   * @brief Gets the extract function.
   *
   * This method is used to get the extract function.
   *
   * @param info The Napi::CallbackInfo object.
   * @return Napi::Value The extract function.
   */
  Napi::Value GetExtract(const Napi::CallbackInfo& info);

  /**
   * @brief Gets the expand function.
   *
   * This method is used to get the expand function.
   *
   * @param info The Napi::CallbackInfo object.
   * @return Napi::Value The expand function.
   */
  Napi::Value GetExpand(const Napi::CallbackInfo& info);

  /**
   * @brief Gets the encrypt function.
   *
   * This method is used to get the encrypt function.
   *
   * @param info The Napi::CallbackInfo object.
   * @return Napi::Value The encrypt function.
   */
  Napi::Value GetEncrypt(const Napi::CallbackInfo& info);

  /**
   * @brief Gets the decrypt function.
   *
   * This method is used to get the decrypt function.
   *
   * @param info The Napi::CallbackInfo object.
   * @return Napi::Value The decrypt function.
   */
  Napi::Value GetDecrypt(const Napi::CallbackInfo& info);

  /**
   * @brief Gets the hash function.
   *
   * This method is used to get the hash function.
   *
   * @param info The Napi::CallbackInfo object.
   * @return Napi::Value The hash function.
   */
  Napi::Value GetHash(const Napi::CallbackInfo& info);

  /**
   * @brief Sets the function and ThreadSafeFunction for a given value.
   *
   * This method is used to set the function and ThreadSafeFunction for a given
   * value.
   *
   * @param value The Napi::Value representing the value to set.
   * @param tsfnName The std::string representing the name of the
   * ThreadSafeFunction.
   * @param functionRef The Napi::FunctionReference representing the function
   * reference.
   * @param tsfn The Napi::ThreadSafeFunction representing the
   * ThreadSafeFunction.
   */
  void SetFunctionAndTsfn(const Napi::Value& value,
                          const std::string& tsfnName,
                          Napi::FunctionReference& functionRef,
                          Napi::ThreadSafeFunction& tsfn);
};

#endif  // EDHOC_CRYPTO_MANAGER_WRAPPER_H
