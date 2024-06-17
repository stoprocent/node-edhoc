#ifndef EDHOC_CREDENTIAL_MANAGER_WRAPPER_H
#define EDHOC_CREDENTIAL_MANAGER_WRAPPER_H

#include "EdhocCredentialManager.h"
#include <napi.h>

/**
 * @class EdhocCredentialManagerWrapper
 * @brief Wraps the EdhocCredentialManager class and exports it to JavaScript.
 */
class EdhocCredentialManagerWrapper
    : public Napi::ObjectWrap<EdhocCredentialManagerWrapper> {
public:
  friend class EdhocCredentialManager;

  /**
   * @brief Initializes the EdhocCredentialManagerWrapper class and exports it
   * to JavaScript.
   *
   * @param env The Napi::Env environment.
   * @param exports The Napi::Object exports.
   * @return Napi::Object The exported object.
   */
  static Napi::Object Init(Napi::Env env, Napi::Object exports);

  /**
   * @brief Constructor for EdhocCredentialManagerWrapper class.
   *
   * @param info The Napi::CallbackInfo object containing the constructor
   * arguments.
   */
  EdhocCredentialManagerWrapper(const Napi::CallbackInfo &info);

  /**
   * @brief Destructor for EdhocCredentialManagerWrapper class.
   */
  ~EdhocCredentialManagerWrapper();

  /**
   * @brief Gets the internal EdhocCredentialManager object.
   *
   * @return std::shared_ptr<EdhocCredentialManager> The internal
   * EdhocCredentialManager object.
   */
  const std::shared_ptr<EdhocCredentialManager> GetInternalManager();

private:
  std::shared_ptr<EdhocCredentialManager> manager;

  /**
   * @brief Sets the fetch function.
   *
   * @param info The Napi::CallbackInfo object containing the function argument.
   * @param value The Napi::Value representing the fetch function.
   */
  void SetFetch(const Napi::CallbackInfo &info, const Napi::Value &value);

  /**
   * @brief Gets the fetch function.
   *
   * @param info The Napi::CallbackInfo object.
   * @return Napi::Value The fetch function.
   */
  Napi::Value GetFetch(const Napi::CallbackInfo &info);

  /**
   * @brief Sets the verify function.
   *
   * @param info The Napi::CallbackInfo object containing the function argument.
   * @param value The Napi::Value representing the verify function.
   */
  void SetVerify(const Napi::CallbackInfo &info, const Napi::Value &value);

  /**
   * @brief Gets the verify function.
   *
   * @param info The Napi::CallbackInfo object.
   * @return Napi::Value The verify function.
   */
  Napi::Value GetVerify(const Napi::CallbackInfo &info);

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
  void SetFunctionAndTsfn(const Napi::Value &value, const std::string &tsfnName,
                          Napi::FunctionReference &functionRef,
                          Napi::ThreadSafeFunction &tsfn);
};

#endif // EDHOC_CREDENTIAL_MANAGER_WRAPPER_H
