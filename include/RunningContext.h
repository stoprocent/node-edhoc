#ifndef RUNNING_CONTEXT_H
#define RUNNING_CONTEXT_H

#include <napi.h>
#include <future>

#include "EdhocCredentialManager.h"
#include "EdhocCryptoManager.h"
#include "EdhocEadManager.h"

extern "C" {
#include "edhoc.h"
}

/**
 * @brief RunningContext is a class that manages the running context of the Edhoc library.
 * It is used to handle the asynchronous calls to the Edhoc library.
 */
class RunningContext {
 public:
  /**
   * @brief ArgumentsHandler is a function that takes an Napi::Env and returns a vector of Napi::Value.
   */
  using ArgumentsHandler = std::function<std::vector<napi_value>(Napi::Env)>;
  /**
   * @brief CompletionHandler is a function that takes an Napi::Env and a Napi::Value and returns an int.
   */
  using CompletionHandler = std::function<int(Napi::Env, Napi::Value)>;
  
  /**
   * @brief Constructs a new RunningContext object.
   * @param env The Napi::Env object.
   * @param edhoc_context The pointer to the edhoc_context object.
   * @param cryptoManager The pointer to the cryptoManager object.
   * @param eadManager The pointer to the eadManager object.
   * @param credentialManager The pointer to the credentialManager object.
   */
  RunningContext(Napi::Env env, 
                 struct edhoc_context* edhoc_context,
                 EdhocCryptoManager* cryptoManager,
                 EdhocEadManager* eadManager,
                 EdhocCredentialManager* credentialManager,
                 const Napi::Function& logger);
      
  /**
   * @brief Get the Napi::Env object.
   * @return The Napi::Env object.
   */
  Napi::Env GetEnv() const { return deferred_.Env(); }

  /**
   * @brief ThreadSafeBlockingCall is a function that takes an Napi::ObjectReference, a std::string, an ArgumentsHandler, and a CompletionHandler and returns an int.
   * @param jsObjectRef The Napi::ObjectReference object.
   * @param jsFunctionName The name of the function to call.
   * @param argumentsHandler The ArgumentsHandler object.
   * @param completionHandler The CompletionHandler object.
   * @return The int.
   */
  int ThreadSafeBlockingCall(Napi::ObjectReference& jsObjectRef,
                             const std::string& jsFunctionName,
                             ArgumentsHandler argumentsHandler,
                             CompletionHandler completionHandler);

  /**
   * @brief Resolve is a function that takes an Napi::Value and resolves the promise.
   * @param value The Napi::Value object.
   */
  void Resolve(Napi::Value value);

  /**
   * @brief Reject is a function that takes an Napi::Value and rejects the promise.
   * @param value The Napi::Value object.
   */
  void Reject(Napi::Value value);

  /**
   * @brief GetPromise is a function that returns the promise.
   * @return The Napi::Promise object.
   */
  Napi::Promise GetPromise() const;

  // Raw pointer getters
  Napi::ThreadSafeFunction GetTsfn() const { return tsfn_; }
  EdhocCryptoManager* GetCryptoManager() const { return cryptoManager_; }
  EdhocEadManager* GetEadManager() const { return eadManager_; }
  EdhocCredentialManager* GetCredentialManager() const { return credentialManager_; }
  struct edhoc_context* GetEdhocContext() const { return edhoc_context_; }
  Napi::FunctionReference& GetLoggerRef() { return loggerRef_; }
  
 private:
  struct edhoc_context* edhoc_context_;       ///< Pointer to the edhoc_context object.
  EdhocCryptoManager* cryptoManager_;         ///< Pointer to the cryptoManager object.
  EdhocEadManager* eadManager_;               ///< Pointer to the eadManager object.
  EdhocCredentialManager* credentialManager_; ///< Pointer to the credentialManager object.
  Napi::ThreadSafeFunction tsfn_;             ///< ThreadSafeFunction object.
  Napi::Promise::Deferred deferred_;          ///< Deferred object.
  Napi::FunctionReference loggerRef_;           ///< Reference to the logger function.
  bool isResolved_;                           ///< Boolean to check if the promise is resolved.
  
};

#endif  // RUNNING_CONTEXT_H
