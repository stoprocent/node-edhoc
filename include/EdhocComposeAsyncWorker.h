#ifndef EDHOC_COMPOSE_ASYNC_WORKER_H
#define EDHOC_COMPOSE_ASYNC_WORKER_H

#include <napi.h>

#include <vector>

extern "C" {
#include "edhoc.h"
}

/**
 * @class EdhocComposeAsyncWorker
 * @brief Asynchronous worker class for composing EDHOC messages.
 */
class EdhocComposeAsyncWorker : public Napi::AsyncWorker {
 public:
  /**
   * @brief The type definition for the callback function.
   */
  using CallbackType = std::function<void(Napi::Env&)>;

  /**
   * @brief Constructor for EdhocComposeAsyncWorker.
   * @param env The Napi::Env object.
   * @param context The EDHOC context.
   * @param messageNumber The message number.
   * @param callback The callback function.
   */
  EdhocComposeAsyncWorker(Napi::Env& env, struct edhoc_context& context, int messageNumber, CallbackType callback);

  /**
   * @brief Executes the asynchronous worker task.
   */
  void Execute() override;

  /**
   * @brief Executes when the asynchronous worker task is completed
   * successfully.
   */
  void OnOK() override;

  /**
   * @brief Executes when an error occurs during the asynchronous worker task.
   * @param error The Napi::Error object.
   */
  void OnError(const Napi::Error& error) override;

  /**
   * @brief Returns the promise object.
   * @return The promise object.
   */
  Napi::Promise GetPromise();

  /**
   * @brief Returns the deferred promise object.
   * @return The deferred promise object.
   */
  Napi::Promise::Deferred GetDeferred();

  Napi::Promise::Deferred deferred;      ///< The deferred promise object.
 private:
  struct edhoc_context& context;         ///< The EDHOC context.
  int messageNumber;                     ///< The message number.
  CallbackType callback;                 ///< The callback function.
  std::vector<uint8_t> composedMessage;  ///< The composed message.
  Napi::Error lastError;                 ///< The last error.
};

#endif  // EDHOC_COMPOSE_ASYNC_WORKER_H
