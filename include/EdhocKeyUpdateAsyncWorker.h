#ifndef EDHOC_KEY_UPDATE_ASYNC_WORKER_H
#define EDHOC_KEY_UPDATE_ASYNC_WORKER_H

#include <napi.h>

#include <vector>

extern "C" {
#include "edhoc.h"
}

/**
 * @class EdhocKeyUpdateAsyncWorker
 * @brief A class that represents an asynchronous worker for key update.
 *
 * This class inherits from the Napi::AsyncWorker class and is used to perform
 * key update in a separate thread. It takes an Edhoc context, a context buffer,
 * and a callback function as input parameters. The key update is performed
 * in the Execute() method, and the result is returned through the OnOK() method
 * or an error is handled through the OnError() method.
 */
class EdhocKeyUpdateAsyncWorker : public Napi::AsyncWorker {
 public:
  /**
   * @brief The type definition for the callback function.
   */
  using CallbackType = std::function<void(Napi::Env&)>;

  /**
   * @brief Constructs a new EdhocKeyUpdateAsyncWorker object.
   *
   * @param env The Napi::Env object representing the current environment.
   * @param context The reference to the edhoc_context structure.
   * @param contextBuffer The context buffer.
   * @param callback The callback function to be called after the key update.
   */
  EdhocKeyUpdateAsyncWorker(Napi::Env& env,
                            struct edhoc_context& context,
                            std::vector<uint8_t> contextBuffer,
                            CallbackType callback);

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

 private:
  Napi::Promise::Deferred deferred;
  struct edhoc_context& context;
  std::vector<uint8_t> contextBuffer;
  CallbackType callback;
};

#endif  // EDHOC_KEY_UPDATE_ASYNC_WORKER_H
