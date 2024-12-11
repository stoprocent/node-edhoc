#ifndef EDHOC_PROCESS_ASYNC_WORKER_H
#define EDHOC_PROCESS_ASYNC_WORKER_H

#include <napi.h>

#include <vector>

extern "C" {
#include "edhoc.h"
}

/**
 * @class EdhocProcessAsyncWorker
 * @brief A class that represents an asynchronous worker for processing Edhoc
 * messages.
 *
 * This class inherits from the Napi::AsyncWorker class and is used to perform
 * Edhoc message processing in a separate thread. It takes an Edhoc context,
 * message number, message buffer, and a callback function as input parameters.
 * The processing is performed in the Execute() method, and the result is
 * returned through the OnOK() method or an error is handled through the
 * OnError() method.
 */
class EdhocProcessAsyncWorker : public Napi::AsyncWorker {
 public:
  /**
   * @brief The type definition for the callback function.
   */
  using CallbackType = std::function<Napi::Array(Napi::Env&)>;

  /**
   * @brief Constructs a new instance of the EdhocProcessAsyncWorker class.
   *
   * @param env The Napi::Env object.
   * @param context The reference to the edhoc_context structure.
   * @param messageNumber The message number.
   * @param buffer The Napi::Buffer<uint8_t> object containing the message
   * buffer.
   * @param callback The callback function to be called after processing.
   */
  EdhocProcessAsyncWorker(Napi::Env& env,
                          struct edhoc_context& context,
                          int messageNumber,
                          Napi::Buffer<uint8_t> buffer,
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
  Napi::Promise::Deferred deferred;       ///< The Napi::Promise::Deferred object for
                                          ///< resolving or rejecting the promise.
  struct edhoc_context& context;          ///< The reference to the edhoc_context structure.
  int messageNumber;                      ///< The message number.
  std::vector<uint8_t> messageBuffer;     ///< The message buffer.
  CallbackType callback;                  ///< The callback function to be called after processing.
  std::vector<uint8_t> peerCipherSuites;  ///< The peer cipher suites.
};

#endif  // EDHOC_PROCESS_ASYNC_WORKER_H
