#ifndef EDHOC_PROCESS_ASYNC_WORKER_H
#define EDHOC_PROCESS_ASYNC_WORKER_H

#include <napi.h>
#include <vector>

#include "RunningContext.h"

extern "C" {
#include "edhoc.h"
}

/**
 * @class EdhocProcessAsyncWorker
 * @brief A class that represents an asynchronous worker for processing Edhoc messages.
 */
class EdhocProcessAsyncWorker : public Napi::AsyncWorker {
 public:

  /**
   * @brief Constructs a new instance of the EdhocProcessAsyncWorker class.
   *
   * @param runningContext The running context.
   * @param messageNumber The message number.
   * @param buffer The Napi::Buffer<uint8_t> object containing the message buffer.
   */
  EdhocProcessAsyncWorker(RunningContext* runningContext,
                          int messageNumber,
                          Napi::Buffer<uint8_t> buffer);

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

 private:
  RunningContext* runningContext_;         ///< The pointer to the running context.
  int messageNumber_;                      ///< The message number.
  std::vector<uint8_t> messageBuffer_;     ///< The message buffer.
  std::vector<uint8_t> peerCipherSuites_;  ///< The peer cipher suites.
};

#endif  // EDHOC_PROCESS_ASYNC_WORKER_H
