#ifndef EDHOC_COMPOSE_ASYNC_WORKER_H
#define EDHOC_COMPOSE_ASYNC_WORKER_H

#include <napi.h>
#include <vector>

#include "RunningContext.h"

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
   * @brief Constructor for EdhocComposeAsyncWorker.
   * @param runningContext The running context.
   * @param messageNumber The message number.
   */
  EdhocComposeAsyncWorker(RunningContext* runningContext, int messageNumber);
  
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
  RunningContext* runningContext_;        ///< The running context.
  int messageNumber_;                     ///< The message number.
  std::vector<uint8_t> composedMessage_;  ///< The composed message.
};

#endif  // EDHOC_COMPOSE_ASYNC_WORKER_H
