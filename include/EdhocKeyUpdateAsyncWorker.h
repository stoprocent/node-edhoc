#ifndef EDHOC_KEY_UPDATE_ASYNC_WORKER_H
#define EDHOC_KEY_UPDATE_ASYNC_WORKER_H

#include <napi.h>
#include <vector>

#include "RunningContext.h"

extern "C" {
#include "edhoc.h"
}

/**
 * @class EdhocKeyUpdateAsyncWorker
 * @brief A class that represents an asynchronous worker for key update.
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
   * @param runningContext The running context.
   * @param contextBuffer The context buffer.
   */
  EdhocKeyUpdateAsyncWorker(RunningContext *runningContext,
                            std::vector<uint8_t> contextBuffer);

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
  RunningContext* runningContext_;     ///< Pointer to the running context.
  std::vector<uint8_t> contextBuffer_; ///< The context buffer.
};

#endif  // EDHOC_KEY_UPDATE_ASYNC_WORKER_H
