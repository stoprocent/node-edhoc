#ifndef EDHOC_EXPORT_OSCORE_ASYNC_WORKER_H
#define EDHOC_EXPORT_OSCORE_ASYNC_WORKER_H

#include <napi.h>
#include <functional>
#include <vector>

#include "RunningContext.h"

extern "C" {
#include "edhoc.h"
}

/**
 * @class EdhocExportOscoreAsyncWorker
 * @brief A class that represents an asynchronous worker for exporting OSCORE context.
 */
class EdhocExportOscoreAsyncWorker : public Napi::AsyncWorker {
 public:
  /**
   * @brief Constructs a new EdhocExportOscoreAsyncWorker object.
   *
   * @param runningContext The pointer to the running context.
   */
  EdhocExportOscoreAsyncWorker(RunningContext* runningContext);

  /**
   * @brief Destroys the EdhocExportOscoreAsyncWorker object.
   */
  ~EdhocExportOscoreAsyncWorker() override;

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
  RunningContext* runningContext_;     ///< The pointer to the running context.
  std::vector<uint8_t> masterSecret_;  ///< The master secret.
  std::vector<uint8_t> masterSalt_;    ///< The master salt.
  std::vector<uint8_t> senderId_;      ///< The sender ID.
  std::vector<uint8_t> recipientId_;   ///< The recipient ID.
};

#endif  // EDHOC_EXPORT_OSCORE_ASYNC_WORKER_H
