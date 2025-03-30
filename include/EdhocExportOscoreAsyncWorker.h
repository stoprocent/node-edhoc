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
 * @brief A class that represents an asynchronous worker for exporting Edhoc
 * context.
 *
 * This class inherits from Napi::AsyncWorker and provides methods for executing
 * the export operation asynchronously and handling the result or error.
 */
class EdhocExportOscoreAsyncWorker : public Napi::AsyncWorker {
 public:
  /**
   * @brief Constructs a new EdhocExportOscoreAsyncWorker object.
   *
   * @param runningContext The reference to the running context.
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
  RunningContext* runningContext_;    ///< The running context.
  std::vector<uint8_t> masterSecret;  ///< The master secret.
  std::vector<uint8_t> masterSalt;    ///< The master salt.
  std::vector<uint8_t> senderId;      ///< The sender ID.
  std::vector<uint8_t> recipientId;   ///< The recipient ID.
};

#endif  // EDHOC_EXPORT_OSCORE_ASYNC_WORKER_H
