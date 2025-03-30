#ifndef EDHOC_KEY_EXPORTER_ASYNC_WORKER_H
#define EDHOC_KEY_EXPORTER_ASYNC_WORKER_H

#include <napi.h>
#include <vector>

#include "RunningContext.h"

extern "C" {
#include "edhoc.h"
}

/**
 * @class EdhocKeyExporterAsyncWorker
 * @brief A class that represents an asynchronous worker for exporting PRKs.
 */
class EdhocKeyExporterAsyncWorker : public Napi::AsyncWorker {
 public:

  /**
   * @brief Constructs a new EdhocKeyExporterAsyncWorker object.
   *
   * @param env The Napi::Env object representing the current environment.
   * @param context The reference to the edhoc_context structure.
   * @param label The label of the key to export.
   * @param desiredLength The desired length of the key to export.
   */
  EdhocKeyExporterAsyncWorker(RunningContext* runningContext,
                              uint16_t label,
                              uint8_t desiredLength);

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
  RunningContext* runningContext_; ///< Pointer to the running context.
  uint16_t label_;                 ///< The label of the key to export.
  uint8_t desiredLength_;          ///< The desired length of the key to export.
  std::vector<uint8_t> output_;    ///< The output vector.
};

#endif  // EDHOC_KEY_EXPORTER_ASYNC_WORKER_H
