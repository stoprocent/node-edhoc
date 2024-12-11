#ifndef EDHOC_KEY_EXPORTER_ASYNC_WORKER_H
#define EDHOC_KEY_EXPORTER_ASYNC_WORKER_H

#include <napi.h>

#include <vector>

extern "C" {
#include "edhoc.h"
}

/**
 * @class EdhocKeyExporterAsyncWorker
 * @brief A class that represents an asynchronous worker for exporting PRKs.
 *
 * This class inherits from the Napi::AsyncWorker class and is used to perform
 * PRK export in a separate thread. It takes an Edhoc context, a label, a
 * desired length, and a callback function as input parameters. The export is
 * performed in the Execute() method, and the result is returned through the
 * OnOK() method or an error is handled through the OnError() method.
 */
class EdhocKeyExporterAsyncWorker : public Napi::AsyncWorker {
 public:
  /**
   * @brief The type definition for the callback function.
   */
  using CallbackType = std::function<void(Napi::Env&)>;

  /**
   * @brief Constructs a new EdhocKeyExporterAsyncWorker object.
   *
   * @param env The Napi::Env object representing the current environment.
   * @param context The reference to the edhoc_context structure.
   * @param label The label of the key to export.
   * @param desiredLength The desired length of the key to export.
   * @param callback The callback function to be called after the export.
   */
  EdhocKeyExporterAsyncWorker(Napi::Env& env,
                              struct edhoc_context& context,
                              uint16_t label,
                              uint8_t desiredLength,
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
  uint16_t label;
  uint8_t desiredLength;
  std::vector<uint8_t> output;
  CallbackType callback;
};

#endif  // EDHOC_KEY_EXPORTER_ASYNC_WORKER_H
