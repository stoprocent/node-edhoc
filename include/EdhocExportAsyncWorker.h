#ifndef EDHOC_EXPORT_ASYNC_WORKER_H
#define EDHOC_EXPORT_ASYNC_WORKER_H

#include <functional>
#include <napi.h>
#include <vector>

extern "C" {
#include "edhoc.h"
}

/**
 * @class EdhocExportAsyncWorker
 * @brief A class that represents an asynchronous worker for exporting Edhoc
 * context.
 *
 * This class inherits from Napi::AsyncWorker and provides methods for executing
 * the export operation asynchronously and handling the result or error.
 */
class EdhocExportAsyncWorker : public Napi::AsyncWorker {
public:
  using CallbackType = std::function<void(Napi::Env)>;

  /**
   * @brief Constructs a new EdhocExportAsyncWorker object.
   *
   * @param env The Napi::Env object representing the current environment.
   * @param deferred The Napi::Promise::Deferred object representing the
   * deferred promise.
   * @param context The reference to the edhoc_context structure.
   */
  EdhocExportAsyncWorker(Napi::Env &env, Napi::Promise::Deferred deferred,
                         struct edhoc_context &context);

  /**
   * @brief Destroys the EdhocExportAsyncWorker object.
   */
  ~EdhocExportAsyncWorker() override;

  /**
   * @brief Executes the export operation.
   *
   * This method is called by the worker thread to perform the export operation.
   */
  void Execute() override;

  /**
   * @brief Handles the successful completion of the export operation.
   *
   * This method is called on the main thread when the export operation is
   * completed successfully.
   */
  void OnOK() override;

  /**
   * @brief Handles the error that occurred during the export operation.
   *
   * This method is called on the main thread when an error occurs during the
   * export operation.
   *
   * @param error The Napi::Error object representing the error.
   */
  void OnError(const Napi::Error &error) override;

private:
  Napi::Promise::Deferred deferred; /**< The deferred promise object. */
  struct edhoc_context
      &context; /**< The reference to the edhoc_context structure. */
  std::vector<uint8_t> masterSecret; /**< The master secret. */
  std::vector<uint8_t> masterSalt;   /**< The master salt. */
  std::vector<uint8_t> senderId;     /**< The sender ID. */
  std::vector<uint8_t> recipientId;  /**< The recipient ID. */
};

#endif // EDHOC_EXPORT_ASYNC_WORKER_H
