#ifndef EDHOC_EXPORT_ASYNC_WORKER_H
#define EDHOC_EXPORT_ASYNC_WORKER_H

#include <napi.h>
#include <functional>
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
  /**
   * @brief The type definition for the callback function.
   */
  using CallbackType = std::function<void(Napi::Env)>;

  /**
   * @brief Constructs a new EdhocExportAsyncWorker object.
   *
   * @param env The Napi::Env object representing the current environment.
   * @param deferred The Napi::Promise::Deferred object representing the
   * deferred promise.
   * @param context The reference to the edhoc_context structure.
   */
  EdhocExportAsyncWorker(Napi::Env& env,
                         Napi::Promise::Deferred deferred,
                         struct edhoc_context& context);

  /**
   * @brief Destroys the EdhocExportAsyncWorker object.
   */
  ~EdhocExportAsyncWorker() override;

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
  Napi::Promise::Deferred deferred;  ///< The deferred promise object.
  struct edhoc_context&
      context;  ///< The reference to the edhoc_context structure.
  std::vector<uint8_t> masterSecret;  ///< The master secret.
  std::vector<uint8_t> masterSalt;    ///< The master salt.
  std::vector<uint8_t> senderId;      ///< The sender ID.
  std::vector<uint8_t> recipientId;   ///< The recipient ID.
};

#endif  // EDHOC_EXPORT_ASYNC_WORKER_H
