#ifndef LIB_EDHOC_H
#define LIB_EDHOC_H

#include <napi.h>

#include "UserContext.h"

extern "C" {
#include "edhoc.h"
}

/**
 * @class LibEDHOC
 * @brief A class that represents the LibEDHOC object.
 *
 * The LibEDHOC class is a wrapper around the EDHOC library and provides
 * an interface for performing EDHOC operations. It allows users to
 * initialize the EDHOC context, set connection identifiers, set the
 * method used in EDHOC, set cipher suites, set a logger function, and
 * compose/process EDHOC messages.
 */
class LibEDHOC : public Napi::ObjectWrap<LibEDHOC> {
 public:
  /**
   * @brief Initializes the LibEDHOC object.
   *
   * This static method is used to initialize the LibEDHOC object and
   * bind it to the provided JavaScript environment.
   *
   * @param env The Napi::Env representing the JavaScript environment.
   * @param exports The Napi::Object representing the exports object.
   * @return Napi::Object The initialized LibEDHOC object.
   */
  static Napi::Object Init(Napi::Env env, Napi::Object exports);

  /**
   * @brief Constructs a LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   */
  LibEDHOC(const Napi::CallbackInfo& info);

  /**
   * @brief Destroys the LibEDHOC object.
   */
  ~LibEDHOC();

  /**
   * @brief Gets the connection identifier (C_I or C_R depending on the role).
   *
   * This method returns the connection identifier (C_I or C_R depending on the
   * role).
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The connection identifier (C_I or C_R depending on the
   * role).
   */
  Napi::Value GetCID(const Napi::CallbackInfo& info);

  /**
   * @brief Sets the connection identifier (C_I or C_R depending on the role).
   *
   * This method sets the connection identifier (C_I or C_R depending on the
   * role).
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @param value The Napi::Value representing the connection identifier (C_I or
   * C_R depending on the role).
   */
  void SetCID(const Napi::CallbackInfo& info, const Napi::Value& value);

  /**
   * @brief Gets the peer connection identifier (C_I or C_R depending on the
   * role).
   *
   * This method returns the peer connection identifier (C_I or C_R depending on
   * the role).
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The peer connection identifier (C_I or C_R depending on
   * the role).
   */
  Napi::Value GetPeerCID(const Napi::CallbackInfo& info);

  /**
   * @brief Gets the Method (RFC 9528: 3.2.) used in EDHOC.
   *
   * This method returns the Method (RFC 9528: 3.2.) used in EDHOC
   * associated with the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The supported methods used in EDHOC.
   */
  Napi::Value GetMethods(const Napi::CallbackInfo& info);

  /**
   * @brief Sets the Method (RFC 9528: 3.2.) used in EDHOC.
   *
   * This method sets the supported methods (RFC 9528: 3.2.) used in EDHOC for
   * the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @param value The Napi::Value representing the supported methods used in EDHOC.
   */
  void SetMethods(const Napi::CallbackInfo& info, const Napi::Value& value);

  /**
   * @brief Gets the selected method.
   *
   * This method returns the selected method associated with the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The selected method.
   */
  Napi::Value GetSelectedMethod(const Napi::CallbackInfo& info);

  /**
   * @brief Sets the cipher suites.
   *
   * This method sets the cipher suites for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @param value The Napi::Value representing the cipher suites.
   */
  void SetCipherSuites(const Napi::CallbackInfo& info, const Napi::Value& value);

  /**
   * @brief Gets the cipher suites.
   *
   * This method returns the cipher suites associated with the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The cipher suites.
   */
  Napi::Value GetCipherSuites(const Napi::CallbackInfo& info);

  /**
   * @brief Gets the selected cipher suite.
   *
   * This method returns the selected cipher suite associated with the LibEDHOC
   * object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The selected cipher suite.
   */
  Napi::Value GetSelectedCipherSuite(const Napi::CallbackInfo& info);

  /**
   * @brief Gets the logger function.
   *
   * This method returns the logger function associated with the LibEDHOC
   * object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The logger function.
   */
  Napi::Value GetLogger(const Napi::CallbackInfo& info);

  /**
   * @brief Sets the logger function.
   *
   * This method sets the logger function for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @param value The Napi::Value representing the logger function.
   */
  void SetLogger(const Napi::CallbackInfo& info, const Napi::Value& value);

  /**
   * @brief Composes EDHOC message 1.
   *
   * This method composes EDHOC message 1 for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The composed EDHOC message 1.
   */
  Napi::Value ComposeMessage1(const Napi::CallbackInfo& info);

  /**
   * @brief Processes EDHOC message 1.
   *
   * This method processes EDHOC message 1 for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The EAD data from message 1 or Null.
   */
  Napi::Value ProcessMessage1(const Napi::CallbackInfo& info);

  /**
   * @brief Composes EDHOC message 2.
   *
   * This method composes EDHOC message 2 for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The composed EDHOC message 2.
   */
  Napi::Value ComposeMessage2(const Napi::CallbackInfo& info);

  /**
   * @brief Processes EDHOC message 2.
   *
   * This method processes EDHOC message 2 for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The EAD data from message 2 or Null.
   */
  Napi::Value ProcessMessage2(const Napi::CallbackInfo& info);

  /**
   * @brief Composes EDHOC message 3.
   *
   * This method composes EDHOC message 3 for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The composed EDHOC message 3.
   */
  Napi::Value ComposeMessage3(const Napi::CallbackInfo& info);

  /**
   * @brief Processes EDHOC message 3.
   *
   * This method processes EDHOC message 3 for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The EAD data from message 3 or Null.
   */
  Napi::Value ProcessMessage3(const Napi::CallbackInfo& info);

  /**
   * @brief Composes EDHOC message 4.
   *
   * This method composes EDHOC message 4 for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The composed EDHOC message 4.
   */
  Napi::Value ComposeMessage4(const Napi::CallbackInfo& info);

  /**
   * @brief Processes EDHOC message 4.
   *
   * This method processes EDHOC message 4 for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The EAD data from message 4 or Null.
   */
  Napi::Value ProcessMessage4(const Napi::CallbackInfo& info);

  /**
   * @brief Exports OSCORE.
   *
   * This method exports an OSCORE context object containing the master key,
   * salt, recipient ID, and sender ID for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The exported OSCORE context object.
   */
  Napi::Value ExportOSCORE(const Napi::CallbackInfo& info);

  /**
   * @brief Exports keying material using the EDHOC_Exporter interface.
   *
   * This method derives keying material using the EDHOC_Exporter, which
   * utilizes an `exporter_label`, `context`, and `length` to generate the
   * key.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The derived keying material.
   */
  Napi::Value ExportKey(const Napi::CallbackInfo& info);

  /**
   * @brief Performs a key update.
   *
   * This method performs a key update for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value void.
   */
  Napi::Value KeyUpdate(const Napi::CallbackInfo& info);

 private:
  struct edhoc_context context;  ///< The EDHOC context.

  struct edhoc_connection_id cid;  ///< RFC 9528: 3.3.2. Representation of Byte String Identifiers.

  Napi::FunctionReference logger;  ///< N-API reference to the logger function

  // Private member variables to hold instances of EDHOC managers for
  // cryptographic operations, EAD, and credentials
  std::shared_ptr<UserContext> userContext;

  /**
   * @brief Logger function for the LibEDHOC object.
   *
   * This static method is used to log messages from the EDHOC library.
   *
   * @param user_context The user context.
   * @param name The name of the logger.
   * @param buffer The buffer containing the log message.
   * @param buffer_length The length of the log message buffer.
   */
  static void Logger(void* user_context, const char* name, const uint8_t* buffer, size_t buffer_length);

  /**
   * @brief Composes an EDHOC message.
   *
   * This method is used to compose an EDHOC message for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @param message The EDHOC message to compose.
   * @return Napi::Value The composed EDHOC message.
   */
  Napi::Value ComposeMessage(const Napi::CallbackInfo& info, enum edhoc_message message);

  /**
   * @brief Processes an EDHOC message.
   *
   * This method is used to process an EDHOC message for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @param message The EDHOC message to process.
   * @return Napi::Value The EAD data or Null for given EDHOC message.
   */
  Napi::Value ProcessMessage(const Napi::CallbackInfo& info, enum edhoc_message message);
};

#endif  // LIB_EDHOC_H
