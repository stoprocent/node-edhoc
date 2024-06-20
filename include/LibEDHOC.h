#ifndef LIB_EDHOC_H
#define LIB_EDHOC_H

#include "UserContext.h"
#include <napi.h>

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
   * The constructor initializes the EDHOC context and connection identifiers.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   */
  LibEDHOC(const Napi::CallbackInfo &info);

  /**
   * @brief Destroys the LibEDHOC object.
   *
   * The destructor releases the EDHOC context and connection identifiers.
   * It also releases the user context and logger.
   */
  ~LibEDHOC();

  /**
   * @brief Gets the connection identifier (CID).
   *
   * This method returns the connection identifier (CID) associated with
   * the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The connection identifier (CID).
   */
  Napi::Value GetCID(const Napi::CallbackInfo &info);

  /**
   * @brief Sets the connection identifier (CID).
   *
   * This method sets the connection identifier (CID) for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @param value The Napi::Value representing the connection identifier (CID).
   */
  void SetCID(const Napi::CallbackInfo &info, const Napi::Value &value);

  /**
   * @brief Gets the peer connection identifier (CID).
   *
   * This method returns the peer connection identifier (CID) associated with
   * the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The peer connection identifier (CID).
   */
  Napi::Value GetPeerCID(const Napi::CallbackInfo &info);

  /**
   * @brief Gets the method used in EDHOC.
   *
   * This method returns the method used in EDHOC (e.g., symmetric/asymmetric)
   * associated with the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The method used in EDHOC.
   */
  Napi::Value GetMethod(const Napi::CallbackInfo &info);

  /**
   * @brief Sets the method used in EDHOC.
   *
   * This method sets the method used in EDHOC (e.g., symmetric/asymmetric)
   * for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @param value The Napi::Value representing the method used in EDHOC.
   */
  void SetMethod(const Napi::CallbackInfo &info, const Napi::Value &value);

  /**
   * @brief Sets the cipher suites.
   *
   * This method sets the cipher suites for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @param value The Napi::Value representing the cipher suites.
   */
  void SetCipherSuites(const Napi::CallbackInfo &info,
                       const Napi::Value &value);

  /**
   * @brief Gets the cipher suites.
   *
   * This method returns the cipher suites associated with the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The cipher suites.
   */
  Napi::Value GetCipherSuites(const Napi::CallbackInfo &info);

  /**
   * @brief Gets the logger function.
   *
   * This method returns the logger function associated with the LibEDHOC
   * object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The logger function.
   */
  Napi::Value GetLogger(const Napi::CallbackInfo &info);

  /**
   * @brief Sets the logger function.
   *
   * This method sets the logger function for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @param value The Napi::Value representing the logger function.
   */
  void SetLogger(const Napi::CallbackInfo &info, const Napi::Value &value);

  /**
   * @brief Composes EDHOC message 1.
   *
   * This method composes EDHOC message 1 for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The composed EDHOC message 1.
   */
  Napi::Value ComposeMessage1(const Napi::CallbackInfo &info);

  /**
   * @brief Processes EDHOC message 1.
   *
   * This method processes EDHOC message 1 for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The processed EDHOC message 1.
   */
  Napi::Value ProcessMessage1(const Napi::CallbackInfo &info);

  /**
   * @brief Composes EDHOC message 2.
   *
   * This method composes EDHOC message 2 for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The composed EDHOC message 2.
   */
  Napi::Value ComposeMessage2(const Napi::CallbackInfo &info);

  /**
   * @brief Processes EDHOC message 2.
   *
   * This method processes EDHOC message 2 for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The processed EDHOC message 2.
   */
  Napi::Value ProcessMessage2(const Napi::CallbackInfo &info);

  /**
   * @brief Composes EDHOC message 3.
   *
   * This method composes EDHOC message 3 for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The composed EDHOC message 3.
   */
  Napi::Value ComposeMessage3(const Napi::CallbackInfo &info);

  /**
   * @brief Processes EDHOC message 3.
   *
   * This method processes EDHOC message 3 for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The processed EDHOC message 3.
   */
  Napi::Value ProcessMessage3(const Napi::CallbackInfo &info);

  /**
   * @brief Composes EDHOC message 4.
   *
   * This method composes EDHOC message 4 for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The composed EDHOC message 4.
   */
  Napi::Value ComposeMessage4(const Napi::CallbackInfo &info);

  /**
   * @brief Processes EDHOC message 4.
   *
   * This method processes EDHOC message 4 for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The processed EDHOC message 4.
   */
  Napi::Value ProcessMessage4(const Napi::CallbackInfo &info);

  /**
   * @brief Exports OSCORE.
   *
   * This method exports OSCORE for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @return Napi::Value The exported OSCORE.
   */
  Napi::Value ExportOSCORE(const Napi::CallbackInfo &info);

private:

  struct edhoc_context context; ///< The EDHOC context.

  struct edhoc_connection_id cid; ///< RFC 9528: 3.3.2. Representation of Byte String Identifiers.

  enum edhoc_method method; ///< RFC 9528: 3.2. Method.

  Napi::FunctionReference logger; ///< N-API reference to the logger function

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
  static void Logger(void *user_context, const char *name,
                     const uint8_t *buffer, size_t buffer_length);

  /**
   * @brief Composes an EDHOC message.
   *
   * This method is used to compose an EDHOC message for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @param message The EDHOC message to compose.
   * @return Napi::Value The composed EDHOC message.
   */
  Napi::Value ComposeMessage(const Napi::CallbackInfo &info,
                             enum edhoc_message message);

  /**
   * @brief Processes an EDHOC message.
   *
   * This method is used to process an EDHOC message for the LibEDHOC object.
   *
   * @param info The Napi::CallbackInfo representing the callback information.
   * @param message The EDHOC message to process.
   * @return Napi::Value The processed EDHOC message.
   */
  Napi::Value ProcessMessage(const Napi::CallbackInfo &info,
                             enum edhoc_message message);
};

#endif // LIB_EDHOC_H
