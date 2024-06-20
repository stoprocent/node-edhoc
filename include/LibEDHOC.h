#ifndef LIB_EDHOC_H
#define LIB_EDHOC_H

#include "UserContext.h"
#include <napi.h>

extern "C" {
#include "edhoc.h"
}

/**
 * @class LibEDHOC
 * @brief Represents the EDHOC protocol in a Node.js add-on.
 *
 * The LibEDHOC class encapsulates the EDHOC protocol and provides methods to
 * interact with it. It also provides access to the EDHOC context, connection
 * identifiers, method, cipher suites, and logger.
 */
class LibEDHOC : public Napi::ObjectWrap<LibEDHOC> {
public:
  /**
   * @brief Initializes the LibEDHOC class and exports it to JavaScript.
   *
   * @param env The Napi::Env environment.
   * @param exports The Napi::Object exports.
   * @return Napi::Object The exported object.
   */
  static Napi::Object Init(Napi::Env env, Napi::Object exports);

  /**
   * @brief Constructs a LibEDHOC object.
   *
   * The constructor initializes the EDHOC context and connection identifiers.
   */
  LibEDHOC(const Napi::CallbackInfo &info);

  /**
   * @brief Destroys the LibEDHOC object.
   */
  ~LibEDHOC();

  /**
   * @brief Retrieves the EDHOC context as a N-API value.
   *
   * This method retrieves the EDHOC context as a N-API value.
   *
   * @param info The Napi::CallbackInfo object representing the callback
   * information.
   * @return The N-API value representing the EDHOC context.
   */
  Napi::Value GetCID(const Napi::CallbackInfo &info);

  /**
   * @brief Sets the connection identifier in the EDHOC context from a N-API
   * value.
   *
   * This method sets the connection identifier in the EDHOC context from a
   * N-API value.
   *
   * @param info The Napi::CallbackInfo object representing the callback
   * information.
   * @param value The N-API value representing the connection identifier.
   */
  void SetCID(const Napi::CallbackInfo &info, const Napi::Value &value);

  /**
   * @brief Retrieves the peer's connection identifier from the EDHOC context as
   * a N-API value.
   *
   * This method retrieves the connection identifier from the EDHOC context as a
   * N-API value.
   *
   * @param info The Napi::CallbackInfo object representing the callback
   * information.
   * @return The N-API value representing the connection identifier.
   */
  Napi::Value GetPeerCID(const Napi::CallbackInfo &info);

  /**
   * @brief Sets the peer's connection identifier in the EDHOC context from a
   * N-API value.
   *
   * This method sets the peer connection identifier in the EDHOC context from a
   * N-API value.
   *
   * @param info The Napi::CallbackInfo object representing the callback
   * information.
   * @param value The N-API value representing the peer connection identifier.
   */
  Napi::Value GetMethod(const Napi::CallbackInfo &info);

  /**
   * @brief Sets the method in the EDHOC context from a N-API value.
   *
   * This method sets the method in the EDHOC context from a N-API value.
   *
   * @param info The Napi::CallbackInfo object representing the callback
   * information.
   * @param value The N-API value representing the method.
   */
  void SetMethod(const Napi::CallbackInfo &info, const Napi::Value &value);

  /**
   * @brief Retrieves the method from the EDHOC context as a N-API value.
   *
   * This method retrieves the method from the EDHOC context as a N-API value.
   *
   * @param info The Napi::CallbackInfo object representing the callback
   * information.
   * @return The N-API value representing the method.
   */
  void SetCipherSuites(const Napi::CallbackInfo &info,
                       const Napi::Value &value);

  /**
   * @brief Sets the cipher suites in the EDHOC context from a N-API value.
   *
   * This method sets the cipher suites in the EDHOC context from a N-API value.
   *
   * @param info The Napi::CallbackInfo object representing the callback
   * information.
   * @param value The N-API value representing the cipher suites.
   */
  Napi::Value GetCipherSuites(const Napi::CallbackInfo &info);

  /**
   * @brief Retrieves the cipher suites from the EDHOC context as a N-API value.
   *
   * This method retrieves the cipher suites from the EDHOC context as a N-API
   * value.
   *
   * @param info The Napi::CallbackInfo object representing the callback
   * information.
   * @return The N-API value representing the cipher suites.
   */
  Napi::Value GetLogger(const Napi::CallbackInfo &info);

  /**
   * @brief Sets the logger in the EDHOC context from a N-API value.
   *
   * This method sets the logger in the EDHOC context from a N-API value.
   *
   * @param info The Napi::CallbackInfo object representing the callback
   * information.
   * @param value The N-API value representing the logger.
   */
  void SetLogger(const Napi::CallbackInfo &info, const Napi::Value &value);

  /**
   * @brief Composes the first message in the EDHOC protocol.
   *
   * This method composes the first message in the EDHOC protocol.
   *
   * @param info The Napi::CallbackInfo object representing the callback
   * information.
   * @return The N-API value representing the first message.
   */
  Napi::Value ComposeMessage1(const Napi::CallbackInfo &info);

  /**
   * @brief Processes the first message in the EDHOC protocol.
   *
   * This method processes the first message in the EDHOC protocol.
   *
   * @param info The Napi::CallbackInfo object representing the callback
   * information.
   * @return The N-API value representing the processed first message.
   */
  Napi::Value ProcessMessage1(const Napi::CallbackInfo &info);

  /**
   * @brief Composes the second message in the EDHOC protocol.
   *
   * This method composes the second message in the EDHOC protocol.
   *
   * @param info The Napi::CallbackInfo object representing the callback
   * information.
   * @return The N-API value representing the second message.
   */
  Napi::Value ComposeMessage2(const Napi::CallbackInfo &info);

  /**
   * @brief Processes the second message in the EDHOC protocol.
   *
   * This method processes the second message in the EDHOC protocol.
   *
   * @param info The Napi::CallbackInfo object representing the callback
   * information.
   * @return The N-API value representing the processed second message.
   */
  Napi::Value ProcessMessage2(const Napi::CallbackInfo &info);

  /**
   * @brief Composes the third message in the EDHOC protocol.
   *
   * This method composes the third message in the EDHOC protocol.
   *
   * @param info The Napi::CallbackInfo object representing the callback
   * information.
   * @return The N-API value representing the third message.
   */
  Napi::Value ComposeMessage3(const Napi::CallbackInfo &info);

  /**
   * @brief Processes the third message in the EDHOC protocol.
   *
   * This method processes the third message in the EDHOC protocol.
   *
   * @param info The Napi::CallbackInfo object representing the callback
   * information.
   * @return The N-API value representing the processed third message.
   */
  Napi::Value ProcessMessage3(const Napi::CallbackInfo &info);

  /**
   * @brief Composes the fourth message in the EDHOC protocol.
   *
   * This method composes the fourth message in the EDHOC protocol.
   *
   * @param info The Napi::CallbackInfo object representing the callback
   * information.
   * @return The N-API value representing the fourth message.
   */
  Napi::Value ComposeMessage4(const Napi::CallbackInfo &info);

  /**
   * @brief Processes the fourth message in the EDHOC protocol.
   *
   * This method processes the fourth message in the EDHOC protocol.
   *
   * @param info The Napi::CallbackInfo object representing the callback
   * information.
   * @return The N-API value representing the processed fourth message.
   */
  Napi::Value ProcessMessage4(const Napi::CallbackInfo &info);

  /**
   * @brief Exports the EDHOC context.
   *
   * This method exports the EDHOC context.
   *
   * @param info The Napi::CallbackInfo object representing the callback
   * information.
   * @return The N-API value representing the exported EDHOC context.
   */
  Napi::Value ExportOSCORE(const Napi::CallbackInfo &info);

private:
  struct edhoc_context context; ///< Libedhoc's internal EDHOC context

  std::shared_ptr<UserContext>
      userContext; ///< Private member variables to hold instances of EDHOC
                   ///< managers for cryptographic operations, EAD, and
                   ///< credentials

  struct edhoc_connection_id
      cid; ///< RFC 9528: 3.3.2. Representation of Byte String Identifiers.

  enum edhoc_method method; ///< RFC 9528: 3.2. Method.

  Napi::FunctionReference logger; ///< N-API reference to the logger function

  static void Logger(void *user_context, const char *name,
                     const uint8_t *buffer, size_t buffer_length);

  Napi::Value ComposeMessage(const Napi::CallbackInfo &info,
                             enum edhoc_message message);

  Napi::Value ProcessMessage(const Napi::CallbackInfo &info,
                             enum edhoc_message message);
};

#endif // LIB_EDHOC_H
