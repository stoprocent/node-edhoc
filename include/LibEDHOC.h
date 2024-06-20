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

  static Napi::Object Init(Napi::Env env, Napi::Object exports);

  /**
   * @brief Constructs a LibEDHOC object.
   *
   * The constructor initializes the EDHOC context and connection identifiers.
   * It also sets the method to EDHOC_METHOD_INITIATOR and the logger to
   * nullptr.
   */
  LibEDHOC(const Napi::CallbackInfo &info);

  /**
   * @brief Destroys the LibEDHOC object.
   *
   * The destructor releases the EDHOC context and connection identifiers.
   * It also releases the user context and logger.
   */
  ~LibEDHOC();

  Napi::Value GetCID(const Napi::CallbackInfo &info);

  void SetCID(const Napi::CallbackInfo &info, const Napi::Value &value);

  Napi::Value GetPeerCID(const Napi::CallbackInfo &info);

  Napi::Value GetMethod(const Napi::CallbackInfo &info);

  void SetMethod(const Napi::CallbackInfo &info, const Napi::Value &value);

  void SetCipherSuites(const Napi::CallbackInfo &info, const Napi::Value &value);

  Napi::Value GetCipherSuites(const Napi::CallbackInfo &info);

  Napi::Value GetLogger(const Napi::CallbackInfo &info);

  void SetLogger(const Napi::CallbackInfo &info, const Napi::Value &value);

  Napi::Value ComposeMessage1(const Napi::CallbackInfo &info);

  Napi::Value ProcessMessage1(const Napi::CallbackInfo &info);

  Napi::Value ComposeMessage2(const Napi::CallbackInfo &info);

  Napi::Value ProcessMessage2(const Napi::CallbackInfo &info);

  Napi::Value ComposeMessage3(const Napi::CallbackInfo &info);

  Napi::Value ProcessMessage3(const Napi::CallbackInfo &info);

  Napi::Value ComposeMessage4(const Napi::CallbackInfo &info);

  Napi::Value ProcessMessage4(const Napi::CallbackInfo &info);

  Napi::Value ExportOSCORE(const Napi::CallbackInfo &info);



private:
  struct edhoc_context _context;

  // Private member variables to hold instances of EDHOC managers for
  // cryptographic operations, EAD, and credentials
  std::shared_ptr<UserContext> userContext;

  // Structure to manage connection identifiers within EDHOC
  struct edhoc_connection_id _cid;

  // Enum to specify the method (e.g., symmetric/asymmetric) used in EDHOC
  enum edhoc_method _method;

  // N-API reference to the logger function
  Napi::FunctionReference logger;

  // Static method to log messages from the EDHOC library
  static void Logger(void *user_context, const char *name,
                     const uint8_t *buffer, size_t buffer_length);

  // Method to compose EDHOC messages
  Napi::Value ComposeMessage(const Napi::CallbackInfo &info,
                             enum edhoc_message message);

  // Method to process the EDHOC messages
  Napi::Value ProcessMessage(const Napi::CallbackInfo &info,
                             enum edhoc_message message);
};

#endif // LIB_EDHOC_H
