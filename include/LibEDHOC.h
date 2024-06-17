#ifndef LIB_EDHOC_H
#define LIB_EDHOC_H

#include <napi.h>
#include "UserContext.h"

extern "C" {
    #include "edhoc.h"
}

/**
 * @class LibEDHOC
 * @brief Represents the EDHOC protocol in a Node.js add-on.
 * 
 * The LibEDHOC class encapsulates the EDHOC protocol and provides methods to interact with it.
 * It also provides access to the EDHOC context, connection identifiers, method, cipher suites, and logger.
 */
class LibEDHOC : public Napi::ObjectWrap<LibEDHOC> {
public:
    
    /**
     * @brief Constructs a LibEDHOC object.
     * 
     * The constructor initializes the EDHOC context and connection identifiers.
     * It also sets the method to EDHOC_METHOD_INITIATOR and the logger to nullptr.
     */
    LibEDHOC(const Napi::CallbackInfo& info);

    /**
     * @brief Destroys the LibEDHOC object.
     * 
     * The destructor releases the EDHOC context and connection identifiers.
     * It also releases the user context and logger.
     */
    ~LibEDHOC();

    /**
     * @brief Retrieves the EDHOC context as a N-API value.
     * 
     * This method retrieves the EDHOC context as a N-API value.
     * 
     * @param info The Napi::CallbackInfo object representing the callback information.
     * @return The N-API value representing the EDHOC context.
     */
    Napi::Value GetCID(const Napi::CallbackInfo &info);

    /**
     * @brief Sets the connection identifier in the EDHOC context from a N-API value.
     * 
     * This method sets the connection identifier in the EDHOC context from a N-API value.
     * 
     * @param info The Napi::CallbackInfo object representing the callback information.
     * @param value The N-API value representing the connection identifier.
     */
    void SetCID(const Napi::CallbackInfo &info, const Napi::Value &value);
    
    // Retrieves the Peer Connection ID from the EDHOC context as a N-API value
    Napi::Value GetPeerCID(const Napi::CallbackInfo &info);

    // Retrieves the Method (e.g., authentication method) from the EDHOC context as a N-API value
    Napi::Value GetMethod(const Napi::CallbackInfo &info);

    // Sets the Method in the EDHOC context from a N-API value
    void SetMethod(const Napi::CallbackInfo &info, const Napi::Value &value);

    // Retrieves the Cipher Suites from the EDHOC context as a N-API value
    void SetCipherSuites(const Napi::CallbackInfo &info, const Napi::Value &value);

    // Gets the Cipher Suites from the EDHOC context as a N-API value
    Napi::Value GetCipherSuites(const Napi::CallbackInfo &info);

    // Retrieves the Logger function from the EDHOC context as a N-API value
    Napi::Value GetLogger(const Napi::CallbackInfo &info);

    // Sets the Logger function in the EDHOC context from a N-API value
    void SetLogger(const Napi::CallbackInfo &info, const Napi::Value &value);

    // Method to compose first message in the EDHOC protocol
    Napi::Value ComposeMessage1(const Napi::CallbackInfo &info);

    // Method to process the first message in the EDHOC protocol
    Napi::Value ProcessMessage1(const Napi::CallbackInfo &info);

    // Method to compose the second message in the EDHOC protocol
    Napi::Value ComposeMessage2(const Napi::CallbackInfo &info);

    // Method to process the second message in the EDHOC protocol
    Napi::Value ProcessMessage2(const Napi::CallbackInfo &info);

    // Method to compose the third message in the EDHOC protocol
    Napi::Value ComposeMessage3(const Napi::CallbackInfo &info);

    // Method to process the third message in the EDHOC protocol
    Napi::Value ProcessMessage3(const Napi::CallbackInfo &info);

    // Method to compose the fourth message in the EDHOC protocol
    Napi::Value ComposeMessage4(const Napi::CallbackInfo &info);

    // Method to process the fourth message in the EDHOC protocol
    Napi::Value ProcessMessage4(const Napi::CallbackInfo &info);

    // Method to export the EDHOC library functions to JavaScript
    Napi::Value ExportOSCORE(const Napi::CallbackInfo &info);

    // Static method to initialize the class within the N-API framework and expose it to JavaScript
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

private:
    struct edhoc_context _context;

    // Private member variables to hold instances of EDHOC managers for cryptographic operations, EAD, and credentials
    std::shared_ptr<UserContext> userContext;

    // Structure to manage connection identifiers within EDHOC
    struct edhoc_connection_id _cid;

    // Enum to specify the method (e.g., symmetric/asymmetric) used in EDHOC
    enum edhoc_method _method;

    // N-API reference to the logger function
    Napi::FunctionReference logger;

    // Static method to log messages from the EDHOC library
    static void Logger(void *user_context, const char *name, const uint8_t *buffer, size_t buffer_length);

    // Method to compose EDHOC messages
    Napi::Value ComposeMessage(const Napi::CallbackInfo &info, enum edhoc_message message);
    
    // Method to process the EDHOC messages
    Napi::Value ProcessMessage(const Napi::CallbackInfo &info, enum edhoc_message message);
};

#endif // LIB_EDHOC_H
