#ifndef LIB_EDHOC_H
#define LIB_EDHOC_H

#include <napi.h>  // Include the N-API headers to interact with Node.js
#include "UserContext.h"  // Include the interface for user context
#include "TaskQueue.h"  // Include the task queue for asynchronous operations

extern "C" {
    #include "edhoc.h"  // Include EDHOC protocol C headers necessary for cryptographic operations
}

// Define the LibEDHOC class that extends Napi::ObjectWrap to enable wrapping with N-API functionalities,
// and implements UserContext for user-specific context handling in EDHOC operations
class LibEDHOC : public Napi::ObjectWrap<LibEDHOC> {
public:
    // Constructor that takes N-API callback info object which includes arguments passed from JS
    LibEDHOC(const Napi::CallbackInfo& info);

    // Virtual destructor to clean up resources upon object destruction
    ~LibEDHOC();

    // Retrieves the Connection ID from the EDHOC context as a N-API value
    Napi::Value GetCID(const Napi::CallbackInfo &info);

    // Sets the Connection ID in the EDHOC context from a N-API value
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

    // Private member variable to hold the task queue for asynchronous operations
    std::shared_ptr<TaskQueue> taskQueue;

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
