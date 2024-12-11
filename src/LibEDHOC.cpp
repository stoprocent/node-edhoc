#include "LibEDHOC.h"

#include <iostream>
#include <thread>

#include "EdhocComposeAsyncWorker.h"
#include "EdhocExportOscoreAsyncWorker.h"
#include "EdhocKeyExporterAsyncWorker.h"
#include "EdhocKeyUpdateAsyncWorker.h"
#include "EdhocProcessAsyncWorker.h"
#include "Suites.h"
#include "Utils.h"

static constexpr const char* kErrorFailedToInitializeEdhocContext = "Failed to initialize EDHOC context.";
static constexpr const char* kErrorFailedToSetEdhocConnectionId = "Failed to set EDHOC Connection ID.";
static constexpr const char* kErrorFailedToSetEdhocMethod = "Failed to set EDHOC Method.";
static constexpr const char* kErrorArraySuiteIndexesExpected = "Array of suite indexes expected";
static constexpr const char* kErrorArrayMethodIndexesExpected = "Array of method indexes expected";
static constexpr const char* kErrorInvalidCipherSuiteIndex = "Invalid cipher suite index";
static constexpr const char* kErrorFailedToSetCipherSuites = "Failed to set cipher suites";
static constexpr const char* kErrorExpectedFirstArgumentToBeBuffer = "Expected first argument to be a Buffer";
static constexpr const char* kErrorExpectedArgumentToBeNumber = "Expected argument to be a number";
static constexpr const char* kErrorExpectedAFunction = "Expected a function";
static constexpr const char* kClassNameLibEDHOC = "EDHOC";
static constexpr const char* kMethodComposeMessage1 = "composeMessage1";
static constexpr const char* kMethodProcessMessage1 = "processMessage1";
static constexpr const char* kMethodComposeMessage2 = "composeMessage2";
static constexpr const char* kMethodProcessMessage2 = "processMessage2";
static constexpr const char* kMethodComposeMessage3 = "composeMessage3";
static constexpr const char* kMethodProcessMessage3 = "processMessage3";
static constexpr const char* kMethodComposeMessage4 = "composeMessage4";
static constexpr const char* kMethodProcessMessage4 = "processMessage4";
static constexpr const char* kMethodExportOSCORE = "exportOSCORE";
static constexpr const char* kMethodExportKey = "exportKey";
static constexpr const char* kMethodKeyUpdate = "keyUpdate";
static constexpr const char* kJsPropertyConnectionID = "connectionID";
static constexpr const char* kJsPropertyPeerConnectionID = "peerConnectionID";
static constexpr const char* kJsPropertyMethods = "methods";
static constexpr const char* kJsPropertySelectedMethod = "selectedMethod";
static constexpr const char* kJsPropertyCipherSuites = "cipherSuites";
static constexpr const char* kJsPropertySelectedCipherSuite = "selectedSuite";
static constexpr const char* kJsPropertyLogger = "logger";
static constexpr const char* kLogggerFunctionName = "Logger";

LibEDHOC::LibEDHOC(const Napi::CallbackInfo& info) : Napi::ObjectWrap<LibEDHOC>(info) {
  Napi::Env env = info.Env();
  Napi::HandleScope scope(env);

  // Initialize EDHOC context
  context = {};
  if (edhoc_context_init(&context) != EDHOC_SUCCESS) {
    throw Napi::TypeError::New(env, kErrorFailedToInitializeEdhocContext);
  }

  // Connection ID, Methods, and Suites
  SetCID(info, info[0]);
  SetMethods(info, info[1]);
  SetCipherSuites(info, info[2]);

  // Crypto Manager
  Napi::Object jsCryptoManager = info[4].As<Napi::Object>();
  auto cryptoManager = std::make_shared<EdhocCryptoManager>(jsCryptoManager);

  // Credentials
  Napi::Object jsCredentialManager = info[3].As<Napi::Object>();
  auto credentialManager = std::make_shared<EdhocCredentialManager>(jsCredentialManager);
  // EAD
  auto eadManager = std::make_shared<EdhocEadManager>();

  // Bind all managers
  if (edhoc_bind_keys(&context, &cryptoManager->keys) != EDHOC_SUCCESS ||
      edhoc_bind_crypto(&context, &cryptoManager->crypto) != EDHOC_SUCCESS ||
      edhoc_bind_credentials(&context, &credentialManager->credentials) != EDHOC_SUCCESS ||
      edhoc_bind_ead(&context, &eadManager->ead) != EDHOC_SUCCESS) {
    throw Napi::TypeError::New(env, kErrorFailedToInitializeEdhocContext);
  }

  // Logger
  context.logger = LibEDHOC::Logger;

  // User Context
  userContext = std::make_shared<UserContext>(cryptoManager, eadManager, credentialManager);
  userContext->parent = Reference<Napi::Object>::New(info.This().As<Napi::Object>());

  if (edhoc_set_user_context(&context, static_cast<void*>(userContext.get())) != EDHOC_SUCCESS) {
    throw Napi::TypeError::New(env, kErrorFailedToInitializeEdhocContext);
  }
}

LibEDHOC::~LibEDHOC() {
  userContext.reset();
  context = {};
}

Napi::Value LibEDHOC::GetCID(const Napi::CallbackInfo& info) {
  return Utils::CreateJsValueFromEdhocCid(info.Env(), cid);
}

void LibEDHOC::SetCID(const Napi::CallbackInfo& info, const Napi::Value& value) {
  cid = Utils::ConvertJsValueToEdhocCid(value);
  int result = edhoc_set_connection_id(&context, &cid);
  if (result != EDHOC_SUCCESS) {
    Napi::TypeError::New(info.Env(), kErrorFailedToSetEdhocConnectionId).ThrowAsJavaScriptException();
  }
}

Napi::Value LibEDHOC::GetPeerCID(const Napi::CallbackInfo& info) {
  return Utils::CreateJsValueFromEdhocCid(info.Env(), context.EDHOC_PRIVATE(peer_cid));
}

Napi::Value LibEDHOC::GetMethods(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::Array result = Napi::Array::New(env, context.EDHOC_PRIVATE(method_len));
  for (size_t i = 0; i < context.EDHOC_PRIVATE(method_len); i++) {
    result.Set(i, Napi::Number::New(env, context.EDHOC_PRIVATE(method)[i]));
  }
  return result;
}

void LibEDHOC::SetMethods(const Napi::CallbackInfo& info, const Napi::Value& value) {
  Napi::Env env = info.Env();

  if (!value.IsArray()) {
    throw Napi::TypeError::New(env, kErrorArrayMethodIndexesExpected);
  }

  const auto jsArray = value.As<Napi::Array>();
  std::vector<edhoc_method> methods;
  methods.reserve(jsArray.Length());

  for (uint32_t i = 0; i < jsArray.Length(); i++) {
    methods.push_back(static_cast<edhoc_method>(jsArray.Get(i).As<Napi::Number>().Int32Value()));
  }

  if (edhoc_set_methods(&context, methods.data(), methods.size()) != EDHOC_SUCCESS) {
    throw Napi::TypeError::New(env, kErrorFailedToSetEdhocMethod);
  }
}

Napi::Value LibEDHOC::GetSelectedMethod(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), context.EDHOC_PRIVATE(chosen_method));
}

void LibEDHOC::SetCipherSuites(const Napi::CallbackInfo& info, const Napi::Value& value) {
  Napi::Env env = info.Env();

  if (!value.IsArray()) {
    throw Napi::TypeError::New(env, kErrorArraySuiteIndexesExpected);
  }

  const auto jsArray = value.As<Napi::Array>();
  std::vector<edhoc_cipher_suite> selected_suites;
  selected_suites.reserve(jsArray.Length());

  for (uint32_t i = 0; i < jsArray.Length(); i++) {
    const uint32_t index = jsArray.Get(i).As<Napi::Number>().Uint32Value();

    if (index >= suite_pointers_count || suite_pointers[index] == nullptr) {
      throw Napi::RangeError::New(env, kErrorInvalidCipherSuiteIndex);
    }

    selected_suites.push_back(*suite_pointers[index]);
  }

  if (edhoc_set_cipher_suites(&context, selected_suites.data(), selected_suites.size()) != 0) {
    throw Napi::TypeError::New(env, kErrorFailedToSetCipherSuites);
  }
}

Napi::Value LibEDHOC::GetCipherSuites(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::Array result = Napi::Array::New(env, context.EDHOC_PRIVATE(csuite_len));
  for (size_t i = 0; i < context.EDHOC_PRIVATE(csuite_len); i++) {
    result.Set(i, Napi::Number::New(env, context.EDHOC_PRIVATE(csuite)[i].value));
  }
  return result;
}

Napi::Value LibEDHOC::GetSelectedCipherSuite(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::Number suite =
      Napi::Number::New(env, context.EDHOC_PRIVATE(csuite)[context.EDHOC_PRIVATE(chosen_csuite_idx)].value);
  return suite;
}

Napi::Value LibEDHOC::GetLogger(const Napi::CallbackInfo& info) {
  return logger.Value();
}

void LibEDHOC::SetLogger(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (!info[0].IsFunction()) {
    Napi::TypeError::New(info.Env(), kErrorExpectedAFunction).ThrowAsJavaScriptException();
  }
  Napi::Function jsCallback = info[0].As<Napi::Function>();
  logger = Napi::Persistent(jsCallback);
  userContext->logger = Napi::ThreadSafeFunction::New(info.Env(), jsCallback, kLogggerFunctionName, 0, 1);
}

void LibEDHOC::Logger(void* usercontext, const char* name, const uint8_t* buffer, size_t buffer_length) {
  auto* context = static_cast<UserContext*>(usercontext);
  if (!context || !context->logger) {
    return;
  }

  const std::vector<uint8_t> bufferCopy(buffer, buffer + buffer_length);

  context->logger.NonBlockingCall([name = std::string(name), bufferCopy](Napi::Env env, Napi::Function jsCallback) {
    jsCallback.Call(
        {Napi::String::New(env, name), Napi::Buffer<uint8_t>::Copy(env, bufferCopy.data(), bufferCopy.size())});
  });
}

Napi::Value LibEDHOC::ComposeMessage(const Napi::CallbackInfo& info, enum edhoc_message messageNumber) {
  Napi::Env env = info.Env();
  Napi::HandleScope scope(env);

  if (info[0].IsArray()) {
    try {
      userContext->GetEadManager()->StoreEad(messageNumber, info[0].As<Napi::Array>());
    } catch (const Napi::Error& e) {
      e.ThrowAsJavaScriptException();
      return env.Null();
    }
  }

  userContext->GetCredentialManager()->SetupAsyncFunctions();
  userContext->GetCryptoManager()->SetupAsyncFunctions();

  EdhocComposeAsyncWorker::CallbackType callback = [this, messageNumber](Napi::Env& env) {
    userContext->GetEadManager()->ClearEadByMessage(messageNumber);
    userContext->GetCredentialManager()->CleanupAsyncFunctions();
    userContext->GetCryptoManager()->CleanupAsyncFunctions();
  };

  EdhocComposeAsyncWorker* worker = new EdhocComposeAsyncWorker(env, context, messageNumber, callback);
  worker->Queue();

  return worker->GetPromise();
}

Napi::Value LibEDHOC::ProcessMessage(const Napi::CallbackInfo& info, enum edhoc_message messageNumber) {
  Napi::Env env = info.Env();
  Napi::HandleScope scope(env);

  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, kErrorExpectedFirstArgumentToBeBuffer).ThrowAsJavaScriptException();
    return env.Null();
  }
  Napi::Buffer<uint8_t> inputBuffer = info[0].As<Napi::Buffer<uint8_t>>();

  userContext->GetCredentialManager()->SetupAsyncFunctions();
  userContext->GetCryptoManager()->SetupAsyncFunctions();

  EdhocProcessAsyncWorker::CallbackType callback = [this, messageNumber](Napi::Env& env) {
    Napi::Array EADs = userContext->GetEadManager()->GetEadByMessage(env, messageNumber);
    userContext->GetEadManager()->ClearEadByMessage(messageNumber);
    userContext->GetCredentialManager()->CleanupAsyncFunctions();
    userContext->GetCryptoManager()->CleanupAsyncFunctions();
    return EADs;
  };

  EdhocProcessAsyncWorker* worker = new EdhocProcessAsyncWorker(env, context, messageNumber, inputBuffer, callback);
  worker->Queue();

  return worker->GetPromise();
}

Napi::Value LibEDHOC::ComposeMessage1(const Napi::CallbackInfo& info) {
  return ComposeMessage(info, EDHOC_MSG_1);
}

Napi::Value LibEDHOC::ProcessMessage1(const Napi::CallbackInfo& info) {
  return ProcessMessage(info, EDHOC_MSG_1);
}

Napi::Value LibEDHOC::ComposeMessage2(const Napi::CallbackInfo& info) {
  return ComposeMessage(info, EDHOC_MSG_2);
}

Napi::Value LibEDHOC::ProcessMessage2(const Napi::CallbackInfo& info) {
  return ProcessMessage(info, EDHOC_MSG_2);
}

Napi::Value LibEDHOC::ComposeMessage3(const Napi::CallbackInfo& info) {
  return ComposeMessage(info, EDHOC_MSG_3);
}

Napi::Value LibEDHOC::ProcessMessage3(const Napi::CallbackInfo& info) {
  return ProcessMessage(info, EDHOC_MSG_3);
}

Napi::Value LibEDHOC::ComposeMessage4(const Napi::CallbackInfo& info) {
  return ComposeMessage(info, EDHOC_MSG_4);
}

Napi::Value LibEDHOC::ProcessMessage4(const Napi::CallbackInfo& info) {
  return ProcessMessage(info, EDHOC_MSG_4);
}

Napi::Value LibEDHOC::ExportOSCORE(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::HandleScope scope(env);

  userContext->GetCredentialManager()->SetupAsyncFunctions();
  userContext->GetCryptoManager()->SetupAsyncFunctions();

  EdhocExportOscoreAsyncWorker::CallbackType callback = [this](Napi::Env& env) {
    userContext->GetCredentialManager()->CleanupAsyncFunctions();
    userContext->GetCryptoManager()->CleanupAsyncFunctions();
  };

  EdhocExportOscoreAsyncWorker* worker = new EdhocExportOscoreAsyncWorker(env, context, callback);
  worker->Queue();

  return worker->GetPromise();
}

Napi::Value LibEDHOC::ExportKey(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::HandleScope scope(env);

  if (info.Length() < 1 || !info[0].IsNumber()) {
    Napi::TypeError::New(env, kErrorExpectedArgumentToBeNumber).ThrowAsJavaScriptException();
    return env.Null();
  }

  if (info.Length() < 2 || !info[1].IsNumber()) {
    Napi::TypeError::New(env, kErrorExpectedArgumentToBeNumber).ThrowAsJavaScriptException();
    return env.Null();
  }

  uint16_t label = (uint16_t)info[0].As<Napi::Number>().Uint32Value();
  uint8_t desiredLength = (uint8_t)info[1].As<Napi::Number>().Uint32Value();

  userContext->GetCredentialManager()->SetupAsyncFunctions();
  userContext->GetCryptoManager()->SetupAsyncFunctions();

  EdhocKeyExporterAsyncWorker::CallbackType callback = [this](Napi::Env& env) {
    userContext->GetCredentialManager()->CleanupAsyncFunctions();
    userContext->GetCryptoManager()->CleanupAsyncFunctions();
  };

  EdhocKeyExporterAsyncWorker* worker = new EdhocKeyExporterAsyncWorker(env, context, label, desiredLength, callback);
  worker->Queue();

  return worker->GetPromise();
}

Napi::Value LibEDHOC::KeyUpdate(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::HandleScope scope(env);

  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, kErrorExpectedFirstArgumentToBeBuffer).ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Buffer<uint8_t> contextBuffer = info[0].As<Napi::Buffer<uint8_t>>();
  std::vector<uint8_t> contextBufferVector(contextBuffer.Data(), contextBuffer.Data() + contextBuffer.Length());

  userContext->GetCredentialManager()->SetupAsyncFunctions();
  userContext->GetCryptoManager()->SetupAsyncFunctions();

  EdhocKeyUpdateAsyncWorker::CallbackType callback = [this](Napi::Env& env) {
    userContext->GetCredentialManager()->CleanupAsyncFunctions();
    userContext->GetCryptoManager()->CleanupAsyncFunctions();
  };

  EdhocKeyUpdateAsyncWorker* worker = new EdhocKeyUpdateAsyncWorker(env, context, contextBufferVector, callback);
  worker->Queue();

  return worker->GetPromise();
}

Napi::Object LibEDHOC::Init(Napi::Env env, Napi::Object exports) {
  Napi::HandleScope scope(env);
  Napi::Function func =
      DefineClass(env, kClassNameLibEDHOC,
                  {
                      InstanceAccessor(kJsPropertyConnectionID, &LibEDHOC::GetCID, &LibEDHOC::SetCID),
                      InstanceAccessor<&LibEDHOC::GetPeerCID>(kJsPropertyPeerConnectionID),
                      InstanceAccessor(kJsPropertyMethods, &LibEDHOC::GetMethods, &LibEDHOC::SetMethods),
                      InstanceAccessor<&LibEDHOC::GetSelectedMethod>(kJsPropertySelectedMethod),
                      InstanceAccessor(kJsPropertyCipherSuites, &LibEDHOC::GetCipherSuites, &LibEDHOC::SetCipherSuites),
                      InstanceAccessor<&LibEDHOC::GetSelectedCipherSuite>(kJsPropertySelectedCipherSuite),
                      InstanceAccessor(kJsPropertyLogger, &LibEDHOC::GetLogger, &LibEDHOC::SetLogger),
                      InstanceMethod(kMethodComposeMessage1, &LibEDHOC::ComposeMessage1),
                      InstanceMethod(kMethodProcessMessage1, &LibEDHOC::ProcessMessage1),
                      InstanceMethod(kMethodComposeMessage2, &LibEDHOC::ComposeMessage2),
                      InstanceMethod(kMethodProcessMessage2, &LibEDHOC::ProcessMessage2),
                      InstanceMethod(kMethodComposeMessage3, &LibEDHOC::ComposeMessage3),
                      InstanceMethod(kMethodProcessMessage3, &LibEDHOC::ProcessMessage3),
                      InstanceMethod(kMethodComposeMessage4, &LibEDHOC::ComposeMessage4),
                      InstanceMethod(kMethodProcessMessage4, &LibEDHOC::ProcessMessage4),
                      InstanceMethod(kMethodExportOSCORE, &LibEDHOC::ExportOSCORE),
                      InstanceMethod(kMethodExportKey, &LibEDHOC::ExportKey),
                      InstanceMethod(kMethodKeyUpdate, &LibEDHOC::KeyUpdate),
                  });

  Napi::FunctionReference* constructor = new Napi::FunctionReference();
  *constructor = Napi::Persistent(func);
  env.SetInstanceData(constructor);

  exports.Set(kClassNameLibEDHOC, func);
  return exports;
}

NODE_API_NAMED_ADDON(addon, LibEDHOC);
