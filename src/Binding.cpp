#include "Binding.h"

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

Edhoc::Edhoc(const Napi::CallbackInfo& info) : Napi::ObjectWrap<Edhoc>(info) {
  Napi::Env env = info.Env();
  Napi::HandleScope scope(env);

  // Get the JS object
  Napi::Object jsEdhoc = info.This().As<Napi::Object>();
  
  // Crypto Manager
  Napi::Object jsCryptoManager = info[4].As<Napi::Object>();
  this->cryptoManager_ = std::make_unique<EdhocCryptoManager>(jsCryptoManager, jsEdhoc);

  // Credentials
  Napi::Object jsCredentialManager = info[3].As<Napi::Object>();
  this->credentialManager_ = std::make_unique<EdhocCredentialManager>(jsCredentialManager, jsEdhoc);
  
  // EAD
  this->eadManager_ = std::make_unique<EdhocEadManager>();

  // Reset the EDHOC context
  this->Reset(info);

  // Connection ID, Methods, and Suites
  SetCID(info, info[0]);
  SetMethods(info, info[1]);
  SetCipherSuites(info, info[2]);
}

void Edhoc::Reset(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::HandleScope scope(env);

  bool isInitialized = edhocContext_ != nullptr;

  // Get the Connection ID, Methods, and Suites
  Napi::Value cid = env.Null();
  Napi::Value methods = env.Null();
  Napi::Value suites = env.Null();

  if (isInitialized) {
    cid = this->GetCID(info);
    methods = this->GetMethods(info);
    suites = this->GetCipherSuites(info);
  }

  // Initialize EDHOC context
  edhocContext_ = std::make_unique<edhoc_context>();

  if (edhoc_context_init(edhocContext_.get()) != EDHOC_SUCCESS) {
    Napi::TypeError::New(env, kErrorFailedToInitializeEdhocContext)
      .ThrowAsJavaScriptException();
  }

  // Bind all managers
  if (edhoc_bind_keys(edhocContext_.get(), &this->cryptoManager_.get()->keys) != EDHOC_SUCCESS ||
      edhoc_bind_crypto(edhocContext_.get(), &this->cryptoManager_.get()->crypto) != EDHOC_SUCCESS ||
      edhoc_bind_credentials(edhocContext_.get(), &this->credentialManager_.get()->credentials) != EDHOC_SUCCESS ||
      edhoc_bind_ead(edhocContext_.get(), &this->eadManager_.get()->ead) != EDHOC_SUCCESS) 
  {
    Napi::TypeError::New(env, kErrorFailedToInitializeEdhocContext)
      .ThrowAsJavaScriptException();
  }

  // If the previous context was initialized, copy the Connection ID, Methods, and Suites
  if (isInitialized) {
    this->SetCID(info, cid);
    this->SetMethods(info, methods);
    this->SetCipherSuites(info, suites);
  }

  // Logger
  edhocContext_->logger = Edhoc::Logger;
}

Edhoc::~Edhoc() {
  // Reset the EDHOC context
}

Napi::Value Edhoc::GetCID(const Napi::CallbackInfo& info) {
  return Utils::CreateJsValueFromEdhocCid(info.Env(), cid_);
}

void Edhoc::SetCID(const Napi::CallbackInfo& info, const Napi::Value& value) {
  cid_ = Utils::ConvertJsValueToEdhocCid(value);
  int result = edhoc_set_connection_id(edhocContext_.get(), &cid_);
  if (result != EDHOC_SUCCESS) {
    Napi::TypeError::New(info.Env(), kErrorFailedToSetEdhocConnectionId).ThrowAsJavaScriptException();
  }
}

Napi::Value Edhoc::GetPeerCID(const Napi::CallbackInfo& info) {
  return Utils::CreateJsValueFromEdhocCid(info.Env(), edhocContext_->EDHOC_PRIVATE(peer_cid));
}

Napi::Value Edhoc::GetMethods(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::Array result = Napi::Array::New(env, edhocContext_->EDHOC_PRIVATE(method_len));
  for (size_t i = 0; i < edhocContext_->EDHOC_PRIVATE(method_len); i++) {
    result.Set(i, Napi::Number::New(env, edhocContext_->EDHOC_PRIVATE(method)[i]));
  }
  return result;
}

void Edhoc::SetMethods(const Napi::CallbackInfo& info, const Napi::Value& value) {
  Napi::Env env = info.Env();

  if (!value.IsArray()) {
    Napi::TypeError::New(env, kErrorArrayMethodIndexesExpected)
      .ThrowAsJavaScriptException();
  }

  const auto jsArray = value.As<Napi::Array>();
  std::vector<edhoc_method> methods;
  methods.reserve(jsArray.Length());

  for (uint32_t i = 0; i < jsArray.Length(); i++) {
    methods.push_back(static_cast<edhoc_method>(jsArray.Get(i).As<Napi::Number>().Int32Value()));
  }
  
  int result = edhoc_set_methods(edhocContext_.get(), methods.data(), methods.size());
  if (result != EDHOC_SUCCESS) {
    Napi::TypeError::New(env, kErrorFailedToSetEdhocMethod)
      .ThrowAsJavaScriptException();
  }
}

Napi::Value Edhoc::GetSelectedMethod(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), edhocContext_->EDHOC_PRIVATE(chosen_method));
}

void Edhoc::SetCipherSuites(const Napi::CallbackInfo& info, const Napi::Value& value) {
  Napi::Env env = info.Env();

  if (!value.IsArray()) {
    Napi::TypeError::New(env, kErrorArraySuiteIndexesExpected)
      .ThrowAsJavaScriptException();
  }

  const auto jsArray = value.As<Napi::Array>();
  std::vector<edhoc_cipher_suite> selected_suites;
  selected_suites.reserve(jsArray.Length());

  for (uint32_t i = 0; i < jsArray.Length(); i++) {
    const uint32_t index = jsArray.Get(i).As<Napi::Number>().Uint32Value();

    if (index >= suite_pointers_count || suite_pointers[index] == nullptr) {
      Napi::RangeError::New(env, kErrorInvalidCipherSuiteIndex)
        .ThrowAsJavaScriptException();
    }

    selected_suites.push_back(*suite_pointers[index]);
  }

  if (edhoc_set_cipher_suites(edhocContext_.get(), selected_suites.data(), selected_suites.size()) != 0) {
    Napi::TypeError::New(env, kErrorFailedToSetCipherSuites)
      .ThrowAsJavaScriptException();
  }
}

Napi::Value Edhoc::GetCipherSuites(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::Array result = Napi::Array::New(env, edhocContext_->EDHOC_PRIVATE(csuite_len));
  for (size_t i = 0; i < edhocContext_->EDHOC_PRIVATE(csuite_len); i++) {
    result.Set(i, Napi::Number::New(env, edhocContext_->EDHOC_PRIVATE(csuite)[i].value));
  }
  return result;
}

Napi::Value Edhoc::GetSelectedCipherSuite(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::Number suite =
      Napi::Number::New(env, edhocContext_->EDHOC_PRIVATE(csuite)[edhocContext_->EDHOC_PRIVATE(chosen_csuite_idx)].value);
  return suite;
}

Napi::Value Edhoc::GetLogger(const Napi::CallbackInfo& info) {
  return logger_.Value();
}

void Edhoc::SetLogger(const Napi::CallbackInfo& info, const Napi::Value& value) {
  if (!info[0].IsFunction()) {
    Napi::TypeError::New(info.Env(), kErrorExpectedAFunction).ThrowAsJavaScriptException();
  }
  Napi::Function jsCallback = info[0].As<Napi::Function>();
  logger_ = Napi::Persistent(jsCallback);
}

void Edhoc::Logger(void* user_context, const char* name, const uint8_t* buffer, size_t buffer_length) {
  RunningContext* context = static_cast<RunningContext*>(const_cast<void*>(user_context));
  
  if (!context || !context->GetTsfn() || !context->GetLoggerRef()) {
    return;
  }

  const std::vector<uint8_t> bufferCopy(buffer, buffer + buffer_length);

  context->GetTsfn().NonBlockingCall(context, [name = std::string(name), bufferCopy](Napi::Env env, Napi::Function jsCallback, RunningContext* context) {
    Napi::HandleScope scope(env);
    try {
      context->GetLoggerRef().Value().As<Napi::Function>().Call({Napi::String::New(env, name), Napi::Buffer<uint8_t>::Copy(env, bufferCopy.data(), bufferCopy.size())});
    } catch (const Napi::Error& e) {
       // This is just a logger, so we don't want to throw an error
      std::cerr << "Error in Logger: " << e.Get("stack").ToString().Utf8Value() << std::endl;
    }
  });
}

void Edhoc::StartRunningContext(Napi::Env env) {
  // Initialize the running context
  this->runningContext_ = std::make_unique<RunningContext>(
    env, 
    edhocContext_.get(), 
    this->cryptoManager_.get(), 
    this->eadManager_.get(), 
    this->credentialManager_.get(), 
    logger_.Value()
  );

  // Set the user context of the EDHOC context
  if (edhoc_set_user_context(edhocContext_.get(), static_cast<void*>(this->runningContext_.get())) != EDHOC_SUCCESS) {
    Napi::TypeError::New(env, kErrorFailedToInitializeEdhocContext)
      .ThrowAsJavaScriptException();
  }
}

Napi::Value Edhoc::ComposeMessage(const Napi::CallbackInfo& info, enum edhoc_message messageNumber) {
  Napi::Env env = info.Env();
  Napi::HandleScope scope(env);

  // Check if the first argument (EADs) is an array
  if (info[0].IsArray()) {
    try {
      this->eadManager_->StoreEad(messageNumber, info[0].As<Napi::Array>());
    } catch (const Napi::Error& e) {
      e.ThrowAsJavaScriptException();
      return env.Null();
    }
  }

  // Start the running context
  this->StartRunningContext(env);

  // Compose the message
  EdhocComposeAsyncWorker* worker = new EdhocComposeAsyncWorker(this->runningContext_.get(), messageNumber);
  worker->Queue();

  // Return the promise of the running context
  return this->runningContext_->GetPromise();
}

Napi::Value Edhoc::ProcessMessage(const Napi::CallbackInfo& info, enum edhoc_message messageNumber) {
  Napi::Env env = info.Env();
  Napi::HandleScope scope(env);

  // Check if the first argument (input buffer) is a buffer
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, kErrorExpectedFirstArgumentToBeBuffer).ThrowAsJavaScriptException();
    return env.Null();
  }

  // Get the input buffer
  Napi::Buffer<uint8_t> inputBuffer = info[0].As<Napi::Buffer<uint8_t>>();

  // Start the running context
  this->StartRunningContext(env);

  // Process the message
  EdhocProcessAsyncWorker* worker = new EdhocProcessAsyncWorker(this->runningContext_.get(), messageNumber, inputBuffer);
  worker->Queue();

  // Return the promise of the running context
  return this->runningContext_->GetPromise();
}

Napi::Value Edhoc::ComposeMessage1(const Napi::CallbackInfo& info) {
  return ComposeMessage(info, EDHOC_MSG_1);
}

Napi::Value Edhoc::ProcessMessage1(const Napi::CallbackInfo& info) {
  return ProcessMessage(info, EDHOC_MSG_1);
}

Napi::Value Edhoc::ComposeMessage2(const Napi::CallbackInfo& info) {
  return ComposeMessage(info, EDHOC_MSG_2);
}

Napi::Value Edhoc::ProcessMessage2(const Napi::CallbackInfo& info) {
  return ProcessMessage(info, EDHOC_MSG_2);
}

Napi::Value Edhoc::ComposeMessage3(const Napi::CallbackInfo& info) {
  return ComposeMessage(info, EDHOC_MSG_3);
}

Napi::Value Edhoc::ProcessMessage3(const Napi::CallbackInfo& info) {
  return ProcessMessage(info, EDHOC_MSG_3);
}

Napi::Value Edhoc::ComposeMessage4(const Napi::CallbackInfo& info) {
  return ComposeMessage(info, EDHOC_MSG_4);
}

Napi::Value Edhoc::ProcessMessage4(const Napi::CallbackInfo& info) {
  return ProcessMessage(info, EDHOC_MSG_4);
}

Napi::Value Edhoc::ExportOSCORE(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::HandleScope scope(env);

  // Start the running context
  this->StartRunningContext(env);

  // Export the OSCORE
  EdhocExportOscoreAsyncWorker* worker = new EdhocExportOscoreAsyncWorker(this->runningContext_.get());
  worker->Queue();

  // Return the promise of the running context
  return this->runningContext_->GetPromise();
}

Napi::Value Edhoc::ExportKey(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::HandleScope scope(env);

  // Check if the first argument (label) is a number
  if (info.Length() < 1 || !info[0].IsNumber()) {
    Napi::TypeError::New(env, kErrorExpectedArgumentToBeNumber).ThrowAsJavaScriptException();
    return env.Null();
  }

  // Check if the second argument (desired length) is a number
  if (info.Length() < 2 || !info[1].IsNumber()) {
    Napi::TypeError::New(env, kErrorExpectedArgumentToBeNumber).ThrowAsJavaScriptException();
    return env.Null();
  }

  // Get the label and desired length
  uint16_t label = (uint16_t)info[0].As<Napi::Number>().Uint32Value();
  uint8_t desiredLength = (uint8_t)info[1].As<Napi::Number>().Uint32Value();

  // Start the running context
  this->StartRunningContext(env);

  // Export the key
  EdhocKeyExporterAsyncWorker* worker = new EdhocKeyExporterAsyncWorker(this->runningContext_.get(), label, desiredLength);
  worker->Queue();

  // Return the promise of the running context
  return this->runningContext_->GetPromise();
}

Napi::Value Edhoc::KeyUpdate(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::HandleScope scope(env);

  // Check if the first argument (context buffer) is a buffer
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, kErrorExpectedFirstArgumentToBeBuffer).ThrowAsJavaScriptException();
    return env.Null();
  }

  // Get the context buffer
  Napi::Buffer<uint8_t> contextBuffer = info[0].As<Napi::Buffer<uint8_t>>();
  std::vector<uint8_t> contextBufferVector(contextBuffer.Data(), contextBuffer.Data() + contextBuffer.Length());

  // Start the running context
  this->StartRunningContext(env);

  // Update the key
  EdhocKeyUpdateAsyncWorker* worker = new EdhocKeyUpdateAsyncWorker(this->runningContext_.get(), contextBufferVector);
  worker->Queue();

  // Return the promise of the running context
  return this->runningContext_->GetPromise();
}

Napi::Object Edhoc::Init(Napi::Env env, Napi::Object exports) {
  Napi::HandleScope scope(env);

  Napi::Function func = DefineClass(env, "EDHOC", {
    InstanceAccessor("connectionID", &Edhoc::GetCID, &Edhoc::SetCID),
    InstanceAccessor<&Edhoc::GetPeerCID>("peerConnectionID"),
    InstanceAccessor("methods", &Edhoc::GetMethods, &Edhoc::SetMethods),
    InstanceAccessor<&Edhoc::GetSelectedMethod>("selectedMethod"),
    InstanceAccessor("cipherSuites", &Edhoc::GetCipherSuites, &Edhoc::SetCipherSuites),
    InstanceAccessor<&Edhoc::GetSelectedCipherSuite>("selectedSuite"),
    InstanceAccessor("logger", &Edhoc::GetLogger, &Edhoc::SetLogger),
    InstanceMethod("reset", &Edhoc::Reset),
    InstanceMethod("composeMessage1", &Edhoc::ComposeMessage1),
    InstanceMethod("processMessage1", &Edhoc::ProcessMessage1),
    InstanceMethod("composeMessage2", &Edhoc::ComposeMessage2),
    InstanceMethod("processMessage2", &Edhoc::ProcessMessage2),
    InstanceMethod("composeMessage3", &Edhoc::ComposeMessage3),
    InstanceMethod("processMessage3", &Edhoc::ProcessMessage3),
    InstanceMethod("composeMessage4", &Edhoc::ComposeMessage4),
    InstanceMethod("processMessage4", &Edhoc::ProcessMessage4),
    InstanceMethod("exportOSCORE", &Edhoc::ExportOSCORE),
    InstanceMethod("exportKey", &Edhoc::ExportKey),
    InstanceMethod("keyUpdate", &Edhoc::KeyUpdate),
  });

  Napi::FunctionReference* constructor = new Napi::FunctionReference();
  *constructor = Napi::Persistent(func);
  env.SetInstanceData(constructor);

  exports.Set("EDHOC", func);
  return exports;
}

NODE_API_NAMED_ADDON(addon, Edhoc);
