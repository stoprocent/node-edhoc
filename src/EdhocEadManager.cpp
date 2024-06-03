#include <exception>
#include <future>
#include <iostream>
#include <stdexcept>

#include "EdhocEadManager.h"
#include "UserContext.h"
#include "Utils.h"

static constexpr const char* kErrorExpectedObject =
    "Expected an object as element in the input array";
static constexpr const char* kErrorExpectedLabelNumberAndValueBuffer =
    "Expected 'label' to be a number and 'value' to be a buffer in the input "
    "array";
static constexpr const char* kPropLabel = "label";
static constexpr const char* kPropValue = "value";

EdhocEadManager::EdhocEadManager() {
  ead.compose = ComposeEad;
  ead.process = ProcessEad;
}

EdhocEadManager::~EdhocEadManager() {
  eadBuffers.clear();
}

void EdhocEadManager::StoreEad(enum edhoc_message message,
                               int label,
                               const std::vector<uint8_t>& ead) {
  auto& vecOfMaps = eadBuffers[message];
  EadMap newMap;
  newMap[label] = ead;
  vecOfMaps.push_back(std::move(newMap));
}

void EdhocEadManager::StoreEad(enum edhoc_message message,
                               const Napi::Array& eadArray) {
  Napi::Env env = eadArray.Env();
  for (size_t i = 0; i < eadArray.Length(); i++) {
    Napi::Value element = eadArray.Get(i);
    if (!element.IsObject()) {
      throw Napi::TypeError::New(env, kErrorExpectedObject);
    }

    Napi::Object obj = element.As<Napi::Object>();
    Napi::Value labelValue = obj.Get(kPropLabel);
    Napi::Value bufferValue = obj.Get(kPropValue);

    if (!labelValue.IsNumber() || !bufferValue.IsBuffer()) {
      throw Napi::TypeError::New(env, kErrorExpectedLabelNumberAndValueBuffer);
    }

    int label = labelValue.As<Napi::Number>().Int32Value();
    Napi::Buffer<uint8_t> buffer = bufferValue.As<Napi::Buffer<uint8_t>>();

    std::vector<uint8_t> eadVector(buffer.Data(),
                                   buffer.Data() + buffer.Length());
    StoreEad(message, label, eadVector);
  }
}

const EadMapVector* EdhocEadManager::GetEadByMessage(
    enum edhoc_message message) const {
  auto it = eadBuffers.find(message);
  return it != eadBuffers.end() ? &it->second : nullptr;
}

Napi::Array EdhocEadManager::GetEadByMessage(Napi::Env& env,
                                             enum edhoc_message message) const {
  const EadMapVector* buffers = GetEadByMessage(message);
  if (!buffers) {
    return Napi::Array::New(env);
  }

  Napi::Array result = Napi::Array::New(env, buffers->size());
  size_t i = 0;
  for (auto const& map : *buffers) {
    Napi::Object obj = Napi::Object::New(env);
    for (auto const& [label, buffer] : map) {
      obj.Set(kPropLabel, Napi::Number::New(env, label));
      obj.Set(kPropValue,
              Napi::Buffer<uint8_t>::Copy(env, buffer.data(), buffer.size()));
    }
    result.Set(i++, obj);
  }

  return result;
}

void EdhocEadManager::ClearEadByMessage(enum edhoc_message message) {
  eadBuffers.erase(message);
}

int EdhocEadManager::ComposeEad(void* user_context,
                                enum edhoc_message message,
                                struct edhoc_ead_token* ead_token,
                                size_t ead_token_size,
                                size_t* ead_token_len) {
  UserContext* context = static_cast<UserContext*>(user_context);
  EdhocEadManager* manager = context->GetEadManager();
  return manager->callComposeEad(
      message, ead_token, ead_token_size, ead_token_len);
}

int EdhocEadManager::ProcessEad(void* user_context,
                                enum edhoc_message message,
                                const struct edhoc_ead_token* ead_token,
                                size_t ead_token_size) {
  UserContext* context = static_cast<UserContext*>(user_context);
  EdhocEadManager* manager = context->GetEadManager();
  return manager->callProcessEad(message, ead_token, ead_token_size);
}

int EdhocEadManager::callComposeEad(enum edhoc_message message,
                                    struct edhoc_ead_token* ead_token,
                                    size_t ead_token_size,
                                    size_t* ead_token_len) {
  const EadMapVector* eadBuffers = GetEadByMessage(message);
  if (!eadBuffers) {
    *ead_token_len = 0;
    return EDHOC_SUCCESS;
  }

  size_t count = 0;

  for (const auto& map : *eadBuffers) {
    for (const auto& [label, buffer] : map) {
      if (count >= ead_token_size) {
        break;
      }
      ead_token[count].label = label;
      ead_token[count].value = buffer.data();
      ead_token[count].value_len = buffer.size();
      count++;
    }
    if (count >= ead_token_size) {
      break;
    }
  }

  *ead_token_len = count;
  return EDHOC_SUCCESS;
}

int EdhocEadManager::callProcessEad(enum edhoc_message message,
                                    const struct edhoc_ead_token* ead_token,
                                    size_t ead_token_size) {
  for (size_t i = 0; i < ead_token_size; ++i) {
    const edhoc_ead_token& token = ead_token[i];
    std::vector<uint8_t> eadBuffer(token.value, token.value + token.value_len);

    StoreEad(message, token.label, eadBuffer);
  }

  return EDHOC_SUCCESS;
}
