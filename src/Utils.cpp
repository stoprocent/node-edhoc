#include "Utils.h"

#include <condition_variable>
#include <cstring>
#include <mutex>
#include <thread>
#include <iostream>

static constexpr const char* kErrorInputValueMustBeANumberOrABuffer = "Input value must be a number or a buffer";

void Utils::EncodeInt64ToBuffer(int64_t value, uint8_t* buffer, size_t* length) {
  size_t idx = 0;
  if (value == 0) {
    buffer[idx++] = 0;
  } else {
    while (value != 0) {
      buffer[idx++] = value & 0xFF;
      value >>= 8;
    }
  }
  *length = idx;
}

struct edhoc_connection_id Utils::ConvertJsValueToEdhocCid(Napi::Value value) {
  struct edhoc_connection_id cid = {};
  if (value.IsNumber()) {
    int64_t numeric = value.As<Napi::Number>().Int64Value();
    if (numeric >= ONE_BYTE_CBOR_INT_MIN_VALUE && numeric <= ONE_BYTE_CBOR_INT_MAX_VALUE) {
      cid = {.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER, .int_value = (int8_t)numeric};
    } else {
      size_t length = 0;
      Utils::EncodeInt64ToBuffer(numeric, cid.bstr_value, &length);
      cid.encode_type = EDHOC_CID_TYPE_BYTE_STRING;
      cid.bstr_length = length;
    }
  } else if (value.IsBuffer()) {
    Napi::Buffer<uint8_t> buffer = value.As<Napi::Buffer<uint8_t>>();
    cid.encode_type = EDHOC_CID_TYPE_BYTE_STRING;
    cid.bstr_length = buffer.Length();
    memcpy(cid.bstr_value, buffer.Data(), cid.bstr_length);
  } else {
    throw Napi::TypeError::New(value.Env(), kErrorInputValueMustBeANumberOrABuffer);
  }
  return cid;
}

Napi::Value Utils::CreateJsValueFromEdhocCid(Napi::Env env, struct edhoc_connection_id value) {
  if (value.encode_type == EDHOC_CID_TYPE_ONE_BYTE_INTEGER) {
    return Napi::Number::New(env, value.int_value);
  } else if (value.encode_type == EDHOC_CID_TYPE_BYTE_STRING) {
    return Napi::Buffer<char>::Copy(env, (const char*)value.bstr_value, value.bstr_length);
  }
  return env.Null();
}
