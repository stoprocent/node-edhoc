#ifndef UTILS_H
#define UTILS_H

#include <napi.h>
#include <cstdint>
#include <future>
#include <string>
#include <vector>

extern "C" {
#include "edhoc.h"
}

/**
 * @class Utils
 * @brief Utility functions for handling N-API resources and converting between
 * JavaScript and native types.
 *
 * The Utils class provides static utility functions for handling N-API
 * resources and converting between JavaScript and native types.
 */
class Utils {
 public:
  /**
   * Converts a JavaScript value to an EDHOC connection ID structure.
   * The input can be a number or a buffer.
   * Throws a JavaScript exception if the input is not a number or a buffer.
   *
   * @param value The N-API value representing the connection ID.
   * @return A structure representing the EDHOC connection ID.
   */
  static struct edhoc_connection_id ConvertJsValueToEdhocCid(Napi::Value value);

  /**
   * Creates a JavaScript value from an EDHOC connection ID structure.
   * Returns a number or a buffer based on the type of connection ID.
   *
   * @param env The N-API environment handle.
   * @param value The EDHOC connection ID structure.
   * @return A N-API value representing the connection ID.
   */
  static Napi::Value CreateJsValueFromEdhocCid(Napi::Env env, struct edhoc_connection_id value);

  /**
   * Converts a JavaScript number to a strongly typed enum.
   * Throws a JavaScript exception if the input is not a number.
   *
   * @param value The N-API value expected to be a number.
   * @return The enum value cast from the input number.
   */
  template <typename EnumType>
  static EnumType ConvertToEnum(const Napi::Value& value) {
    if (!value.IsNumber()) {
      throw Napi::TypeError::New(value.Env(), "Input value must be a number");
    }
    return static_cast<EnumType>(value.As<Napi::Number>().Int32Value());
  }

  /**
   * Encodes a uint64_t value into a buffer in little-endian format.
   * Writes a single zero byte if the value is zero.
   *
   * @param value The uint64_t value to encode.
   * @param buffer Pointer to the buffer where the encoded bytes will be stored.
   * @param length Pointer to a size_t variable where the length of the encoded
   * data will be stored.
   */
  static void EncodeInt64ToBuffer(int64_t value, uint8_t* buffer, size_t* length);
};

#endif  // UTILS_H
