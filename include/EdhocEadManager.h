#ifndef EDHOC_EAD_MANAGER_H
#define EDHOC_EAD_MANAGER_H

#include <napi.h>
#include <map>
#include <vector>

extern "C" {
#include "edhoc.h"
}

/**
 * @brief Type definition for the EAD (External Authorization Data) map.
 */
using EadMap = std::map<int, std::vector<uint8_t>>;
using EadMapVector = std::vector<EadMap>;
using EadBufferMap = std::map<enum edhoc_message, EadMapVector>;

/**
 * @class EdhocEadManager
 * @brief Manages the storage and retrieval of EAD (External Authorization Data)
 * for different EDHOC messages.
 *
 * The EdhocEadManager class provides methods to store, retrieve, and clear EAD
 * for different EDHOC messages. It also includes static callback functions for
 * composing and processing EAD tokens.
 */
class EdhocEadManager {
 public:
  /**
   * @struct edhoc_ead
   * @brief Edhoc's bind structure for EAD operations.
   */
  struct edhoc_ead ead;

  /**
   * @brief Default constructor for the EdhocEadManager class.
   */
  EdhocEadManager();

  /**
   * @brief Destructor for the EdhocEadManager class.
   */
  ~EdhocEadManager();

  /**
   * @brief Stores the EAD for a specific EDHOC message and label.
   *
   * @param message The EDHOC message type.
   * @param label The label associated with the EAD.
   * @param ead The EAD data to be stored.
   */
  void StoreEad(enum edhoc_message message, int label, const std::vector<uint8_t>& ead);

  /**
   * @brief Stores the EAD for a specific EDHOC message using a Napi::Array.
   *
   * @param message The EDHOC message type.
   * @param eadArray The Napi::Array containing the EAD data to be stored.
   */
  void StoreEad(enum edhoc_message message, const Napi::Array& eadArray);

  /**
   * @brief Retrieves the EAD for a specific EDHOC message.
   *
   * @param message The EDHOC message type.
   * @return A constant pointer to the EadMapVector containing the EAD data for
   * the specified message.
   */
  const EadMapVector* GetEadByMessage(enum edhoc_message message) const;

  /**
   * @brief Retrieves the EAD for a specific EDHOC message as a Napi::Array.
   *
   * @param env The Napi::Env object.
   * @param message The EDHOC message type.
   * @return A Napi::Array containing the EAD data for the specified message.
   */
  Napi::Array GetEadByMessage(Napi::Env& env, enum edhoc_message message) const;

  /**
   * @brief Clears the EAD for a specific EDHOC message.
   *
   * @param message The EDHOC message type.
   */
  void ClearEadByMessage(enum edhoc_message message);

 private:
  EadBufferMap eadBuffers_;  ///< Map to store the EAD buffers for different
                             ///< EDHOC messages.

  /**
   * @brief Static callback function for composing an EAD token.
   *
   * @param user_context The user context.
   * @param message The EDHOC message type.
   * @param ead_token The EAD token structure to be composed.
   * @param ead_token_size The size of the EAD token structure.
   * @param ead_token_len The length of the composed EAD token.
   * @return The status of the compose operation.
   */
  static int ComposeEad(void* user_context,
                        enum edhoc_message message,
                        struct edhoc_ead_token* ead_token,
                        size_t ead_token_size,
                        size_t* ead_token_len);

  /**
   * @brief Static callback function for processing an EAD token.
   *
   * @param user_context The user context.
   * @param message The EDHOC message type.
   * @param ead_token The EAD token structure to be processed.
   * @param ead_token_size The size of the EAD token structure.
   * @return The status of the process operation.
   */
  static int ProcessEad(void* user_context,
                        enum edhoc_message message,
                        const struct edhoc_ead_token* ead_token,
                        size_t ead_token_size);

  /**
   * @brief Calls the static ComposeEad callback function.
   *
   * @param message The EDHOC message type.
   * @param ead_token The EAD token structure to be composed.
   * @param ead_token_size The size of the EAD token structure.
   * @param ead_token_len The length of the composed EAD token.
   * @return The status of the compose operation.
   */
  int callComposeEad(enum edhoc_message message,
                     struct edhoc_ead_token* ead_token,
                     size_t ead_token_size,
                     size_t* ead_token_len);

  /**
   * @brief Calls the static ProcessEad callback function.
   *
   * @param message The EDHOC message type.
   * @param ead_token The EAD token structure to be processed.
   * @param ead_token_size The size of the EAD token structure.
   * @return The status of the process operation.
   */
  int callProcessEad(enum edhoc_message message, const struct edhoc_ead_token* ead_token, size_t ead_token_size);
};

#endif  // EDHOC_EAD_MANAGER_H
