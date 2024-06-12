#include <iostream>
#include <future>
#include <exception>
#include <stdexcept>

#include "EdhocEADManager.h"
#include "UserContext.h"
#include "Utils.h"

EdhocEADManager::EdhocEADManager() {
    this->ead.compose = ComposeEAD;
    this->ead.process = ProcessEAD;
}

EdhocEADManager::~EdhocEADManager() {

}

void EdhocEADManager::StoreEADBuffer(enum edhoc_message message, int label, std::vector<uint8_t> ead) {
    auto& vecOfMaps = EadBuffers_[message];
    std::map<int, std::vector<uint8_t>> newMap;
    newMap[label] = ead;
    vecOfMaps.push_back(std::move(newMap));
}

const std::vector<std::map<int, std::vector<uint8_t>>>& EdhocEADManager::GetEADBuffersByMessage(enum edhoc_message message) {
    return EadBuffers_[message];
}

void EdhocEADManager::ClearEADBuffersByMessage(enum edhoc_message message) {
    EadBuffers_.erase(message);
}

int EdhocEADManager::ComposeEAD(void *user_context, enum edhoc_message message, struct edhoc_ead_token *ead_token, size_t ead_token_size, size_t *ead_token_len) {
    UserContext* context = static_cast<UserContext*>(user_context);
    EdhocEADManager* manager = context->GetEADManager();
    return manager->CallComposeEAD(message, ead_token, ead_token_size, ead_token_len);
}

int EdhocEADManager::ProcessEAD(void *user_context, enum edhoc_message message, const struct edhoc_ead_token *ead_token, size_t ead_token_size) {
    UserContext* context = static_cast<UserContext*>(user_context);
    EdhocEADManager* manager = context->GetEADManager();
    return manager->CallProcessEAD(message, ead_token, ead_token_size);
}

int EdhocEADManager::CallComposeEAD(enum edhoc_message message, struct edhoc_ead_token *ead_token, size_t ead_token_size, size_t *ead_token_len) {
    const std::vector<std::map<int, std::vector<uint8_t>>>& eadBuffers = GetEADBuffersByMessage(message);

    size_t count = 0;

    for (auto const& map : eadBuffers) {
        for (auto const& [label, buffer] : map) {
            if (count >= ead_token_size) {
                break;
            }
            ead_token[count].label = label;
            ead_token[count].value = buffer.data();
            ead_token[count].value_len = buffer.size();
            count++;
        }
    }

    *ead_token_len = count;

    return EDHOC_SUCCESS;
}

int EdhocEADManager::CallProcessEAD(enum edhoc_message message, const struct edhoc_ead_token *ead_token, size_t ead_token_size) {
    for (size_t i = 0; i < ead_token_size; ++i) {
        const edhoc_ead_token& token = ead_token[i];
        std::vector<uint8_t> eadBuffer(token.value, token.value + token.value_len);
        
        this->StoreEADBuffer(message, token.label, eadBuffer);
    }

    return EDHOC_SUCCESS;
}