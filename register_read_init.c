/*
 * Copyright (c) 2026
 *
 * Hochschule Offenburg, University of Applied Sciences
 * Institute for reliable Embedded Systems
 * and Communications Electronic (ivESK)
 *
 * This file is licensed as described in the "LICENSE" file
 * included within the root folder of this work.
 */

// Handles read-initiate requests and sends the responses.

#include "crypto.h"
#include "keys.h"
#include "messages.h"
#include "participant.h"
#include "participant_channel.h"
#include "participant_storage.h"
#include "register_operations.h"
#include "register_read.h"
#include "register_validation.h"
#include "spsec_common.h"
#include "spsec_registers.h"

static const char *logger_name_ptr = "register_read_init";

spsec_ret_t register_process_read_initiate(Participant *participant_ptr,
                                           SPsecReadInitiateMessage *msg_ptr,
                                           uint8_t *read_register_ptr,
                                           uint32_t *real_len_ptr) {
  if (msg_ptr->participant_id != participant_ptr->participant_id) {
    LOG_ERROR(logger_name_ptr,
              "Read Initiate for other participant_ptr ID: %u (our "
              "participant_id %u)",
              msg_ptr->participant_id, participant_ptr->participant_id);
    return 1;
  }

  participant_ptr->session.cnt++;

  uint8_t *nonce_ptr = NULL;
  spsec_ret_t ret = participant_generate_nonce(participant_ptr, &nonce_ptr);
  LOG_SECRET(logger_name_ptr, "Generated register_process_read_initiate nonce_ptr:", nonce_ptr,
            REQUIRED_NONCE_LEN);
  if (ret != SPSEC_SUCCESS) {
    participant_ptr->session.cnt--;
    free(nonce_ptr);
    return ret;
  }

  ret = setup_crypto_context(participant_ptr, nonce_ptr, REQUIRED_NONCE_LEN,
                             participant_ptr->session.key, AUTH_TAG_SIZE);
  if (ret != SPSEC_SUCCESS) {
    participant_ptr->session.cnt--;
    free(nonce_ptr);
    return ret;
  }

  uint8_t *assoc_data_ptr = (uint8_t *)&msg_ptr->address;
  ret = decrypt_message(participant_ptr, msg_ptr->ciphertext,
                        sizeof(msg_ptr->ciphertext), msg_ptr->auth_tag,
                        msg_ptr->plaintext, assoc_data_ptr, 4);
  free(nonce_ptr);
  if (ret != SPSEC_SUCCESS) {
    participant_ptr->session.cnt--;
    participant_report_security_event(participant_ptr,
                                      SPSEC_SESS_KEY_AUTH_FAILURE);
    LOG_ERROR(logger_name_ptr, "Failed to decrypt message content");
    return ret;
  }

  spsecreadinitiatemessage_parse_plaintext(msg_ptr);
  LOG_INFO(logger_name_ptr, "Read Initiate message for register: %u and length: %u",
           msg_ptr->reg, msg_ptr->len);

  // Check register access permissions (read-only check)
  ret = register_check_access(participant_ptr, msg_ptr->reg, false);
  if (ret != SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr, "Register 0x%02x access denied", msg_ptr->reg);
    return ret;
  }

  switch (msg_ptr->reg) {
  case SPSEC_REG_STATUS:
    LOG_INFO(logger_name_ptr, "Read Initiate for SPsec Status (50h)");
    *read_register_ptr = msg_ptr->reg;
    *real_len_ptr = 1;
    break;
  case SPSEC_REG_LAST_SECURITY_EVENT:
    LOG_INFO(logger_name_ptr, "Read Initiate for Last Security Event (51h)");
    *read_register_ptr = msg_ptr->reg;
    *real_len_ptr = 2;
    break;
  case SPSEC_REG_PROVISIONING_KEY_ID:
    LOG_INFO(logger_name_ptr, "Read Initiate for Provisioning Key ID");
    if (participant_ptr->comm_keys.spsec_keys[1]) {
      *real_len_ptr = sizeof(participant_ptr->comm_keys.spsec_keys[1]->key_id);
    } else {
      uint32_t key_id;
      if (participant_storage_get_key_id(participant_ptr, 1, &key_id) == 0) {
        *real_len_ptr = sizeof(uint32_t);
      } else {
        LOG_ERROR(logger_name_ptr, "Provisioning key not initialized in RAM or storage");
        return SPSEC_ERROR_NOT_INITIALIZED;
      }
    }
    *read_register_ptr = msg_ptr->reg;
    break;
  case SPSEC_REG_INTEGRATOR_KEY_ID:
    LOG_INFO(logger_name_ptr, "Read Initiate for Integrator Key ID");
    if (participant_ptr->comm_keys.spsec_keys[2]) {
      *real_len_ptr = sizeof(participant_ptr->comm_keys.spsec_keys[2]->key_id);
    } else {
      uint32_t key_id;
      if (participant_storage_get_key_id(participant_ptr, 2, &key_id) == 0) {
        *real_len_ptr = sizeof(uint32_t);
      } else {
        LOG_ERROR(logger_name_ptr, "Integrator key not initialized in RAM or storage");
        return SPSEC_ERROR_NOT_INITIALIZED;
      }
    }
    *read_register_ptr = msg_ptr->reg;
    break;
  case SPSEC_REG_SEED_KEY_ID:
    LOG_INFO(logger_name_ptr, "Read Initiate for Seed Key ID");
    if (participant_ptr->comm_keys.spsec_keys[3]) {
      *real_len_ptr = sizeof(participant_ptr->comm_keys.spsec_keys[3]->key_id);
    } else {
      uint32_t key_id;
      if (participant_storage_get_key_id(participant_ptr, 3, &key_id) == 0) {
        *real_len_ptr = sizeof(uint32_t);
      } else {
        LOG_ERROR(logger_name_ptr, "Seed key not initialized in RAM or storage");
        return SPSEC_ERROR_NOT_INITIALIZED;
      }
    }
    *read_register_ptr = msg_ptr->reg;
    break;
  case SPSEC_REG_SECURE_HEARTBEAT_TIMING:
    LOG_INFO(logger_name_ptr, "Read Initiate for Heartbeat Timing");
    *read_register_ptr = msg_ptr->reg;
    *real_len_ptr = 1;
    break;
  case SPSEC_REG_SECURE_HEARTBEAT_MONITOR:
    LOG_INFO(logger_name_ptr, "Read Initiate for Heartbeat Monitor");
    *read_register_ptr = msg_ptr->reg;
    *real_len_ptr = 4;
    break;
  case SPSEC_REG_CORE_VERSION_INFO:
    LOG_INFO(logger_name_ptr, "Read Initiate for Core Version Info (58h)");
    *read_register_ptr = msg_ptr->reg;
    *real_len_ptr =
        (uint32_t)strlen(participant_ptr->device_info.core_version_info);
    break;
  case SPSEC_REG_MAPPING_VERSION_INFO:
    LOG_INFO(logger_name_ptr, "Read Initiate for Mapping Version Info (59h)");
    *read_register_ptr = msg_ptr->reg;
    *real_len_ptr =
        (uint32_t)strlen(participant_ptr->device_info.mapping_version_info);
    break;
  case SPSEC_REG_DEVICE_IDENTIFICATION:
    LOG_INFO(logger_name_ptr, "Read Initiate for Device Identification (81h)");
    *read_register_ptr = msg_ptr->reg;
    *real_len_ptr =
        (uint32_t)strlen(participant_ptr->device_info.device_identification);
    break;
  case SPSEC_REG_MCU_SERIAL_NUMBER:
    LOG_INFO(logger_name_ptr, "Read Initiate for MCU Serial Number (82h)");
    *read_register_ptr = msg_ptr->reg;
    *real_len_ptr = 16;
    break;
  case SPSEC_REG_CODE_UPDATE_CAPABILITIES:
    LOG_INFO(logger_name_ptr, "Read Initiate for Code Update Capabilities (90h)");
    *read_register_ptr = msg_ptr->reg;
    *real_len_ptr = 4;
    break;
  case SPSEC_REG_PUBLIC_AUTH_KEY:
    LOG_INFO(logger_name_ptr, "Read Initiate for Public Authentication Key (91h)");
    *read_register_ptr = msg_ptr->reg;
    *real_len_ptr = KEY_LEN;
    break;
  case SPSEC_REG_PARTICIPANT_ID:
    LOG_INFO(logger_name_ptr, "Read Initiate for Participant ID (60h)");
    *read_register_ptr = msg_ptr->reg;
    *real_len_ptr = 1;
    break;
  case SPSEC_REG_SYNC_ROLE_ACTIVATION:
    LOG_INFO(logger_name_ptr, "Read Initiate for Sync Role Activation (63h)");
    *read_register_ptr = msg_ptr->reg;
    *real_len_ptr = 1;
    break;
  default:
    LOG_ERROR(logger_name_ptr, "Unknown register id: %u", msg_ptr->reg);
    return SPSEC_ERROR_REGISTER_INVALID;
  }
  return SPSEC_SUCCESS;
}

static spsec_ret_t
prepare_read_initiate_response(Participant *participant_ptr,
                               uint8_t read_register_ptr, uint32_t real_len_ptr,
                               SPsecReadInitiateMessage **response_ptr) {
  *response_ptr = spsecreadinitiatemessage_new(participant_ptr->participant_id,
                                           participant_ptr->session.cnt,
                                           read_register_ptr, real_len_ptr);
  if (!*response_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to create read initiate response_ptr");
    return SPSEC_ERROR_OUT_OF_MEMORY;
  }
  set_read_initiate_response_address(*response_ptr);
  return SPSEC_SUCCESS;
}

spsec_ret_t register_send_read_initiate_response(Participant *participant_ptr,
                                                 uint8_t *read_register_ptr,
                                                 uint32_t *real_len_ptr) {
  SPsecReadInitiateMessage *response_ptr = NULL;
  uint8_t *nonce_ptr = NULL;
  spsec_ret_t ret = SPSEC_SUCCESS;

  ret = prepare_read_initiate_response(participant_ptr, *read_register_ptr,
                                       *real_len_ptr, &response_ptr);
  if (ret != SPSEC_SUCCESS)
    return ret;

  ret = participant_generate_nonce(participant_ptr, &nonce_ptr);
  LOG_SECRET(logger_name_ptr, "Read initiate response_ptr nonce_ptr:", nonce_ptr, REQUIRED_NONCE_LEN);
  if (ret != SPSEC_SUCCESS) {
    if (response_ptr)
      spsecreadinitiatemessage_free(response_ptr);
    if (nonce_ptr)
      free(nonce_ptr);
    return ret;
  }

  ret = setup_crypto_context(participant_ptr, nonce_ptr, REQUIRED_NONCE_LEN,
                             participant_ptr->session.key, AUTH_TAG_SIZE);
  if (ret != SPSEC_SUCCESS) {
    if (response_ptr)
      spsecreadinitiatemessage_free(response_ptr);
    if (nonce_ptr)
      free(nonce_ptr);
    return ret;
  }

  uint8_t *assoc_data_ptr = (uint8_t *)&response_ptr->address;
  ret = encrypt_message(
      participant_ptr, response_ptr->plaintext, sizeof(response_ptr->plaintext),
      response_ptr->ciphertext, response_ptr->auth_tag, assoc_data_ptr, 4);
  if (ret != SPSEC_SUCCESS) {
    if (response_ptr)
      spsecreadinitiatemessage_free(response_ptr);
    if (nonce_ptr)
      free(nonce_ptr);
    return ret;
  }

  ret = participant_channel_send_read_initiate_response(
      &participant_ptr->secure_channel, response_ptr);
  if (ret != SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr, "Failed to send read initiate response_ptr");
    if (response_ptr)
      spsecreadinitiatemessage_free(response_ptr);
    if (nonce_ptr)
      free(nonce_ptr);
    return ret;
  }

  LOG_INFO(logger_name_ptr, "Read initiate response_ptr sent successfully");
  if (response_ptr)
    spsecreadinitiatemessage_free(response_ptr);
  if (nonce_ptr)
    free(nonce_ptr);
  return SPSEC_SUCCESS;
}
