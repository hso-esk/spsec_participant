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

// Handles read-segment requests and sends the responses.

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
#include "device_info.h"

static const char *logger_name_ptr = "register_read_seg";

spsec_ret_t
register_check_read_segment_request(Participant *participant_ptr,
                                    SPsecClientReadSegmentRequest *msg_ptr) {
  if (msg_ptr->participant_id != participant_ptr->participant_id) {
    LOG_ERROR(
        logger_name_ptr,
        "Received read segment request for wrong participant_ptr id: %u, our "
        "participant_id: %u",
        msg_ptr->participant_id, participant_ptr->participant_id);
    return 1;
  }

  participant_ptr->session.cnt++;

  if ((uint8_t)(participant_ptr->session.cnt & 0xFF) != (uint8_t)msg_ptr->cnt) {
    LOG_WARNING(logger_name_ptr,
                "Shared counter LSB mismatch: peer=%u ours=%u (possible desync)",
                (unsigned)(msg_ptr->cnt & 0xFF),
                (unsigned)(participant_ptr->session.cnt & 0xFF));
    participant_ptr->state_info.last_event = SPSEC_SESS_KEY_AUTH_FAILURE;
  }

  uint8_t *nonce_ptr = NULL;
  spsec_ret_t ret = participant_generate_nonce(participant_ptr, &nonce_ptr);
  LOG_SECRET(logger_name_ptr, "Generated register_check_read_segment_request nonce_ptr:", nonce_ptr,
            REQUIRED_NONCE_LEN);
  if (ret != SPSEC_SUCCESS) {
    participant_ptr->session.cnt--;
    free(nonce_ptr);
    return ret;
  }

  uint8_t *assoc_data_ptr = (uint8_t *)&msg_ptr->address;
  uint8_t expected_auth_tag[AUTH_TAG_SIZE];

  LOG_SECRET(logger_name_ptr, "Session key for decryption:", participant_ptr->session.key,
            KEY_LEN);
  LOG_DEBUG_ARRAY(logger_name_ptr, "Assoc data for decryption:", assoc_data_ptr, 4);

  ret = setup_crypto_context_and_calculate_tag(
      &participant_ptr->crypto_handler, participant_ptr->session.key, nonce_ptr,
      REQUIRED_NONCE_LEN, assoc_data_ptr, 4, expected_auth_tag, AUTH_TAG_SIZE);
  free(nonce_ptr);
  if (ret != SPSEC_SUCCESS) {
    participant_ptr->session.cnt--;
    LOG_ERROR(logger_name_ptr, "Failed to calculate expected authentication tag");
    return ret;
  }

  if (spsec_ct_memcmp(msg_ptr->auth_tag, expected_auth_tag, AUTH_TAG_SIZE) !=
      0) {
    participant_ptr->session.cnt--;
    participant_report_security_event(participant_ptr,
                                      SPSEC_SESS_KEY_AUTH_FAILURE);
    LOG_ERROR(logger_name_ptr,
              "Authentication tag mismatch for read segment request");
    return SPSEC_ERROR_CRYPTO_AUTH;
  }

  LOG_INFO(logger_name_ptr, "Authentication tag match for read segment request");
  return SPSEC_SUCCESS;
}

spsec_ret_t register_prepare_read_segment_data(Participant *participant_ptr,
                                               uint8_t **data_bytes_ptr,
                                               uint32_t *data_len_ptr) {
  switch (participant_ptr->state_info.prepared_read_register) {
  case SPSEC_REG_STATUS:
    *data_len_ptr = 1;
    *data_bytes_ptr = (uint8_t *)malloc(*data_len_ptr);
    if (!*data_bytes_ptr) {
      return SPSEC_ERROR_OUT_OF_MEMORY;
    }
    (*data_bytes_ptr)[0] = participant_get_status_register(participant_ptr);
    break;
  case SPSEC_REG_LAST_SECURITY_EVENT:
    *data_len_ptr = 2;
    *data_bytes_ptr = (uint8_t *)malloc(*data_len_ptr);
    if (!*data_bytes_ptr)
      return SPSEC_ERROR_OUT_OF_MEMORY;
    (*data_bytes_ptr)[0] = (uint8_t)(participant_ptr->state_info.last_event & 0xFF);
    (*data_bytes_ptr)[1] =
        (uint8_t)((participant_ptr->state_info.last_event >> 8) & 0xFF);
    break;
  case SPSEC_REG_PROVISIONING_KEY_ID:
    *data_len_ptr = sizeof(uint32_t);
    *data_bytes_ptr = malloc(*data_len_ptr);
    if (!*data_bytes_ptr) {
      LOG_ERROR(logger_name_ptr, "Failed to allocate memory for key ID data");
      return SPSEC_ERROR_OUT_OF_MEMORY;
    }
    if (participant_ptr->comm_keys.spsec_keys[1]) {
      memcpy(*data_bytes_ptr, &participant_ptr->comm_keys.spsec_keys[1]->key_id, *data_len_ptr);
    } else {
      uint32_t key_id;
      if (participant_storage_get_key_id(participant_ptr, 1, &key_id) == 0) {
        memcpy(*data_bytes_ptr, &key_id, *data_len_ptr);
      } else {
        free(*data_bytes_ptr);
        LOG_ERROR(logger_name_ptr, "Provisioning key not initialized in RAM or storage");
        return SPSEC_ERROR_NOT_INITIALIZED;
      }
    }
    break;
  case SPSEC_REG_INTEGRATOR_KEY_ID:
    *data_len_ptr = sizeof(uint32_t);
    *data_bytes_ptr = malloc(*data_len_ptr);
    if (!*data_bytes_ptr) {
      LOG_ERROR(logger_name_ptr, "Failed to allocate memory for key ID data");
      return SPSEC_ERROR_OUT_OF_MEMORY;
    }
    if (participant_ptr->comm_keys.spsec_keys[2]) {
      memcpy(*data_bytes_ptr, &participant_ptr->comm_keys.spsec_keys[2]->key_id, *data_len_ptr);
    } else {
      uint32_t key_id;
      if (participant_storage_get_key_id(participant_ptr, 2, &key_id) == 0) {
        memcpy(*data_bytes_ptr, &key_id, *data_len_ptr);
      } else {
        free(*data_bytes_ptr);
        LOG_ERROR(logger_name_ptr, "Integrator key not initialized in RAM or storage");
        return SPSEC_ERROR_NOT_INITIALIZED;
      }
    }
    break;
  case SPSEC_REG_SEED_KEY_ID:
    *data_len_ptr = sizeof(uint32_t);
    *data_bytes_ptr = malloc(*data_len_ptr);
    if (!*data_bytes_ptr) {
      LOG_ERROR(logger_name_ptr, "Failed to allocate memory for key ID data");
      return SPSEC_ERROR_OUT_OF_MEMORY;
    }
    if (participant_ptr->comm_keys.spsec_keys[3]) {
      memcpy(*data_bytes_ptr, &participant_ptr->comm_keys.spsec_keys[3]->key_id, *data_len_ptr);
    } else {
      uint32_t key_id;
      if (participant_storage_get_key_id(participant_ptr, 3, &key_id) == 0) {
        memcpy(*data_bytes_ptr, &key_id, *data_len_ptr);
      } else {
        free(*data_bytes_ptr);
        LOG_ERROR(logger_name_ptr, "Seed key not initialized in RAM or storage");
        return SPSEC_ERROR_NOT_INITIALIZED;
      }
    }
    break;
  case SPSEC_REG_SECURE_HEARTBEAT_TIMING:
    *data_len_ptr = 1;
    *data_bytes_ptr = malloc(*data_len_ptr);
    if (!*data_bytes_ptr)
      return SPSEC_ERROR_OUT_OF_MEMORY;
    (*data_bytes_ptr)[0] = (uint8_t)participant_ptr->heartbeat.timing;
    break;
  case SPSEC_REG_SECURE_HEARTBEAT_MONITOR:
    *data_len_ptr = 4;
    *data_bytes_ptr = malloc(*data_len_ptr);
    if (!*data_bytes_ptr)
      return SPSEC_ERROR_OUT_OF_MEMORY;
    memcpy(*data_bytes_ptr, participant_ptr->heartbeat.monitor.participant_ids, 4);
    break;
  case SPSEC_REG_CORE_VERSION_INFO:
    *data_len_ptr =
        (uint32_t)strlen(participant_ptr->device_info.core_version_info);
    *data_bytes_ptr = (uint8_t *)malloc(*data_len_ptr);
    if (!*data_bytes_ptr)
      return SPSEC_ERROR_OUT_OF_MEMORY;
    memcpy(*data_bytes_ptr, participant_ptr->device_info.core_version_info,
           *data_len_ptr);
    break;
  case SPSEC_REG_MAPPING_VERSION_INFO:
    *data_len_ptr =
        (uint32_t)strlen(participant_ptr->device_info.mapping_version_info);
    *data_bytes_ptr = (uint8_t *)malloc(*data_len_ptr);
    if (!*data_bytes_ptr)
      return SPSEC_ERROR_OUT_OF_MEMORY;
    memcpy(*data_bytes_ptr, participant_ptr->device_info.mapping_version_info,
           *data_len_ptr);
    break;
  case SPSEC_REG_DEVICE_IDENTIFICATION: {
    size_t dev_id_len =
        strlen(participant_ptr->device_info.device_identification);
    if (dev_id_len == 0) {
      *data_len_ptr = 0;
      *data_bytes_ptr = NULL;
      LOG_INFO(logger_name_ptr,
               "Device Identification not set, returning empty string");
    } else {
      *data_len_ptr = (uint32_t)dev_id_len;
      *data_bytes_ptr = (uint8_t *)malloc(*data_len_ptr);
      if (!*data_bytes_ptr)
        return SPSEC_ERROR_OUT_OF_MEMORY;
      memcpy(*data_bytes_ptr, participant_ptr->device_info.device_identification,
             *data_len_ptr);
    }
  } break;
  case SPSEC_REG_MCU_SERIAL_NUMBER:
    *data_len_ptr = 16;
    *data_bytes_ptr = (uint8_t *)malloc(*data_len_ptr);
    if (!*data_bytes_ptr)
      return SPSEC_ERROR_OUT_OF_MEMORY;
    // Retrieve 128-bit hardware MCU serial number
    if (device_info_get_mcu_serial(*data_bytes_ptr) != 0) {
      memset(*data_bytes_ptr, 0, *data_len_ptr);
      LOG_WARNING(logger_name_ptr,
                  "MCU serial number unavailable - reporting 82h as zeros");
    }
    break;
  case SPSEC_REG_CODE_UPDATE_CAPABILITIES:
    *data_len_ptr = 4;
    *data_bytes_ptr = (uint8_t *)malloc(*data_len_ptr);
    if (!*data_bytes_ptr)
      return SPSEC_ERROR_OUT_OF_MEMORY;
    {
      uint32_t capabilities =
          participant_ptr->device_info.code_update_capabilities.raw;
      (*data_bytes_ptr)[0] = (uint8_t)(capabilities & 0xFF);
      (*data_bytes_ptr)[1] = (uint8_t)((capabilities >> 8) & 0xFF);
      (*data_bytes_ptr)[2] = (uint8_t)((capabilities >> 16) & 0xFF);
      (*data_bytes_ptr)[3] = (uint8_t)((capabilities >> 24) & 0xFF);
    }
    break;
  case SPSEC_REG_PUBLIC_AUTH_KEY:
    *data_len_ptr = KEY_LEN;
    *data_bytes_ptr = malloc(*data_len_ptr);
    if (!*data_bytes_ptr)
      return SPSEC_ERROR_OUT_OF_MEMORY;
    size_t key_size = *data_len_ptr;
    if (device_info_get_public_auth_key(*data_bytes_ptr, &key_size) != 0 ||
        key_size != KEY_LEN) {
      // Report zero if public auth key is not provisioned
      memset(*data_bytes_ptr, 0, *data_len_ptr);
      LOG_WARNING(logger_name_ptr,
                  "Public authentication key not provisioned - reporting 91h as "
                  "all zeros; code updates are refused");
    }
    break;
  case SPSEC_REG_PARTICIPANT_ID:
    *data_len_ptr = 1;
    *data_bytes_ptr = malloc(*data_len_ptr);
    if (!*data_bytes_ptr)
      return SPSEC_ERROR_OUT_OF_MEMORY;
    (*data_bytes_ptr)[0] = participant_ptr->participant_id;
    break;
  case SPSEC_REG_SYNC_ROLE_ACTIVATION:
    *data_len_ptr = 1;
    *data_bytes_ptr = malloc(*data_len_ptr);
    if (!*data_bytes_ptr)
      return SPSEC_ERROR_OUT_OF_MEMORY;
    (*data_bytes_ptr)[0] = participant_ptr->timesync.is_role_authority
                           ? SPSEC_SYNC_ROLE_ON
                           : SPSEC_SYNC_ROLE_OFF;
    break;
  default:
    LOG_ERROR(logger_name_ptr, "Unknown register id: %u",
              participant_ptr->state_info.prepared_read_register);
    return SPSEC_ERROR_REGISTER_INVALID;
  }
  return SPSEC_SUCCESS;
}

spsec_ret_t register_send_read_segment_response(Participant *participant_ptr) {
  if (!participant_ptr) {
    LOG_ERROR(logger_name_ptr, "Invalid argument: participant_ptr is NULL");
    return SPSEC_ERROR_INVALID_ARGUMENT;
  }

  uint8_t *data_bytes_ptr = NULL;
  uint32_t data_len_ptr = 0;
  SPsecServerReadSegmentResponse *response_ptr = NULL;
  uint8_t *nonce_ptr = NULL;
  spsec_ret_t ret = SPSEC_SUCCESS;

  ret = register_prepare_read_segment_data(participant_ptr, &data_bytes_ptr,
                                           &data_len_ptr);
  if (ret != SPSEC_SUCCESS)
    return ret;

  response_ptr = spsecreadsegmentresponse_new(participant_ptr->participant_id,
                                          participant_ptr->session.cnt,
                                          data_bytes_ptr, data_len_ptr);
  if (!response_ptr) {
    free(data_bytes_ptr);
    LOG_ERROR(logger_name_ptr, "Failed to create read segment response_ptr");
    return SPSEC_ERROR_OUT_OF_MEMORY;
  }

  // Allocate memory for ciphertext_ptr
  response_ptr->ciphertext_ptr = malloc(data_len_ptr);
  if (!response_ptr->ciphertext_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to allocate memory for ciphertext_ptr");
    if (response_ptr)
      spsecreadsegmentresponse_free(response_ptr);
    return SPSEC_ERROR_OUT_OF_MEMORY;
  }

  set_read_segment_response_address(response_ptr);

  ret = participant_generate_nonce(participant_ptr, &nonce_ptr);
  LOG_SECRET(logger_name_ptr, "Generated register_send_read_segment_response nonce_ptr:", nonce_ptr,
            REQUIRED_NONCE_LEN);
  if (ret != SPSEC_SUCCESS) {
    if (response_ptr)
      spsecreadsegmentresponse_free(response_ptr);
    if (nonce_ptr)
      free(nonce_ptr);
    return ret;
  }

  ret = setup_crypto_context(participant_ptr, nonce_ptr, REQUIRED_NONCE_LEN,
                             participant_ptr->session.key, AUTH_TAG_SIZE);
  if (ret != SPSEC_SUCCESS) {
    if (response_ptr)
      spsecreadsegmentresponse_free(response_ptr);
    if (nonce_ptr)
      free(nonce_ptr);
    return ret;
  }

  uint8_t *assoc_data_ptr = (uint8_t *)&response_ptr->address;
  ret = encrypt_message(participant_ptr, response_ptr->data_ptr, response_ptr->data_len,
                        response_ptr->ciphertext_ptr, response_ptr->auth_tag,
                        assoc_data_ptr, 4);
  if (ret != SPSEC_SUCCESS) {
    if (response_ptr)
      spsecreadsegmentresponse_free(response_ptr);
    if (nonce_ptr)
      free(nonce_ptr);
    return ret;
  }

  ret = participant_channel_send_read_segment_response(
      &participant_ptr->secure_channel, response_ptr);
  if (ret != SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr, "Failed to send read segment response_ptr");
    if (response_ptr)
      spsecreadsegmentresponse_free(response_ptr);
    if (nonce_ptr)
      free(nonce_ptr);
    return ret;
  }

  LOG_INFO(logger_name_ptr, "Read segment response_ptr sent successfully");
  if (response_ptr)
    spsecreadsegmentresponse_free(response_ptr);
  if (nonce_ptr)
    free(nonce_ptr);
  return ret;
}
