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

// Handles write-initiate requests.

#include "crypto.h"
#include "keys.h"
#include "messages.h"
#include "participant.h"
#include "participant_channel.h"
#include "register_operations.h"
#include "register_validation.h"
#include "register_write.h"
#include "spsec_common.h"
#include "spsec_mapping.h"
#include "spsec_registers.h"

static const char *logger_name_ptr = "register_write_init";

spsec_ret_t
register_process_write_initiate(Participant *participant_ptr,
                                SPsecWriteInitiateMessage *msg_ptr) {
  if (!participant_ptr || !msg_ptr) {
    LOG_ERROR(logger_name_ptr,
              "Invalid arguments: participant_ptr or msg_ptr is NULL");
    return SPSEC_ERROR_INVALID_ARGUMENT;
  }

  if (msg_ptr->participant_id != participant_ptr->participant_id) {
    LOG_ERROR(
        logger_name_ptr,
        "Received write initiate request for wrong participant_ptr id: %u, "
        "our participant_id: %u",
        msg_ptr->participant_id, participant_ptr->participant_id);
    return 1;
  }

  participant_ptr->session.cnt++;

  uint8_t *nonce_ptr = NULL;
  spsec_ret_t ret = participant_generate_nonce(participant_ptr, &nonce_ptr);
  LOG_SECRET(logger_name_ptr, "Generated register_process_write_initiate nonce_ptr:", nonce_ptr,
            REQUIRED_NONCE_LEN);
  if (ret != SPSEC_SUCCESS) {
    participant_ptr->session.cnt--;
    if (nonce_ptr)
      free(nonce_ptr);
    return ret;
  }

  ret = setup_crypto_context(participant_ptr, nonce_ptr, REQUIRED_NONCE_LEN,
                             participant_ptr->session.key, AUTH_TAG_SIZE);
  if (ret != SPSEC_SUCCESS) {
    participant_ptr->session.cnt--;
    if (nonce_ptr)
      free(nonce_ptr);
    return ret;
  }

  uint8_t *assoc_data_ptr = (uint8_t *)&msg_ptr->address;
  ret = decrypt_message(participant_ptr, msg_ptr->ciphertext,
                        sizeof(msg_ptr->ciphertext), msg_ptr->auth_tag,
                        msg_ptr->plaintext, assoc_data_ptr, 4);
  if (nonce_ptr)
    free(nonce_ptr);
  if (ret != SPSEC_SUCCESS) {
    participant_ptr->session.cnt--;
    participant_report_security_event(participant_ptr,
                                      SPSEC_SESS_KEY_AUTH_FAILURE);
    LOG_ERROR(
        logger_name_ptr,
        "Failed to decrypt write initiate request for participant_ptr %u, "
        "address: %08x",
        msg_ptr->participant_id, msg_ptr->address);
    return ret;
  }

  ret = spsecwriteinitiatemessage_parse_plaintext(msg_ptr);
  if (ret < 0) {
    LOG_ERROR(logger_name_ptr,
              "Failed to parse write initiate request for participant_ptr %u",
              msg_ptr->participant_id);
    return SPSEC_ERROR_PROTOCOL_INVALID_MESSAGE;
  }

  LOG_INFO(logger_name_ptr,
           "Write initiate request parsed successfully for participant_ptr %u, "
           "reg: 0x%02x, len: %u, address: %08x",
           msg_ptr->participant_id, msg_ptr->reg, msg_ptr->len,
           msg_ptr->address);
  return SPSEC_SUCCESS;
}

spsec_ret_t register_check_write_status(Participant *participant_ptr,
                                        uint8_t reg, uint32_t len) {
  spsec_ret_t access_ret = register_check_access(participant_ptr, reg, true);
  if (access_ret != SPSEC_SUCCESS) {
    return access_ret;
  }

  uint32_t expected_len = 0;
  if (!spsec_is_known_register(reg, &expected_len)) {
    LOG_ERROR(logger_name_ptr, "Unknown register 0x%02x requested", reg);
    return SPSEC_ERROR_REGISTER_INVALID;
  }
  if (len != expected_len) {
    LOG_ERROR(logger_name_ptr,
              "Invalid length %u for register 0x%02x (expected %u)", len, reg,
              expected_len);
    return SPSEC_ERROR_REGISTER_INVALID_LENGTH;
  }
  if (reg == SPSEC_REG_CODE_UPDATE_FILE) {
    // Fresh multi-segment write: drop any leftover buffer from a prior upload
    // (e.g. one that was aborted or never completed) before accepting a new one.
    write_accum_reset(&participant_ptr->write_accum);
    participant_ptr->write_accum.expected = len;
    participant_ptr->write_accum.active = true;
  }
  participant_ptr->state_info.prepared_write_register = reg;
  LOG_INFO(logger_name_ptr, "Register 0x%02x length %u is valid", reg, len);
  return SPSEC_SUCCESS;
}

static spsec_ret_t
prepare_write_initiate_response(Participant *participant_ptr,
                                SPsecWriteInitiateMessage *msg_ptr,
                                SPsecWriteInitiateMessage **response_ptr) {
  *response_ptr = spsecwriteinitiatemessage_new(msg_ptr->participant_id,
                                            participant_ptr->session.cnt,
                                            msg_ptr->reg, msg_ptr->len);
  if (!*response_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to create write initiate response_ptr");
    return SPSEC_ERROR_OUT_OF_MEMORY;
  }
  set_write_initiate_response_address(*response_ptr);
  return SPSEC_SUCCESS;
}

spsec_ret_t
register_send_write_initiate_response(Participant *participant_ptr,
                                      SPsecWriteInitiateMessage *msg_ptr) {
  SPsecWriteInitiateMessage *response_ptr = NULL;
  uint8_t *nonce_ptr = NULL;
  spsec_ret_t ret = SPSEC_SUCCESS;

  ret = prepare_write_initiate_response(participant_ptr, msg_ptr, &response_ptr);
  if (ret != SPSEC_SUCCESS)
    return ret;

  ret = participant_generate_nonce(participant_ptr, &nonce_ptr);
  if (ret != SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr,
              "Failed to generate nonce_ptr for write initiate response_ptr");
    if (response_ptr)
      spsecwriteinitiatemessage_free(response_ptr);
    return ret;
  }
  LOG_SECRET(logger_name_ptr, "Write initiate response_ptr nonce_ptr:", nonce_ptr, REQUIRED_NONCE_LEN);

  ret = setup_crypto_context(participant_ptr, nonce_ptr, REQUIRED_NONCE_LEN,
                             participant_ptr->session.key, AUTH_TAG_SIZE);
  if (ret != SPSEC_SUCCESS) {
    if (response_ptr)
      spsecwriteinitiatemessage_free(response_ptr);
    if (nonce_ptr)
      free(nonce_ptr);
    return ret;
  }

  uint8_t *assoc_data_ptr = (uint8_t *)&response_ptr->address;
  ret = encrypt_message(participant_ptr, response_ptr->plaintext, 8,
                        response_ptr->ciphertext, response_ptr->auth_tag,
                        assoc_data_ptr, 4);
  if (ret != SPSEC_SUCCESS) {
    if (response_ptr)
      spsecwriteinitiatemessage_free(response_ptr);
    if (nonce_ptr)
      free(nonce_ptr);
    return ret;
  }

  LOG_SECRET(logger_name_ptr, "Write initiate response_ptr plaintext:", response_ptr->plaintext,
            sizeof(response_ptr->plaintext));
  LOG_SECRET(logger_name_ptr, "Write initiate response_ptr ciphertext:", response_ptr->ciphertext,
            sizeof(response_ptr->ciphertext));
  LOG_SECRET(logger_name_ptr, "Write initiate response_ptr auth tag:", response_ptr->auth_tag,
            AUTH_TAG_SIZE);

  ret = participant_channel_send_write_initiate_response(
      &participant_ptr->secure_channel, response_ptr);
  if (ret != SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr, "Failed to send write initiate response_ptr");
    if (response_ptr)
      spsecwriteinitiatemessage_free(response_ptr);
    if (nonce_ptr)
      free(nonce_ptr);
    return ret;
  }

  LOG_INFO(logger_name_ptr, "Write initiate response_ptr sent successfully");
  if (response_ptr)
    spsecwriteinitiatemessage_free(response_ptr);
  if (nonce_ptr)
    free(nonce_ptr);
  return SPSEC_SUCCESS;
}
