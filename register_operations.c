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

#include "nvol_storage.h"
#include "participant.h"
#include "spsec_common.h"

#include "keys.h"
#include "participant_channel.h"
#include "register_operations.h"
#include "spsec_mapping.h"
#include "spsec_registers.h"
#include "timer.h"

static const char *logger_name_ptr = "part_register_operations";

// Forward declarations for internal event reporting
signed char participant_report_register_change(Participant *participant_ptr,
                                               uint8_t reg);

// Check the active config session for overall/inactivity timeout; terminates
// it and fires a security event if either limit is exceeded.
spsec_ret_t check_session_timeout(Participant *participant_ptr) {
  if (!participant_ptr->session.active) {
    return SPSEC_SUCCESS;
  }

  uint64_t current_time = timer_get_current_time_us(&participant_ptr->timer);
  uint64_t time_since_start =
      current_time - participant_ptr->session.start_time;
  uint64_t time_since_activity =
      current_time - participant_ptr->session.last_activity;

  // Check overall session timeout (10 seconds)
  if (time_since_start >= participant_ptr->session.timeout_us) {
    LOG_WARNING(logger_name_ptr, "Session timeout expired (overall timeout)");
    participant_ptr->state_info.last_event = SPSEC_SESS_TIMEOUT;
    participant_report_security_event(participant_ptr, SPSEC_SESS_TIMEOUT);
    // Terminate session and drop uncommitted write accumulator
    participant_ptr->session.active = false;
    memset(participant_ptr->write_accum.buf, 0, sizeof(participant_ptr->write_accum.buf));
    participant_ptr->write_accum.len = 0;
    participant_ptr->write_accum.expected = 0;
    participant_ptr->write_accum.active = false;
    // Use correct event based on current state
    spsec_event_t abort_event = (participant_ptr->state_info.state == SPSEC_STATE_WAITING)
                                    ? SPSEC_EVENT_SECURITY_ABORT
                                    : SPSEC_EVENT_EXIT_CONFIG;
    participant_state_transition(participant_ptr, abort_event);
    return SPSEC_ERROR_SESSION_TIMEOUT;
  }

  // Check response timeout (100ms) - allow 10x response timeout for overall inactivity
  if (time_since_activity >=
      participant_ptr->session.response_timeout_us * 10) {
    LOG_WARNING(logger_name_ptr, "Session timeout expired (response timeout)");
    participant_ptr->state_info.last_event = SPSEC_SESS_RESPONSE_TIMEOUT;
    participant_report_security_event(participant_ptr,
                                      SPSEC_SESS_RESPONSE_TIMEOUT);
    // Terminate session and drop uncommitted write accumulator
    participant_ptr->session.active = false;
    memset(participant_ptr->write_accum.buf, 0, sizeof(participant_ptr->write_accum.buf));
    participant_ptr->write_accum.len = 0;
    participant_ptr->write_accum.expected = 0;
    participant_ptr->write_accum.active = false;
    // Use correct event based on current state
    spsec_event_t abort_event = (participant_ptr->state_info.state == SPSEC_STATE_WAITING)
                                    ? SPSEC_EVENT_SECURITY_ABORT
                                    : SPSEC_EVENT_EXIT_CONFIG;
    participant_state_transition(participant_ptr, abort_event);
    return SPSEC_ERROR_SESSION_TIMEOUT;
  }

  return SPSEC_SUCCESS;
}

// Configure the crypto handler with the given key and nonce.
spsec_ret_t setup_crypto_context(Participant *participant_ptr, uint8_t *nonce_ptr,
                                 size_t nonce_len, uint8_t *session_key_ptr,
                                 size_t auth_tag_size) {
  if (!participant_ptr || !nonce_ptr || !session_key_ptr) {
    LOG_ERROR(
        logger_name_ptr,
        "Invalid arguments: participant_ptr, nonce, or session_key is NULL");
    return SPSEC_ERROR_INVALID_ARGUMENT;
  }

  spsec_ret_t ret =
      crypto_handler_set_context(&participant_ptr->crypto_handler, session_key_ptr,
                                 nonce_ptr, nonce_len, (int)auth_tag_size);
  if (ret != SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr, "Failed to set crypto context");
    return ret;
  }
  return SPSEC_SUCCESS;
}

// Decrypt a register-operation ciphertext with the session key. Register
// ops are always encrypted per SPsec302 (auth-only mode is data-plane only).
spsec_ret_t decrypt_message(Participant *participant_ptr,
                            uint8_t *ciphertext_ptr, size_t ciphertext_len,
                            uint8_t *auth_tag_ptr, uint8_t *plaintext_ptr,
                            uint8_t *assoc_data_ptr, size_t assoc_data_len) {
  uint32_t addr_le = 0;
  if (assoc_data_len >= 4) {
    addr_le = (uint32_t)assoc_data_ptr[0] | ((uint32_t)assoc_data_ptr[1] << 8) |
              ((uint32_t)assoc_data_ptr[2] << 16) | ((uint32_t)assoc_data_ptr[3] << 24);
  }
  LOG_DEBUG(logger_name_ptr,
            "DECRYPT_CALL site=register_ops.decrypt_message addr=%08x len=%u",
            (unsigned)addr_le, (unsigned)ciphertext_len);
  LOG_SECRET(logger_name_ptr, "AssocData", assoc_data_ptr, assoc_data_len);

  spsec_ret_t ret = crypto_handler_decrypt_with_assoc_data(
      &participant_ptr->crypto_handler, ciphertext_ptr, ciphertext_len,
      auth_tag_ptr, plaintext_ptr, assoc_data_ptr, assoc_data_len);
  LOG_DEBUG(logger_name_ptr,
            "DECRYPT_RESULT site=register_ops.decrypt_message ret=%d addr=%08x",
            (int)ret, (unsigned)addr_le);

  // Treat any non-zero return as failure (avoid char sign issues across
  // targets)
  if (ret != SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr, "Failed to decrypt message");
    return ret;
  }
  LOG_SECRET(logger_name_ptr, "Decrypted plaintext:", plaintext_ptr, ciphertext_len);
  return SPSEC_SUCCESS;
}

// Encrypt a register-operation plaintext block with the session key.
spsec_ret_t encrypt_message(Participant *participant_ptr,
                            uint8_t *plaintext_ptr, size_t plaintext_len,
                            uint8_t *ciphertext_ptr, uint8_t *auth_tag_ptr,
                            uint8_t *assoc_data_ptr, size_t assoc_data_len) {
  spsec_ret_t ret = crypto_handler_encrypt_with_assoc_data(
      &participant_ptr->crypto_handler, plaintext_ptr, plaintext_len,
      ciphertext_ptr, auth_tag_ptr, assoc_data_ptr, assoc_data_len);
  if (ret != SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr, "Failed to encrypt message");
    return ret;
  }
  return SPSEC_SUCCESS;
}

// Generate a nonce for the current session counter.
spsec_ret_t participant_generate_nonce(Participant *participant_ptr,
                                       uint8_t **nonce_ptr) {
  if (!participant_ptr || !nonce_ptr) {
    LOG_ERROR(logger_name_ptr,
              "Invalid arguments: participant_ptr or nonce is NULL");
    return SPSEC_ERROR_INVALID_ARGUMENT;
  }

  if (!participant_ptr->session.auth_tag_data_ptr ||
      !participant_ptr->session.auth_tag_data_ptr->spsec_salt_ptr) {
    LOG_ERROR(logger_name_ptr, "Session auth tag data or salt is NULL");
    return SPSEC_ERROR_INVALID_STATE;
  }

  spsec_ret_t ret = generate_nonce_from_session_cnt(
      participant_ptr->session.cnt, nonce_ptr,
      participant_ptr->session.auth_tag_data_ptr->spsec_salt_ptr);
  if (ret != SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr, "Failed to generate nonce");
    return ret;
  }

  return SPSEC_SUCCESS;
}