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

#include "keys.h"
#include "participant.h"
#include "participant_channel.h"
#include "spsec_common.h"
#include "spsec_registers.h"
#include "utils_bytes.h"
#include <stdint.h>

static const char *logger_name_ptr = "part_session_appdata";

// Decrypt incoming secure AppData and forward it on the insecure channel,
// retrying with the fallback key if the preferred one fails.
signed char participant_process_spsec_appdata(Participant *participant_ptr,
                                              SPsecAppData *msg_ptr) {
  uint8_t timestamp[8];
  timer_get_timestamp(&participant_ptr->timer, timestamp);
  LOG_DEBUG_ARRAY(logger_name_ptr, "Current timestamp for app data decryption:",
                  timestamp, 8);
  // Prefer restored timestamp (from message LSBs) to decide key parity to
  // avoid first-attempt auth failures
  uint8_t restored_ts[8];
  participant_channel_restore_timestamp_and_padding(timestamp, msg_ptr,
                                                    restored_ts);

  // Check acceptance window for replay protection
  uint64_t local_ts = 0, restored_val = 0;
  for (int i = 7; i >= 0; i--) {
    local_ts = (local_ts << 8) | timestamp[i];
    restored_val = (restored_val << 8) | restored_ts[i];
  }
  int64_t skew_ticks = (int64_t)(restored_val - local_ts);
  int64_t window_ns =
      (int64_t)participant_ptr->accept_window_ticks * 100000LL;
  int64_t skew_ns =
      skew_ticks * (int64_t)timer_get_tick_ns(&participant_ptr->timer);
  if (skew_ns > window_ns || skew_ns < -window_ns) {
    LOG_WARNING(logger_name_ptr,
                "AppData outside acceptance window: skew=%lld ns "
                "(|skew|>%lld ns) addr=%08x - rejecting (possible replay)",
                (long long)skew_ns, (long long)window_ns,
                (unsigned)msg_ptr->address);
    return -1;
  }

  // Ensure keys are derived for the same epoch as the message
  communication_keys_update(&participant_ptr->comm_keys, restored_ts);
  uint8_t *plaintext_ptr;
  size_t plaintext_len;

  signed char ret;
  // Try key indicated by use_odd_key first, then fallback
  uint8_t *first_key_ptr = participant_ptr->comm_keys.use_odd_key
                           ? participant_ptr->comm_keys.odd_key
                           : participant_ptr->comm_keys.even_key;
  uint8_t *second_key_ptr = participant_ptr->comm_keys.use_odd_key
                            ? participant_ptr->comm_keys.even_key
                            : participant_ptr->comm_keys.odd_key;
  LOG_DEBUG(logger_name_ptr,
            "DECRYPT_CALL site=session_appdata addr=%08x len=%u key=%s",
            (unsigned)msg_ptr->address, (unsigned)msg_ptr->secure_data_len,
            participant_ptr->comm_keys.use_odd_key ? "odd" : "even");
  ret = participant_decrypt_spsec_appdata(participant_ptr, msg_ptr,
                                          timestamp, first_key_ptr,
                                          &plaintext_ptr, &plaintext_len);
  if (ret < 0) {
    LOG_INFO(logger_name_ptr,
             "Decryption with first key failed, trying fallback key");
    LOG_DEBUG(logger_name_ptr,
              "DECRYPT_CALL site=session_appdata addr=%08x len=%u key=%s",
              (unsigned)msg_ptr->address, (unsigned)msg_ptr->secure_data_len,
              participant_ptr->comm_keys.use_odd_key ? "even" : "odd");
    ret = participant_decrypt_spsec_appdata(participant_ptr, msg_ptr,
                                            timestamp, second_key_ptr,
                                            &plaintext_ptr, &plaintext_len);
    if (ret < 0) {
      participant_report_security_event(participant_ptr, SPSEC_SDP_AUTH_FAILURE);
      return -2;
    }
  }
  AppData *out_msg_ptr =
      appdata_new(msg_ptr->address, plaintext_ptr, plaintext_len);
  if (!out_msg_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to allocate AppData for received message");
    free(plaintext_ptr);
    return -4;
  }

  LOG_CRITICAL(logger_name_ptr, "Received app data_ptr from: 0x%08x",
               out_msg_ptr->address);
  LOG_SECRET(logger_name_ptr, "AppData:", out_msg_ptr->data_ptr, out_msg_ptr->data_len);

  // Need to wrap data_ptr sending to make it platform - dependent
  // ret = channel_send_appdata(&participant_ptr->insecure_channel, out_msg_ptr);
  ret = participant_send_insecure_channel_message(
      &participant_ptr->insecure_channel, out_msg_ptr);

  appdata_free(out_msg_ptr);
  free(plaintext_ptr);
  if (ret < 0)
    return -3;
  return 0;
}

// Build the AEAD associated data: CAN ID (4 bytes) + data length (1 byte).
void prepare_appdata_assoc_data(uint32_t address, size_t data_len,
                                uint8_t assoc_data_ptr[DATA_AAD_LEN]) {
  uint32_t base_can_id = (address & 0x1FFFFFFF); // CAN_EFF_MASK
  u32_to_bytes_le(base_can_id, assoc_data_ptr);
  assoc_data_ptr[4] = (uint8_t)data_len;
  LOG_DEBUG_ARRAY(logger_name_ptr, "AppData encrypt AD(prefix):",
                  assoc_data_ptr, DATA_AAD_LEN);
}

// Build the AEAD nonce.
static spsec_ret_t construct_aead_nonce(Participant *participant_ptr,
                                        uint32_t address, uint8_t *nonce_ptr) {
  uint32_t base_can_id = (address & 0x1FFFFFFF); // CAN_EFF_MASK
  uint8_t timestamp[8];
  timer_get_timestamp(&participant_ptr->timer, timestamp);

  // SPsec nonce_ptr reuse prevention:
  // If the previous transmission used the same timestamp and low 16 bits of CAN ID,
  // wait until the timer advances to the next tick so the AEAD nonce_ptr is guaranteed unique.
  // Bounded: a stalled timer must not hang the participant forever.
  #define NONCE_WAIT_MAX_ATTEMPTS 1000 // 1000 * 50us = 50ms deadline
  int nonce_wait_attempts = 0;
  while (memcmp(timestamp, participant_ptr->last_tx_timestamp, 8) == 0 &&
         (base_can_id & 0xFFFF) == (participant_ptr->last_tx_can_id & 0xFFFF)) {
    if (++nonce_wait_attempts > NONCE_WAIT_MAX_ATTEMPTS) {
      LOG_ERROR(logger_name_ptr,
                "Timer did not advance after %d attempts - aborting send "
                "to avoid nonce_ptr reuse",
                NONCE_WAIT_MAX_ATTEMPTS);
      return SPSEC_ERROR_TIMEOUT;
    }
    struct timespec ts = {0, 50000}; // 50 us
    nanosleep(&ts, NULL);
    timer_get_timestamp(&participant_ptr->timer, timestamp);
  }
  #undef NONCE_WAIT_MAX_ATTEMPTS
  memcpy(participant_ptr->last_tx_timestamp, timestamp, 8);
  participant_ptr->last_tx_can_id = base_can_id;

  LOG_DEBUG_ARRAY(logger_name_ptr, "Timestamp for app data encryption:",
                  timestamp, 8);

  // Build nonce_ptr: timestamp (8) + CAN ID low16 (2) + salt
  memcpy(nonce_ptr, timestamp, 8);
  nonce_ptr[8] = (uint8_t)(base_can_id & 0xFF);
  nonce_ptr[9] = (uint8_t)((base_can_id >> 8) & 0xFF);

  size_t nonce_len = crypto_get_nonce_len(participant_ptr->crypto_algorithm);
  
  if (nonce_len > 10) {
    size_t remain = nonce_len - 10;
    if (remain > SALT_LEN)
      remain = SALT_LEN;
    // Partial provision guard: absence of communication salt prevents building a valid nonce_ptr.
    if (!participant_ptr->comm_keys.spsec_salt[3]) {
      LOG_ERROR(logger_name_ptr, "Communication salt not set - cannot build nonce_ptr");
      return SPSEC_ERROR_CRYPTO_INIT;
    }
    memcpy(nonce_ptr + 10, participant_ptr->comm_keys.spsec_salt[3]->salt,
           remain);
    if (nonce_len > (10 + SALT_LEN)) {
      LOG_ERROR(logger_name_ptr, "Salt is too short to fill up nonce_ptr of length %zu",
                nonce_len);
      return SPSEC_ERROR_CRYPTO_INIT;
    }
  }
  LOG_SECRET(logger_name_ptr, "AppData encrypt nonce_ptr:", nonce_ptr, nonce_len);
  return SPSEC_SUCCESS;
}

// Allocate a padded copy of the payload and build its AEAD assoc data + nonce.
static signed char prepare_encrypted_data(Participant *participant_ptr,
                                          AppData *msg_ptr,
                                          uint8_t **data_with_padding_ptr,
                                          uint8_t *padding_size_ptr,
                                          uint8_t *assoc_data_ptr, uint8_t *nonce_ptr) {
  int padding = participant_channel_calculate_padding((int)msg_ptr->data_len);
  if (padding < 0) {
    // Oversize payload: don't cast -1 to 255, that would pad to 255 bytes
    // and send a malformed oversized frame.
    LOG_ERROR(logger_name_ptr,
              "Cannot compute padding for message of length %zu - aborting send",
              msg_ptr->data_len);
    return -1;
  }
  *padding_size_ptr = (uint8_t)padding;
  LOG_DEBUG(logger_name_ptr,
            "Calculated padding for encryption: message_len=%zu, padding=%d",
            msg_ptr->data_len, *padding_size_ptr);

  *data_with_padding_ptr = malloc(msg_ptr->data_len + *padding_size_ptr);
  if (!*data_with_padding_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to allocate memory for padded data_ptr");
    return -1;
  }

  memcpy(*data_with_padding_ptr, msg_ptr->data_ptr, msg_ptr->data_len);
  memset(*data_with_padding_ptr + msg_ptr->data_len, 0xFF, *padding_size_ptr);

  prepare_appdata_assoc_data(msg_ptr->address, msg_ptr->data_len, assoc_data_ptr);

  if (construct_aead_nonce(participant_ptr, msg_ptr->address, nonce_ptr) !=
      SPSEC_SUCCESS) {
    free(*data_with_padding_ptr);
    return -2;
  }

  return 0;
}

// Fill nonce/assoc data via prepare_encrypted_data() and pick the even/odd
// encryption key for the current timestamp epoch.
static signed char prepare_insec_nonce_and_assoc_data(
    Participant *participant_ptr, AppData *msg_ptr, uint8_t **data_with_padding_ptr,
    uint8_t *padding_size_ptr, uint8_t assoc_data_ptr[DATA_AAD_LEN],
    uint8_t nonce_ptr[REQUIRED_NONCE_LEN], uint8_t **enc_key_out_ptr) {
  signed char ret =
      prepare_encrypted_data(participant_ptr, msg_ptr, data_with_padding_ptr,
                             padding_size_ptr, assoc_data_ptr, nonce_ptr);
  if (ret < 0)
    return ret;

  // Keep keys in sync for this timestamp epoch; also sets use_odd_key
  communication_keys_update(&participant_ptr->comm_keys, nonce_ptr);
  bool use_odd = participant_ptr->comm_keys.use_odd_key;
  *enc_key_out_ptr = use_odd ? participant_ptr->comm_keys.odd_key
                         : participant_ptr->comm_keys.even_key;
  // Debug: show which key will be used for encryption at this timestamp
  // epoch
  LOG_DEBUG(logger_name_ptr, "ENCRYPT_KEY_SELECTED addr=%08x key=%s",
            (unsigned)msg_ptr->address, use_odd ? "odd" : "even");
  LOG_SECRET(logger_name_ptr, "Selected enc key", *enc_key_out_ptr, KEY_LEN);
  return 0;
}

// Handle encryption in authentication-only mode.
static signed char encrypt_auth_only(Participant *participant_ptr,
                                     const uint8_t assoc_data_ptr[DATA_AAD_LEN],
                                     const uint8_t *data_with_padding_ptr,
                                     size_t total_len, uint8_t *ciphertext_out_ptr,
                                     uint8_t tag_out_ptr[8]) {
  // SPsec302 §2.9: AAD's appended data field is unpadded length here.
  size_t unpadded_len = assoc_data_ptr[4];
  if (unpadded_len > total_len)
    unpadded_len = total_len; // defensive
  uint8_t *extended_aad_ptr = (uint8_t *)malloc(DATA_AAD_LEN + unpadded_len);
  if (!extended_aad_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to allocate extended AAD buffer");
    return -3;
  }

  memcpy(extended_aad_ptr, assoc_data_ptr, DATA_AAD_LEN);
  memcpy(extended_aad_ptr + DATA_AAD_LEN, data_with_padding_ptr, unpadded_len);

  uint8_t dummy_input = 0;
  uint8_t dummy_output = 0;
  signed char ret = crypto_handler_encrypt_with_assoc_data(
      &participant_ptr->crypto_handler, &dummy_input, 0, &dummy_output, tag_out_ptr,
      extended_aad_ptr, DATA_AAD_LEN + unpadded_len);
  free(extended_aad_ptr);

  if (ret < 0) {
    LOG_ERROR(logger_name_ptr,
              "Failed to compute authentication tag_ptr in auth-only mode");
    return -4;
  }

  memcpy(ciphertext_out_ptr, data_with_padding_ptr, total_len);
  LOG_DEBUG(logger_name_ptr, "Authentication-only encryption successful");
  return 0;
}

// Encrypt the padded payload with AEAD and produce ciphertext + auth tag.
signed char encrypt_insec_payload(
    Participant *participant_ptr, const uint8_t *enc_key_ptr,
    const uint8_t *nonce_ptr, const uint8_t assoc_data_ptr[DATA_AAD_LEN],
    const uint8_t *data_with_padding_ptr, size_t total_len,
    uint8_t **ciphertext_out_ptr, uint8_t tag_out_ptr[8]) {
  const char *key_label_ptr =
      (enc_key_ptr == participant_ptr->comm_keys.even_key)  ? "even"
      : (enc_key_ptr == participant_ptr->comm_keys.odd_key) ? "odd"
                                                        : "unknown";
  LOG_DEBUG(
      logger_name_ptr,
      "ENCRYPT_CALL site=session_appdata payload_len=%u key=%s auth_only=%d",
      (unsigned)total_len, key_label_ptr, participant_ptr->auth_only_mode);
  size_t nonce_len = crypto_get_nonce_len(participant_ptr->crypto_algorithm);
  if (crypto_handler_set_context(&participant_ptr->crypto_handler,
                                 (uint8_t *)enc_key_ptr, (uint8_t *)nonce_ptr,
                                 nonce_len, AUTH_TAG_SIZE) < 0) {
    return -1;
  }
  *ciphertext_out_ptr = (uint8_t *)malloc(total_len);
  if (!*ciphertext_out_ptr) {
    return -2;
  }

  if (participant_ptr->auth_only_mode) {
    signed char ret =
        encrypt_auth_only(participant_ptr, assoc_data_ptr, data_with_padding_ptr,
                          total_len, *ciphertext_out_ptr, tag_out_ptr);
    if (ret < 0) {
      free(*ciphertext_out_ptr);
      *ciphertext_out_ptr = NULL;
      return ret;
    }
    return 0;
  } else {
    if (crypto_handler_encrypt_with_assoc_data(
            &participant_ptr->crypto_handler, (uint8_t *)data_with_padding_ptr,
            (uint32_t)total_len, *ciphertext_out_ptr, tag_out_ptr,
            (uint8_t *)assoc_data_ptr, DATA_AAD_LEN) < 0) {
      free(*ciphertext_out_ptr);
      *ciphertext_out_ptr = NULL;
      return -3;
    }
    return 0;
  }
}

// Wrap the ciphertext into an SPsecAppData message and send it securely.
static signed char send_insec_message(Participant *participant_ptr,
                                      AppData *msg_ptr,
                                      const uint8_t *ciphertext_ptr,
                                      size_t total_len, uint8_t padding_size_ptr,
                                      const uint8_t nonce_ptr[REQUIRED_NONCE_LEN],
                                      const uint8_t tag_ptr[8]) {
  uint8_t timestamp[8];
  memcpy(timestamp, nonce_ptr, 8);
  SPsecAppData *spsec_app_data_ptr = spsecappdata_new(
      msg_ptr->address, (uint8_t *)ciphertext_ptr, (uint32_t)total_len,
      padding_size_ptr, timestamp, (uint8_t *)tag_ptr, 8);
  if (!spsec_app_data_ptr) {
    return -1;
  }
  signed char ret = participant_channel_send_spapp_data(
      &participant_ptr->secure_channel, spsec_app_data_ptr);
  spsecappdata_free(spsec_app_data_ptr);
  return ret < 0 ? -2 : 0;
}

// Validate, encrypt, and send an application message over the secure channel.
signed char participant_handle_secure_message(Participant *participant_ptr,
                                              AppData *msg_ptr) {
  if (msg_ptr->data_len > 54) {
    LOG_ERROR(logger_name_ptr, "Message data_ptr too long: %zu bytes",
              msg_ptr->data_len);
    return -1;
  }

  uint8_t *data_with_padding_ptr = NULL;
  uint8_t padding_size_ptr = 0;
  uint8_t assoc_data_ptr[DATA_AAD_LEN];
  uint8_t nonce_ptr[REQUIRED_NONCE_LEN];
  uint8_t *enc_key_ptr = NULL;

  signed char ret = prepare_insec_nonce_and_assoc_data(
      participant_ptr, msg_ptr, &data_with_padding_ptr, &padding_size_ptr, assoc_data_ptr,
      nonce_ptr, &enc_key_ptr);
  if (ret < 0)
    return ret;

  uint8_t *ciphertext_ptr = NULL;
  uint8_t tag_ptr[8];
  ret = encrypt_insec_payload(
      participant_ptr, enc_key_ptr, nonce_ptr, assoc_data_ptr, data_with_padding_ptr,
      msg_ptr->data_len + padding_size_ptr, &ciphertext_ptr, tag_ptr);
  if (ret < 0) {
    free(data_with_padding_ptr);
    return -1;
  }

  ret = send_insec_message(participant_ptr, msg_ptr, ciphertext_ptr,
                           msg_ptr->data_len + padding_size_ptr, padding_size_ptr,
                           nonce_ptr, tag_ptr);
  free(ciphertext_ptr);
  free(data_with_padding_ptr);

  if (ret < 0) {
    LOG_ERROR(logger_name_ptr, "Failed to send SPsecAppData");
    return -1;
  }

  LOG_DEBUG(logger_name_ptr, "Encryption and send completed successfully");
  return 0;
}
