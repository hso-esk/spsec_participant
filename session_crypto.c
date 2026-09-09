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

#include "participant.h"
#include "spsec_common.h"

static const char *logger_name_ptr = "session_crypto";

// Build the nonce: 8-byte timestamp || 2-byte address low16 || optional salt.
static void build_nonce_le_low16(Participant *participant_ptr,
                                 const uint8_t *restored_timestamp_ptr,
                                 uint32_t address, uint8_t *nonce_ptr) {
  // Zero entire buffer first so any bytes beyond timer+address+salt are cleanly padded
  memset(nonce_ptr, 0, REQUIRED_NONCE_LEN);

  // Build data-plane nonce_ptr: 64-bit timestamp_ptr (8) + CAN ID low16 (2) + salt
  size_t nonce_len = crypto_get_nonce_len(participant_ptr->crypto_algorithm);
  memcpy(nonce_ptr, restored_timestamp_ptr, 8);
  nonce_ptr[8] = (uint8_t)(address & 0xFF);
  nonce_ptr[9] = (uint8_t)((address >> 8) & 0xFF);
  if (nonce_len > 10) {
    size_t remain = nonce_len - 10;
    if (remain > SALT_LEN)
      remain = SALT_LEN;
    if (remain > (REQUIRED_NONCE_LEN - 10))
      remain = REQUIRED_NONCE_LEN - 10;
    // A partial provision (key_ptr present, comm salt NULL) must not crash here;
    // zero-fill instead — the resulting nonce_ptr is wrong, so decrypt fails cleanly.
    if (participant_ptr->comm_keys.spsec_salt[3]) {
      memcpy(nonce_ptr + 10, participant_ptr->comm_keys.spsec_salt[3]->salt,
             remain);
    }
  }
}

// Try decrypting app data with the given key and little-endian assoc data.
static spsec_ret_t try_decrypt_with_le_assoc(Participant *participant_ptr,
                                             uint8_t *key_ptr,
                                             SPsecAppData *msg_ptr,
                                             const uint8_t *restored_timestamp_ptr,
                                             uint8_t *plaintext_ptr,
                                             const uint8_t assoc_data_le_ptr[DATA_AAD_LEN]) {
  size_t nonce_len = crypto_get_nonce_len(participant_ptr->crypto_algorithm);
  uint8_t nonce_try[REQUIRED_NONCE_LEN];
  build_nonce_le_low16(participant_ptr, restored_timestamp_ptr, msg_ptr->address,
                       nonce_try);
  if (crypto_handler_set_context(&participant_ptr->crypto_handler, key_ptr,
                                 nonce_try, nonce_len,
                                 AUTH_TAG_SIZE) != SPSEC_SUCCESS) {
    return SPSEC_ERROR_CRYPTO_INIT;
  }
  // Identify which rolling key_ptr pointer is being used for clearer tracing
  const char *key_label_ptr = (key_ptr == participant_ptr->comm_keys.even_key) ? "even"
                          : (key_ptr == participant_ptr->comm_keys.odd_key)
                              ? "odd"
                              : "unknown";
  LOG_DEBUG(logger_name_ptr,
            "DECRYPT_CALL site=session_crypto.try_decrypt_with_le_assoc "
            "addr=%08x len=%u key_ptr=%s auth_only=%d",
            (unsigned)msg_ptr->address, (unsigned)msg_ptr->secure_data_len,
            key_label_ptr, participant_ptr->auth_only_mode);
  // LOG_ARRAY, not a fixed %02x chain: a hardcoded width once read past a
  // shrunk DATA_AAD_LEN buffer (OOB stack read). Not secret data, so
  // LOG_ARRAY not LOG_SECRET is correct.
  LOG_ARRAY(LOG_LEVEL_DEBUG, logger_name_ptr, "AssocData(LE):", assoc_data_le_ptr,
           DATA_AAD_LEN);
  LOG_SECRET(logger_name_ptr, "Ciphertext to decrypt:",
            msg_ptr->secure_data_ptr, msg_ptr->secure_data_len);
  LOG_SECRET(logger_name_ptr, "Auth tag for verification:",
            msg_ptr->auth_tag_ptr, AUTH_TAG_SIZE);

  spsec_ret_t ret;
  if (participant_ptr->auth_only_mode) {
    size_t unpadded_len = assoc_data_le_ptr[4];
    if (unpadded_len > msg_ptr->secure_data_len) {
      LOG_ERROR(logger_name_ptr,
                "Invalid auth-only payload length %zu for secure_data_len %u",
                unpadded_len, (unsigned)msg_ptr->secure_data_len);
      return SPSEC_ERROR_INVALID_ARGUMENT;
    }

    uint8_t *extended_aad_ptr = (uint8_t *)malloc(DATA_AAD_LEN + unpadded_len);
    if (!extended_aad_ptr) {
      LOG_ERROR(logger_name_ptr, "Failed to allocate auth-only associated data");
      return SPSEC_ERROR_OUT_OF_MEMORY;
    }
    memcpy(extended_aad_ptr, assoc_data_le_ptr, DATA_AAD_LEN);
    memcpy(extended_aad_ptr + DATA_AAD_LEN, msg_ptr->secure_data_ptr, unpadded_len);

    uint8_t dummy_input = 0;
    uint8_t dummy_output = 0;
    ret = crypto_handler_decrypt_with_assoc_data(
        &participant_ptr->crypto_handler, &dummy_input, 0,
        msg_ptr->auth_tag_ptr, &dummy_output, extended_aad_ptr,
        DATA_AAD_LEN + unpadded_len);
    free(extended_aad_ptr);

    if (ret == SPSEC_SUCCESS) {
      memcpy(plaintext_ptr, msg_ptr->secure_data_ptr, msg_ptr->secure_data_len);
    }
  } else {
    ret = crypto_handler_decrypt_with_assoc_data(
        &participant_ptr->crypto_handler, msg_ptr->secure_data_ptr,
        msg_ptr->secure_data_len, msg_ptr->auth_tag_ptr, plaintext_ptr,
        assoc_data_le_ptr, DATA_AAD_LEN);
  }
  if (ret == SPSEC_SUCCESS) {
    LOG_DEBUG(logger_name_ptr,
              "DECRYPT_RESULT site=session_crypto.try_decrypt_with_le_assoc "
              "addr=%08x len=%u key_ptr=%s OK",
              (unsigned)msg_ptr->address, (unsigned)msg_ptr->secure_data_len,
              key_label_ptr);
  } else {
    LOG_DEBUG(logger_name_ptr,
              "DECRYPT_RESULT site=session_crypto.try_decrypt_with_le_assoc "
              "addr=%08x len=%u key_ptr=%s FAILED (%d)",
              (unsigned)msg_ptr->address, (unsigned)msg_ptr->secure_data_len,
              key_label_ptr, ret);
  }
  return ret;
}

// Decrypt inbound AppData with the given rolling key for its restored epoch.
spsec_ret_t participant_decrypt_spsec_appdata(
    Participant *participant_ptr, SPsecAppData *msg_ptr, uint8_t *timestamp_ptr,
    uint8_t *key_ptr, uint8_t **plaintext_ptr, size_t *plaintext_len_ptr) {
  LOG_DEBUG(
      logger_name_ptr,
      "--- participant_decrypt_spsec_appdata: Starting decryption process ---");
  LOG_DEBUG_ARRAY(logger_name_ptr, "Input timestamp_ptr:", timestamp_ptr, 8);
  LOG_SECRET(logger_name_ptr, "Input key_ptr:", key_ptr, KEY_LEN);

  uint8_t baseline_ts[8];
  memcpy(baseline_ts, timestamp_ptr, 8);

  uint8_t restored_timestamp_ptr[8];
  if (participant_channel_restore_timestamp_and_padding(
          baseline_ts, msg_ptr, restored_timestamp_ptr) < 0) {
    LOG_ERROR(logger_name_ptr, "Failed to restore timestamp_ptr");
    return SPSEC_ERROR_INVALID_ARGUMENT;
  }
  LOG_DEBUG_ARRAY(logger_name_ptr, "Restored timestamp_ptr for app data decryption:",
                  restored_timestamp_ptr, 8);

  // Derive rolling keys from the restored timestamp so key_ptr's epoch
  // matches the message; updates comm_keys in-place, key_ptr still points in.
  if (communication_keys_update(&participant_ptr->comm_keys,
                                restored_timestamp_ptr) < 0) {
    LOG_ERROR(
        logger_name_ptr,
        "Failed to update communication keys using restored timestamp_ptr");
    return SPSEC_ERROR_KEY_NOT_FOUND;
  }
  LOG_SECRET(logger_name_ptr, "Selected key_ptr (post-restore):", key_ptr,
            KEY_LEN);
  // Extra debug: show both rolling keys
  LOG_SECRET(logger_name_ptr, "Comm even_key:",
            participant_ptr->comm_keys.even_key, KEY_LEN);
  LOG_SECRET(logger_name_ptr, "Comm odd_key:",
            participant_ptr->comm_keys.odd_key, KEY_LEN);

  // Guard the payload-length subtraction below: padding_size comes from the
  // frame (0-15) and must not exceed secure_data_len, else secure_data_len -
  // padding_size underflows to a huge size_t and over-reads the plaintext.
  if (msg_ptr->padding_size > msg_ptr->secure_data_len) {
    LOG_ERROR(logger_name_ptr,
              "Invalid padding_size %u for secure_data_len %u - rejecting",
              msg_ptr->padding_size, msg_ptr->secure_data_len);
    return SPSEC_ERROR_INVALID_ARGUMENT;
  }

  uint8_t assoc_data_le_ptr[DATA_AAD_LEN];
  assoc_data_le_ptr[0] = (uint8_t)(msg_ptr->address & 0xFF);
  assoc_data_le_ptr[1] = (uint8_t)((msg_ptr->address >> 8) & 0xFF);
  assoc_data_le_ptr[2] = (uint8_t)((msg_ptr->address >> 16) & 0xFF);
  assoc_data_le_ptr[3] = (uint8_t)((msg_ptr->address >> 24) & 0xFF);
  assoc_data_le_ptr[4] =
      (uint8_t)(msg_ptr->secure_data_len - msg_ptr->padding_size);

  // AAD is CAN ID (4) + payload length (1) (DATA_AAD_LEN = 5)
  LOG_DEBUG(logger_name_ptr,
            "AppData decrypt: base_id=0x%08x secure_len=%u padding=%u payload_len=%u",
            (unsigned)msg_ptr->address, (unsigned)msg_ptr->secure_data_len,
            (unsigned)msg_ptr->padding_size, (unsigned)assoc_data_le_ptr[4]);
  LOG_SECRET(logger_name_ptr, "AppData decrypt AD:", assoc_data_le_ptr,
            DATA_AAD_LEN);

  *plaintext_ptr = (uint8_t *)malloc(msg_ptr->secure_data_len);
  if (!*plaintext_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to allocate memory for plaintext_ptr");
    return SPSEC_ERROR_OUT_OF_MEMORY;
  }

  LOG_DEBUG(logger_name_ptr, "Calling crypto_handler_decrypt_with_assoc_data...");
  LOG_SECRET(logger_name_ptr, "Ciphertext to decrypt:",
            msg_ptr->secure_data_ptr, msg_ptr->secure_data_len);
  LOG_SECRET(logger_name_ptr, "Auth tag for verification:",
            msg_ptr->auth_tag_ptr, AUTH_TAG_SIZE);

  spsec_ret_t ret = try_decrypt_with_le_assoc(participant_ptr, key_ptr, msg_ptr,
                                              restored_timestamp_ptr,
                                              *plaintext_ptr, assoc_data_le_ptr);
  if (ret == SPSEC_SUCCESS) {
      memcpy(msg_ptr->timestamp, restored_timestamp_ptr, 8);
      *plaintext_len_ptr = msg_ptr->secure_data_len - msg_ptr->padding_size;
      LOG_SECRET(logger_name_ptr, "Raw decrypted data (before padding removal):", *plaintext_ptr,
                msg_ptr->secure_data_len);
      LOG_SECRET(logger_name_ptr, "Final plaintext (after padding removal):", *plaintext_ptr,
                *plaintext_len_ptr);
      LOG_DEBUG(logger_name_ptr,
                "Decryption successful - plaintext_len_ptr: %zu, padding_size: %u",
                *plaintext_len_ptr, msg_ptr->padding_size);
      LOG_DEBUG(logger_name_ptr, "--- participant_decrypt_spsec_appdata: Decryption process complete ---");
      return SPSEC_SUCCESS;
    }

    free(*plaintext_ptr);
    *plaintext_ptr = NULL;
    return ret;
}