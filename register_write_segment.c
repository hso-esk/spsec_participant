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

// Handles write-segment requests and applies the written data to registers.

#include "crypto.h"
#include "keys.h"
#include "messages.h"
#include "nvol_storage.h"
#include "participant.h"
#include "participant_channel.h"
#include "participant_storage.h"
#include "register_operations.h"
#include "register_validation.h"
#include "register_write.h"
#include "register_write_internal.h"
#include "spsec_common.h"
#include "spsec_mapping.h"
#include "spsec_registers.h"

static const char *logger_name_ptr = "register_write_seg";

void write_accum_reset(ParticipantWriteAccum *accum_ptr) {
  if (accum_ptr) {
    memset(accum_ptr->buf, 0, sizeof(accum_ptr->buf));
    accum_ptr->len = 0;
    accum_ptr->expected = 0;
    accum_ptr->active = false;
  }
}

spsec_ret_t
register_check_write_segment(Participant *participant_ptr,
                             SPsecClientWriteSegmentRequest *msg_ptr) {
  if (msg_ptr->participant_id != participant_ptr->participant_id) {
    LOG_ERROR(logger_name_ptr,
              "Received write segment request for wrong participant_ptr: %u "
              "(our participant_id %u)",
              msg_ptr->participant_id, participant_ptr->participant_id);
    return 1;
  }

  participant_ptr->session.cnt++;

  // SPsec302 §2.10: confirm the peer's shared-counter LSB matches the local
  // counter (see register_check_read_segment_request). Non-fatal; AEAD tag is authoritative.
  if ((uint8_t)(participant_ptr->session.cnt & 0xFF) != (uint8_t)msg_ptr->cnt) {
    LOG_WARNING(logger_name_ptr,
                "Shared counter LSB mismatch: peer=%u ours=%u (possible desync)",
                (unsigned)(msg_ptr->cnt & 0xFF),
                (unsigned)(participant_ptr->session.cnt & 0xFF));
    participant_ptr->state_info.last_event = SPSEC_SESS_KEY_AUTH_FAILURE;
  }

  uint8_t *nonce_ptr = NULL;
  spsec_ret_t ret = participant_generate_nonce(participant_ptr, &nonce_ptr);
  LOG_SECRET(logger_name_ptr, "Generated register_check_write_segment nonce_ptr:", nonce_ptr,
            REQUIRED_NONCE_LEN);
  if (ret != SPSEC_SUCCESS) {
    participant_ptr->session.cnt--;
    free(nonce_ptr);
    return ret;
  }

  LOG_SECRET(logger_name_ptr, "Session key for decryption:", participant_ptr->session.key,
            KEY_LEN);
  LOG_SECRET(logger_name_ptr, "Ciphertext before decryption:", msg_ptr->ciphertext_ptr,
            msg_ptr->data_len);
  LOG_SECRET(logger_name_ptr, "Auth tag for verification:", msg_ptr->auth_tag, AUTH_TAG_SIZE);

  ret = setup_crypto_context(participant_ptr, nonce_ptr, REQUIRED_NONCE_LEN,
                             participant_ptr->session.key, AUTH_TAG_SIZE);
  if (ret != SPSEC_SUCCESS) {
    participant_ptr->session.cnt--;
    free(nonce_ptr);
    return ret;
  }

  uint8_t *assoc_data_ptr = (uint8_t *)&msg_ptr->address;
  LOG_SECRET(logger_name_ptr, "Associated data for decryption:", assoc_data_ptr, 4);

  ret = decrypt_message(participant_ptr, msg_ptr->ciphertext_ptr,
                        msg_ptr->data_len, msg_ptr->auth_tag,
                        msg_ptr->data_ptr, assoc_data_ptr, 4);
  free(nonce_ptr);
  if (ret != SPSEC_SUCCESS) {
    participant_ptr->session.cnt--;
    participant_report_security_event(participant_ptr,
                                      SPSEC_SESS_KEY_AUTH_FAILURE);
    LOG_ERROR(logger_name_ptr,
              "Failed to decrypt write segment request for participant_ptr %u, "
              "address: %08x",
              msg_ptr->participant_id, msg_ptr->address);
    return ret;
  }

  return SPSEC_SUCCESS;
}

spsec_ret_t
register_apply_write_segment(Participant *participant_ptr,
                             SPsecClientWriteSegmentRequest *msg_ptr) {
  LOG_INFO(logger_name_ptr, "Applying write segment to register 0x%02x",
           participant_ptr->state_info.prepared_write_register);
  LOG_SECRET(logger_name_ptr, "Write segment data:", msg_ptr->data_ptr, msg_ptr->data_len);

  // Validate segment length matches fixed key or salt length.
  switch (participant_ptr->state_info.prepared_write_register) {
  case SPSEC_REG_PROVISIONING_KEY:
  case SPSEC_REG_INTEGRATOR_KEY:
  case SPSEC_REG_SEED_KEY:
    if (msg_ptr->data_len != KEY_LEN) {
      LOG_ERROR(logger_name_ptr, "Invalid key length %u (expected %u)",
                msg_ptr->data_len, (unsigned)KEY_LEN);
      return -1;
    }
    break;
  case SPSEC_REG_PROVISIONING_KEY_SALT:
  case SPSEC_REG_INTEGRATOR_KEY_SALT:
  case SPSEC_REG_SEED_KEY_SALT:
    if (msg_ptr->data_len != SALT_LEN) {
      LOG_ERROR(logger_name_ptr, "Invalid salt length %u (expected %u)",
                msg_ptr->data_len, (unsigned)SALT_LEN);
      return -1;
    }
    break;
  default:
    break;
  }

  switch (participant_ptr->state_info.prepared_write_register) {
  case SPSEC_REG_PROVISIONING_KEY: {
    LOG_ERROR(logger_name_ptr,
              "Provisioning Key cannot be written via protocol. It must be added manually by device manufacturer");
    return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
  }
  case SPSEC_REG_INTEGRATOR_KEY: {
    spsec_ret_t ret = apply_key(participant_ptr, 2, msg_ptr->data_ptr);
    if (ret != SPSEC_SUCCESS) {
      LOG_ERROR(logger_name_ptr, "Failed to apply integrator key: %d", ret);
      return ret;
    }
    LOG_INFO(logger_name_ptr, "Integrator key applied");
    break;
  }
  case SPSEC_REG_SEED_KEY: {
    spsec_ret_t ret = apply_key(participant_ptr, 3, msg_ptr->data_ptr);
    if (ret != SPSEC_SUCCESS) {
      LOG_ERROR(logger_name_ptr, "Failed to apply seed key: %d", ret);
      return ret;
    }
    LOG_INFO(logger_name_ptr, "Seed key applied");
    break;
  }
  case SPSEC_REG_PROVISIONING_KEY_SALT: {
    LOG_ERROR(logger_name_ptr,
              "Provisioning Key Salt cannot be written via protocol. It must be added manually by device manufacturer");
    return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
  }
  case SPSEC_REG_INTEGRATOR_KEY_SALT: {
    spsec_ret_t ret = apply_salt(participant_ptr, 2, msg_ptr->data_ptr);
    if (ret != SPSEC_SUCCESS) {
      LOG_ERROR(logger_name_ptr, "Failed to apply integrator salt: %d", ret);
      return ret;
    }
    LOG_INFO(logger_name_ptr, "Integrator salt applied");
    break;
  }
  case SPSEC_REG_SEED_KEY_SALT: {
    spsec_ret_t ret = apply_salt(participant_ptr, 3, msg_ptr->data_ptr);
    if (ret != SPSEC_SUCCESS) {
      LOG_ERROR(logger_name_ptr, "Failed to apply seed salt: %d", ret);
      return ret;
    }
    LOG_INFO(logger_name_ptr, "Seed salt applied");
    break;
  }
  case SPSEC_REG_PROVISIONING_KEY_ID: {
    LOG_ERROR(logger_name_ptr,
              "Provisioning Key ID cannot be written via protocol; must be added manually by device manufacturer");
    return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
  }
  case SPSEC_REG_INTEGRATOR_KEY_ID: {
    spsec_ret_t ret =
        apply_key_id(participant_ptr, 2, msg_ptr->data_ptr, msg_ptr->data_len);
    if (ret != SPSEC_SUCCESS) {
      LOG_ERROR(logger_name_ptr, "Failed to apply integrator key id: %d", ret);
      return ret;
    }
    LOG_INFO(logger_name_ptr, "Integrator key id applied");
    break;
  }
  case SPSEC_REG_SEED_KEY_ID: {
    spsec_ret_t ret =
        apply_key_id(participant_ptr, 3, msg_ptr->data_ptr, msg_ptr->data_len);
    if (ret != SPSEC_SUCCESS) {
      LOG_ERROR(logger_name_ptr, "Failed to apply seed key id: %d", ret);
      return ret;
    }
    LOG_INFO(logger_name_ptr, "Seed key id applied");
    break;
  }
  case SPSEC_REG_SECURE_HEARTBEAT_TIMING:
    if (msg_ptr->data_len != 1) {
      LOG_ERROR(logger_name_ptr, "Invalid data_ptr length for heartbeat timing: %u",
                msg_ptr->data_len);
      return -1;
    }
    participant_ptr->heartbeat.timing =
        (spsec_heartbeat_timing_t)msg_ptr->data_ptr[0];
    LOG_INFO(logger_name_ptr, "Heartbeat timing set to %u",
             (unsigned)participant_ptr->heartbeat.timing);
    participant_storage_save_heartbeat_timing(participant_ptr);
    break;
  case SPSEC_REG_SECURE_HEARTBEAT_MONITOR:
    if (msg_ptr->data_len != 4) {
      LOG_ERROR(logger_name_ptr,
                "Invalid data_ptr length for heartbeat monitor: %u",
                msg_ptr->data_len);
      return -1;
    }
    memcpy(participant_ptr->heartbeat.monitor.participant_ids,
           msg_ptr->data_ptr, 4);
    for (int i = 0; i < 4; i++) {
      participant_ptr->heartbeat.monitor.last_heartbeat_received[i] = 0;
      participant_ptr->heartbeat.last_received[i] = 0;
    }
    LOG_INFO_ARRAY(logger_name_ptr, "Heartbeat monitor updated:",
                   participant_ptr->heartbeat.monitor.participant_ids, 4);
    participant_storage_save_heartbeat_monitor(participant_ptr);
    break;
  case SPSEC_REG_PARTICIPANT_ID:
    if (msg_ptr->data_len != 1) {
      LOG_ERROR(logger_name_ptr,
                "Invalid data_ptr length for participant_ptr ID: %u",
                msg_ptr->data_len);
      return -1;
    }
    if (msg_ptr->data_ptr[0] < 1 || msg_ptr->data_ptr[0] > 127) {
      LOG_ERROR(logger_name_ptr,
                "Invalid participant_ptr ID value: %u (must be 1-127)",
                msg_ptr->data_ptr[0]);
      return -1;
    }
    participant_ptr->participant_id = msg_ptr->data_ptr[0];
    LOG_INFO(logger_name_ptr,
             "Participant ID set to %u (will be activated on power cycle)",
             participant_ptr->participant_id);
    participant_storage_save_participant_id(participant_ptr);
    break;
  case SPSEC_REG_SYNC_ROLE_ACTIVATION:
    if (msg_ptr->data_len != 1) {
      LOG_ERROR(
          logger_name_ptr,
          "Invalid data_ptr length for sync role activation: %u (expected 1)",
          msg_ptr->data_len);
      return -1;
    }
    if (msg_ptr->data_ptr[0] != SPSEC_SYNC_ROLE_OFF &&
        msg_ptr->data_ptr[0] != SPSEC_SYNC_ROLE_ON) {
      LOG_ERROR(
          logger_name_ptr,
          "Invalid sync role activation value: 0x%02X (only 0 or 1 are valid)",
          msg_ptr->data_ptr[0]);
      return -1;
    }
    participant_ptr->timesync.is_role_authority =
        (msg_ptr->data_ptr[0] == SPSEC_SYNC_ROLE_ON);
    LOG_INFO(logger_name_ptr, "Sync role activation set to %u (%s)",
             participant_ptr->timesync.is_role_authority ? 1 : 0,
             participant_ptr->timesync.is_role_authority ? "ON" : "OFF");
    participant_storage_save_sync_role(participant_ptr);
    break;
  case SPSEC_REG_CAN_FD_BIT_RATE:
    if (msg_ptr->data_len != 2) {
      LOG_ERROR(logger_name_ptr,
                "Invalid data_ptr length for CAN FD bit rate: %u (expected 2)",
                msg_ptr->data_len);
      return -1;
    }
    {
      uint8_t nominal_bitrate = msg_ptr->data_ptr[0];
      uint8_t data_bitrate = msg_ptr->data_ptr[1];

      bool nominal_valid = false;
      if (nominal_bitrate == SPSEC_CAN_NOMINAL_1000KBPS ||
          nominal_bitrate == SPSEC_CAN_NOMINAL_500KBPS ||
          nominal_bitrate == SPSEC_CAN_NOMINAL_250KBPS ||
          nominal_bitrate == SPSEC_CAN_NOMINAL_800KBPS ||
          nominal_bitrate >= SPSEC_CAN_NOMINAL_MANUFACTURER_MIN) {
        nominal_valid = true;
      }

      bool data_valid = false;
      if (data_bitrate == SPSEC_CAN_DATA_1MBPS ||
          data_bitrate == SPSEC_CAN_DATA_2MBPS ||
          data_bitrate == SPSEC_CAN_DATA_5MBPS ||
          data_bitrate == SPSEC_CAN_DATA_4MBPS ||
          data_bitrate == SPSEC_CAN_DATA_8MBPS ||
          data_bitrate == SPSEC_CAN_DATA_10MBPS ||
          data_bitrate >= SPSEC_CAN_DATA_MANUFACTURER_MIN) {
        data_valid = true;
      }

      if (!nominal_valid) {
        LOG_ERROR(logger_name_ptr, "Invalid nominal bitrate value: 0x%02X",
                  nominal_bitrate);
        return -1;
      }
      if (!data_valid) {
        LOG_ERROR(logger_name_ptr, "Invalid data_ptr bitrate value: 0x%02X",
                  data_bitrate);
        return -1;
      }

      participant_ptr->state_info.can_fd_bitrate.rates.nominal_bitrate =
          nominal_bitrate;
      participant_ptr->state_info.can_fd_bitrate.rates.data_bitrate =
          data_bitrate;
      LOG_INFO(logger_name_ptr,
               "CAN FD bit rate set: nominal=0x%02X, data_ptr=0x%02X (will be "
               "activated on power cycle)",
               nominal_bitrate, data_bitrate);
      participant_storage_save_can_bitrate(participant_ptr);
    }
    break;
  case SPSEC_REG_MANUFACTURER_RESET:
    if (msg_ptr->data_len != 4) {
      LOG_ERROR(
          logger_name_ptr,
          "Invalid data_ptr length for manufacturer reset: %u (expected 4)",
          msg_ptr->data_len);
      return -1;
    }
    if (!participant_ptr->session.auth_tag_data_ptr) {
      LOG_ERROR(logger_name_ptr, "No active session for manufacturer reset");
      return -1;
    }
    if (participant_ptr->session.auth_tag_data_ptr->key_selector[0] !=
        KEY_SELECTOR_INTEGRATOR) {
      LOG_ERROR(logger_name_ptr,
                "Manufacturer reset requires session based on Integrator Key "
                "(current: %u)",
                participant_ptr->session.auth_tag_data_ptr->key_selector[0]);
      return -1;
    }
    {
      uint32_t reset_value = (uint32_t)msg_ptr->data_ptr[0] |
                             ((uint32_t)msg_ptr->data_ptr[1] << 8) |
                             ((uint32_t)msg_ptr->data_ptr[2] << 16) |
                             ((uint32_t)msg_ptr->data_ptr[3] << 24);
      if (reset_value != SPSEC_MANUFACTURER_RESET_VALUE) {
        LOG_ERROR(logger_name_ptr,
                  "Invalid manufacturer reset value: 0x%08X (expected 0x%08X)",
                  reset_value, SPSEC_MANUFACTURER_RESET_VALUE);
        return -1;
      }

      LOG_WARNING(logger_name_ptr, "Manufacturer reset requested - will be "
                               "applied on next power cycle");
      participant_ptr->state_info.manufacturer_reset_pending = true;

      if (nvol_storage_write_u8("config/manufacturer_reset", 1) < 0) {
        LOG_ERROR(logger_name_ptr, "Failed to save manufacturer reset flag");
        return -1;
      }

      LOG_INFO(logger_name_ptr,
               "Manufacturer reset flag saved. Integrator and Seed keys will "
               "be erased on next power cycle.");
    }
    break;
  case SPSEC_REG_CODE_UPDATE_FILE: {
    // Accumulate segmented file chunks until complete image has arrived
    if (!participant_ptr->write_accum.active) {
      LOG_ERROR(logger_name_ptr,
                "92h segment arrived without an active prepared write; "
                "ignoring");
      return -1;
    }
    if (msg_ptr->data_len == 0) {
      LOG_ERROR(logger_name_ptr, "92h segment with zero data length");
      return -1;
    }
    if ((uint32_t)msg_ptr->data_len >
        participant_ptr->write_accum.expected - participant_ptr->write_accum.len) {
      LOG_ERROR(logger_name_ptr,
                "92h segment would overflow negotiated total: accum_ptr=%u "
                "+len=%u > expected=%u",
                participant_ptr->write_accum.len, (unsigned)msg_ptr->data_len,
                participant_ptr->write_accum.expected);
      // Drop any half-written buffer so the operator must re-initiate cleanly.
      write_accum_reset(&participant_ptr->write_accum);
      return -1;
    }
    memcpy(participant_ptr->write_accum.buf + participant_ptr->write_accum.len,
           msg_ptr->data_ptr, msg_ptr->data_len);
    participant_ptr->write_accum.len += msg_ptr->data_len;
    LOG_DEBUG(logger_name_ptr,
              "92h accum_ptr: +%u bytes (now %u / %u)",
              (unsigned)msg_ptr->data_len, participant_ptr->write_accum.len,
              participant_ptr->write_accum.expected);

    if (participant_ptr->write_accum.len < participant_ptr->write_accum.expected) {
      // Partial segment - acknowledge success but do not touch storage.
      LOG_INFO(logger_name_ptr,
               "92h segment accepted (%u / %u bytes accumulated)",
               participant_ptr->write_accum.len,
               participant_ptr->write_accum.expected);
      return 0;
    }

    // Require provisioned public authentication key before storing image
    {
      extern signed char device_info_get_public_auth_key(uint8_t *key,
                                                         size_t *key_size);
      size_t key_size = 256;
      uint8_t *pub_key_ptr = malloc(key_size);
      if (!pub_key_ptr ||
          device_info_get_public_auth_key(pub_key_ptr, &key_size) != 0 ||
          key_size == 0) {
        LOG_ERROR(logger_name_ptr,
                  "Public authentication key not available - FAIL CLOSED");
        if (pub_key_ptr)
          free(pub_key_ptr);
        write_accum_reset(&participant_ptr->write_accum);
        return -1;
      }
      free(pub_key_ptr);
    }

    if (nvol_storage_write_varlen("code_update/update_file",
                                  participant_ptr->write_accum.buf,
                                  participant_ptr->write_accum.len) == 0) {
      LOG_INFO(logger_name_ptr,
               "Code update file saved to storage (%u bytes, will be processed "
               "on next power cycle)",
               participant_ptr->write_accum.len);
      write_accum_reset(&participant_ptr->write_accum);
    } else {
      LOG_ERROR(logger_name_ptr, "Failed to save code update file to storage");
      write_accum_reset(&participant_ptr->write_accum);
      return -1;
    }
  }
    break;
  default:
    LOG_ERROR(logger_name_ptr, "Unimplemented register value 0x%02x",
              participant_ptr->state_info.prepared_write_register);
    return -1;
  }
  return 0;
}

static spsec_ret_t
prepare_write_segment_response(Participant *participant_ptr, uint8_t err,
                               SPsecClientWriteSegmentResponse **response_ptr) {
  *response_ptr = spsecwritesegmentresponse_new(participant_ptr->participant_id,
                                            participant_ptr->session.cnt, err);
  if (!*response_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to create write segment response_ptr");
    return SPSEC_ERROR_OUT_OF_MEMORY;
  }
  set_write_segment_response_address(*response_ptr);
  return SPSEC_SUCCESS;
}

spsec_ret_t register_send_write_segment_response(Participant *participant_ptr,
                                                 uint8_t err) {
  SPsecClientWriteSegmentResponse *response_ptr = NULL;
  uint8_t *nonce_ptr = NULL;
  spsec_ret_t ret = SPSEC_SUCCESS;

  ret = prepare_write_segment_response(participant_ptr, err, &response_ptr);
  if (ret != SPSEC_SUCCESS)
    return ret;

  ret = participant_generate_nonce(participant_ptr, &nonce_ptr);
  LOG_SECRET(logger_name_ptr, "Write segment response_ptr nonce_ptr:", nonce_ptr, REQUIRED_NONCE_LEN);
  if (ret != SPSEC_SUCCESS) {
    if (response_ptr)
      spsecwritesegmentresponse_free(response_ptr);
    if (nonce_ptr)
      free(nonce_ptr);
    return ret;
  }

  ret = setup_crypto_context(participant_ptr, nonce_ptr, REQUIRED_NONCE_LEN,
                             participant_ptr->session.key, AUTH_TAG_SIZE);
  if (ret != SPSEC_SUCCESS) {
    if (response_ptr)
      spsecwritesegmentresponse_free(response_ptr);
    if (nonce_ptr)
      free(nonce_ptr);
    return ret;
  }

  uint8_t *assoc_data_ptr = (uint8_t *)&response_ptr->address;
  ret = encrypt_message(participant_ptr, response_ptr->plaintext, 4,
                        response_ptr->ciphertext, response_ptr->auth_tag,
                        assoc_data_ptr, 4);
  if (ret != SPSEC_SUCCESS) {
    if (response_ptr)
      spsecwritesegmentresponse_free(response_ptr);
    if (nonce_ptr)
      free(nonce_ptr);
    return ret;
  }

  LOG_SECRET(logger_name_ptr, "Write segment response_ptr plaintext:", response_ptr->plaintext,
            sizeof(response_ptr->plaintext));
  LOG_SECRET(logger_name_ptr, "Write segment response_ptr ciphertext:", response_ptr->ciphertext,
            sizeof(response_ptr->ciphertext));
  LOG_SECRET(logger_name_ptr, "Write segment response_ptr auth tag:", response_ptr->auth_tag,
            AUTH_TAG_SIZE);

  ret = participant_channel_send_write_segment_response(
      &participant_ptr->secure_channel, response_ptr);
  if (ret != SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr, "Failed to send write segment response_ptr");
    if (response_ptr)
      spsecwritesegmentresponse_free(response_ptr);
    if (nonce_ptr)
      free(nonce_ptr);
    return ret;
  }

  LOG_INFO(logger_name_ptr, "Write segment response_ptr sent successfully");
  if (response_ptr)
    spsecwritesegmentresponse_free(response_ptr);
  if (nonce_ptr)
    free(nonce_ptr);
  return SPSEC_SUCCESS;
}
