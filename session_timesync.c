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

#include "crypto_kdf.h"
#include "keys.h"
#include "participant.h"
#include "participant_channel.h"
#include "spsec_common.h"
#include "spsec_registers.h"
#include <stdint.h>

static const char *logger_name_ptr = "part_session_timesync";

// Recompute and verify the mTLS auth tag on a CPMT_AUTH_TIME response.
static signed char verify_mtls_auth_tag(Participant *participant_ptr,
                                        uint8_t *random_bytes_ptr,
                                        uint8_t *timestamp_ptr, uint8_t *csalt_ptr,
                                        uint8_t participant_id,
                                        uint8_t *received_tag_ptr,
                                        uint8_t *one_time_key_ptr) {
  size_t nonce_len = crypto_get_nonce_len(participant_ptr->crypto_algorithm);
  uint8_t nonce[REQUIRED_NONCE_LEN];
  memset(nonce, 0, sizeof(nonce));
  if (crypto_handler_set_context(&participant_ptr->crypto_handler, one_time_key_ptr,
                                 nonce, nonce_len, 8) != 0) {
    LOG_ERROR(logger_name_ptr, "Failed to set crypto context");
    return -5;
  }
  // Associated data: rnd || tim || csalt_ptr || can_id (32 bytes)
  uint8_t assoc_data[RANDOM_SIZE + TIMESTAMP_SIZE + 4 + 4];
  memcpy(assoc_data, random_bytes_ptr, RANDOM_SIZE);
  memcpy(assoc_data + RANDOM_SIZE, timestamp_ptr, TIMESTAMP_SIZE);
  memcpy(assoc_data + RANDOM_SIZE + TIMESTAMP_SIZE, csalt_ptr, 4);
  uint32_t can_id =
      (0x00230000 | (CPMT_AUTH_TIME << 8) | (participant_id | 0x80));
  assoc_data[RANDOM_SIZE + TIMESTAMP_SIZE + 4 + 0] = (uint8_t)(can_id & 0xFF);
  assoc_data[RANDOM_SIZE + TIMESTAMP_SIZE + 4 + 1] =
      (uint8_t)((can_id >> 8) & 0xFF);
  assoc_data[RANDOM_SIZE + TIMESTAMP_SIZE + 4 + 2] =
      (uint8_t)((can_id >> 16) & 0xFF);
  assoc_data[RANDOM_SIZE + TIMESTAMP_SIZE + 4 + 3] =
      (uint8_t)((can_id >> 24) & 0xFF);
  if (crypto_handler_update(&participant_ptr->crypto_handler, assoc_data, 32) !=
      0) {
    LOG_ERROR(logger_name_ptr, "Failed to update crypto handler");
    return -6;
  }
  uint8_t calc_tag[8];
  size_t tag_len = 8;
  if (crypto_handler_get_digest(&participant_ptr->crypto_handler, calc_tag,
                                &tag_len) != 0) {
    LOG_ERROR(logger_name_ptr, "Failed to get digest");
    return -7;
  }
  if (spsec_ct_memcmp(calc_tag, received_tag_ptr, 8) != 0) {
    LOG_ERROR(logger_name_ptr,
              "Invalid authentication tag in CPMT_AUTH_TIME response");
    participant_report_security_event(participant_ptr, SPSEC_SYNC_REQ_AUTH_FAILURE);
    return -8;
  }
  return 0;
}

// HKDF the one-time key for a time sync exchange (SPsec302) from the seed
// key and rnd||tim||csalt salt.
static signed char calculate_one_time_key(Participant *participant_ptr,
                                          uint8_t *random_bytes_ptr,
                                          uint8_t *timestamp_ptr,
                                          uint8_t *csalt_ptr,
                                          uint8_t *one_time_key_ptr) {
  // 192-bit salt per SPsec302 V40 §6.5.2: rnd[12] || tim[8] || csalt[4].
  uint8_t salt[24];
  memcpy(salt, random_bytes_ptr, 12); // Use first 12 bytes of random (96 bits)
  memcpy(salt + 12, timestamp_ptr, 8); // tim: 8 bytes (64 bits)
  memcpy(salt + 20, csalt_ptr, 4);         // csalt_ptr: 4 bytes (32 bits)
  // Debug only: show HKDF salt used for one-time key derivation
  LOG_SECRET(logger_name_ptr, "HKDF salt (rnd[12]||tim||csalt_ptr):", salt, sizeof(salt));
  if (!participant_ptr->comm_keys.spsec_keys[3]) {
    LOG_ERROR(logger_name_ptr, "Invalid seed key");
    return -3;
  }
  if (crypto_hkdf_sha256(participant_ptr->comm_keys.spsec_keys[3]->key, KEY_LEN,
                         salt, sizeof(salt), NULL, 0, one_time_key_ptr,
                         KEY_LEN) != 0) {
    LOG_ERROR(logger_name_ptr, "Failed to compute HKDF for one-time key");
    return -4;
  }
  // Debug only: show derived one-time key
  LOG_SECRET(logger_name_ptr, "Derived one-time key:", one_time_key_ptr,
            KEY_LEN);
  return 0;
}

// As time sync client: verify a CPMT_AUTH_TIME response, apply the offset,
// and mark ourselves synchronized.
signed char participant_process_mtls_auth_time(Participant *participant_ptr,
                                               SPsecTimeSyncResponse *msg_ptr,
                                               uint8_t *random_bytes_ptr) {
  if (!msg_ptr || !random_bytes_ptr) {
    LOG_ERROR(logger_name_ptr, "Invalid arguments: msg_ptr=%p, random_bytes_ptr=%p",
              msg_ptr, random_bytes_ptr);
    return -2;
  }
  if (msg_ptr->participant_id != participant_ptr->participant_id) {
    LOG_INFO(logger_name_ptr, "Time sync response for PID %u, our PID is %u",
             msg_ptr->participant_id, participant_ptr->participant_id);
    return 1;
  }
  // Debug only: log input materials
  LOG_SECRET(logger_name_ptr, "Received timestamp_ptr:", msg_ptr->timestamp, TIMESTAMP_SIZE);
  LOG_SECRET(logger_name_ptr, "Received csalt_ptr:", msg_ptr->csalt, 4);
  LOG_SECRET(logger_name_ptr, "Our random (from request):", random_bytes_ptr, RANDOM_SIZE);
  LOG_SECRET(logger_name_ptr, "Received auth tag:", msg_ptr->auth_tag_ptr, AUTH_TAG_SIZE);
  uint8_t one_time_key_ptr[KEY_LEN];
  signed char ret = calculate_one_time_key(participant_ptr, random_bytes_ptr,
                                           msg_ptr->timestamp,
                                           msg_ptr->csalt, one_time_key_ptr);
  if (ret < 0)
    return ret;
  // Prepare and log associated data_ptr to match TimeSync responder
  uint8_t assoc_data_dbg[RANDOM_SIZE + TIMESTAMP_SIZE + 4 + 4];
  memcpy(assoc_data_dbg, random_bytes_ptr, RANDOM_SIZE);
  memcpy(assoc_data_dbg + RANDOM_SIZE, msg_ptr->timestamp, TIMESTAMP_SIZE);
  memcpy(assoc_data_dbg + RANDOM_SIZE + TIMESTAMP_SIZE, msg_ptr->csalt, 4);
  uint32_t can_id_dbg =
      (0x00230000 | (CPMT_AUTH_TIME << 8) | (msg_ptr->participant_id | 0x80));
  assoc_data_dbg[RANDOM_SIZE + TIMESTAMP_SIZE + 4 + 0] =
      (uint8_t)(can_id_dbg & 0xFF);
  assoc_data_dbg[RANDOM_SIZE + TIMESTAMP_SIZE + 4 + 1] =
      (uint8_t)((can_id_dbg >> 8) & 0xFF);
  assoc_data_dbg[RANDOM_SIZE + TIMESTAMP_SIZE + 4 + 2] =
      (uint8_t)((can_id_dbg >> 16) & 0xFF);
  assoc_data_dbg[RANDOM_SIZE + TIMESTAMP_SIZE + 4 + 3] =
      (uint8_t)((can_id_dbg >> 24) & 0xFF);
  LOG_SECRET(logger_name_ptr, "Associated Data (random||timestamp_ptr||csalt_ptr||can_idLE):",
            assoc_data_dbg, sizeof(assoc_data_dbg));
  ret = verify_mtls_auth_tag(
      participant_ptr, random_bytes_ptr, msg_ptr->timestamp, msg_ptr->csalt,
      msg_ptr->participant_id, msg_ptr->auth_tag_ptr, one_time_key_ptr);
  if (ret < 0)
    return ret;

  // Store csalt_ptr for communication key derivation
  communication_keys_set_csalt(&participant_ptr->comm_keys, msg_ptr->csalt);
  LOG_SECRET(logger_name_ptr, "Stored csalt_ptr for communication key derivation:",
            participant_ptr->comm_keys.csalt, 4);
  {
    uint8_t adjusted_ts[8];
    memcpy(adjusted_ts, msg_ptr->timestamp, 8);
    if (participant_ptr->timesync.offset != 0) {
      uint64_t ts = 0;
      for (int i = 0; i < 8; i++)
        ts |= ((uint64_t)adjusted_ts[i]) << (i * 8);
      // offset is in reference 0.1ms ticks - convert to the timer's actual
      // tick domain so it keeps its configured duration at every bitrate.
      ts += timer_reference_ticks(&participant_ptr->timer,
                                  (uint64_t)participant_ptr->timesync.offset);
      for (int i = 0; i < 8; i++)
        adjusted_ts[i] = (uint8_t)((ts >> (i * 8)) & 0xFF);
    }

    LOG_DEBUG_ARRAY(logger_name_ptr, "Received timestamp_ptr:",
                    msg_ptr->timestamp, TIMESTAMP_SIZE);
    LOG_DEBUG_ARRAY(logger_name_ptr, "Adjusted timestamp_ptr:",
                    adjusted_ts, sizeof(adjusted_ts));

    if (timer_set_timestamp(&participant_ptr->timer, adjusted_ts) != 0) {
      LOG_ERROR(logger_name_ptr, "Failed to set timestamp_ptr");
      return -9;
    }
  }
  participant_ptr->timesync.is_synchronized = true;
  participant_ptr->timesync.last_successful =
      timer_get_current_time_us(&participant_ptr->timer);
  free(participant_ptr->timesync.last_random_ptr);
  participant_ptr->timesync.last_random_ptr = NULL;
  LOG_INFO(logger_name_ptr, "Time synchronized successfully");
  return 0;
}

// Send a CPMT_AUTH_TIME request; returns the random nonce used (caller frees).
uint8_t *participant_send_timesync_request(Participant *participant_ptr) {
  uint8_t *random_ptr = random_generator_get_bytes(
      &participant_ptr->random_generator, RANDOM_SIZE);
  if (!random_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to allocate random_ptr bytes");
    return NULL;
  }
  SPsecTimeSyncRequest *req_ptr =
      timesyncrequest_new(participant_ptr->participant_id, random_ptr);
  if (!req_ptr) {
    free(random_ptr);
    return NULL;
  }
  signed char ret = participant_channel_send_timesync_request(
      &participant_ptr->secure_channel, req_ptr);
  timesyncrequest_free(req_ptr);
  if (ret < 0) {
    LOG_ERROR(logger_name_ptr, "Failed to send timesync request");
    free(random_ptr);
    return NULL;
  }
  return random_ptr;
}

// As time authority: derive the one-time key, sign, and reply to a
// CPMT_AUTH_TIME request.
signed char timesync_process_mtls_auth_time(Participant *participant_ptr,
                                            SPsecTimeSyncRequest *msg_ptr) {
  LOG_INFO(logger_name_ptr, "Received CPMT_AUTH_TIME");
  uint8_t timestamp_ptr[8];
  timer_get_timestamp(&participant_ptr->timer, timestamp_ptr);
  LOG_SECRET(logger_name_ptr, "Random:", msg_ptr->random, RANDOM_SIZE);
  LOG_DEBUG_ARRAY(logger_name_ptr, "Generated timestamp_ptr:",
                  timestamp_ptr, sizeof(timestamp_ptr));

  // Use the csalt_ptr that was generated when time sync role entered SECURE state
  // This ensures all participants use the same csalt_ptr for communication key
  // derivation
  uint8_t csalt_ptr[4];
  // Ensure valid csalt_ptr is present before responding
  bool csalt_set = false;
  for (int i = 0; i < 4; i++) {
    if (participant_ptr->comm_keys.csalt[i] != 0) {
      csalt_set = true;
      break;
    }
  }
  if (!csalt_set) {
    LOG_ERROR(logger_name_ptr,
              "Time sync role: csalt_ptr not yet generated (request arrived "
              "before SECURE state transition completed) - rejecting");
    return -1;
  }
  memcpy(csalt_ptr, participant_ptr->comm_keys.csalt, 4);
  LOG_SECRET(logger_name_ptr, "Using csalt_ptr for time sync response:", csalt_ptr, 4);

  // 192-bit salt per SPsec302 V40 §6.5.2: rnd[12] || tim[8] || csalt[4].
  uint8_t salt[24];
  memcpy(salt, msg_ptr->random,
         12); // Use first 12 bytes of random (96 bits)
  memcpy(salt + 12, timestamp_ptr, 8); // tim: 8 bytes (64 bits)
  memcpy(salt + 20, csalt_ptr, 4);         // csalt_ptr: 4 bytes (32 bits)
  LOG_SECRET(logger_name_ptr, "Salt (rnd[12]||tim||csalt_ptr):", salt, sizeof(salt));
  LOG_SECRET(logger_name_ptr, "Seed key:", participant_ptr->comm_keys.spsec_keys[3]->key,
            KEY_LEN);
  uint8_t one_time_key_ptr[KEY_LEN];
  if (crypto_hkdf_sha256(participant_ptr->comm_keys.spsec_keys[3]->key, KEY_LEN,
                         salt, sizeof(salt), NULL, 0, one_time_key_ptr,
                         KEY_LEN) != 0) {
    LOG_ERROR(logger_name_ptr, "Failed to compute HKDF for one-time key");
    return -1;
  }
  LOG_SECRET(logger_name_ptr, "One-time key:", one_time_key_ptr, KEY_LEN);
  size_t nonce_len = crypto_get_nonce_len(participant_ptr->crypto_algorithm);
  uint8_t nonce[REQUIRED_NONCE_LEN];
  memset(nonce, 0, sizeof(nonce));
  if (crypto_handler_set_context(&participant_ptr->crypto_handler, one_time_key_ptr,
                                 nonce, nonce_len, 8) != SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr, "Failed to set crypto context for timesync response");
    return -1;
  }
  // Associated data_ptr: rnd || tim || csalt_ptr || can_id (32 bytes)
  uint8_t assoc_data[RANDOM_SIZE + TIMESTAMP_SIZE + 4 + 4];
  memcpy(assoc_data, msg_ptr->random, RANDOM_SIZE);
  memcpy(assoc_data + RANDOM_SIZE, timestamp_ptr, TIMESTAMP_SIZE);
  memcpy(assoc_data + RANDOM_SIZE + TIMESTAMP_SIZE, csalt_ptr, 4);
  uint32_t can_id = (0x00230000 | ((CPMT_AUTH_TIME & 0xFF) << 8) |
                     (msg_ptr->participant_id | 0x80));
  assoc_data[RANDOM_SIZE + TIMESTAMP_SIZE + 4 + 0] = (uint8_t)(can_id & 0xFF);
  assoc_data[RANDOM_SIZE + TIMESTAMP_SIZE + 4 + 1] =
      (uint8_t)((can_id >> 8) & 0xFF);
  assoc_data[RANDOM_SIZE + TIMESTAMP_SIZE + 4 + 2] =
      (uint8_t)((can_id >> 16) & 0xFF);
  assoc_data[RANDOM_SIZE + TIMESTAMP_SIZE + 4 + 3] =
      (uint8_t)((can_id >> 24) & 0xFF);
  LOG_SECRET(logger_name_ptr, "Associated Data (rnd||tim||csalt_ptr||can_id):", assoc_data,
            sizeof(assoc_data));
  if (crypto_handler_update(&participant_ptr->crypto_handler, assoc_data, 32) != SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr, "Failed to update crypto context for timesync response");
    return -1;
  }
  uint8_t auth_tag[AUTH_TAG_SIZE];
  size_t tag_len = AUTH_TAG_SIZE;
  if (crypto_handler_get_digest(&participant_ptr->crypto_handler, auth_tag,
                                &tag_len) != SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr, "Failed to generate auth tag for timesync response");
    return -1;
  }
  LOG_SECRET(logger_name_ptr, "Generated Authentication Tag:", auth_tag, AUTH_TAG_SIZE);

  // Store csalt_ptr for communication key derivation (time sync role also needs it)
  communication_keys_set_csalt(&participant_ptr->comm_keys, csalt_ptr);
  LOG_SECRET(logger_name_ptr, "Stored csalt_ptr for communication key derivation:",
            participant_ptr->comm_keys.csalt, 4);

  SPsecTimeSyncResponse *resp_ptr =
      timesyncresponse_new(timestamp_ptr, csalt_ptr, auth_tag, AUTH_TAG_SIZE,
                           msg_ptr->participant_id);
  if (!resp_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to create timesync response");
    return -1;
  }
  int ret = participant_channel_send_timesync_response(
      &participant_ptr->secure_channel, resp_ptr);
  timesyncresponse_free(resp_ptr);
  if (ret < 0) {
    LOG_ERROR(logger_name_ptr, "Failed to send timesync response");
    return -1;
  }
  return 0;
}

// Block, retrying CPMT_AUTH_TIME requests, until time sync succeeds.
signed char participant_synchronize_time(Participant *participant_ptr) {
  while (!participant_ptr->timesync.is_synchronized) {
    free(participant_ptr->timesync.last_random_ptr);
    participant_ptr->timesync.last_random_ptr =
        participant_send_timesync_request(participant_ptr);
    if (!participant_ptr->timesync.last_random_ptr) {
      LOG_ERROR(logger_name_ptr, "Failed to send timesync request");
      return -1;
    }
    SPsecMessage *msg_ptr = participant_channel_receive(
        &participant_ptr->secure_channel,
        participant_ptr->timesync.retry_delay_seconds * 1000);
    if (!msg_ptr) {
      LOG_INFO(logger_name_ptr, "No response received within %d seconds",
               participant_ptr->timesync.retry_delay_seconds);
      continue;
    }
    if (msg_ptr->msg_type != CPMT_AUTH_TIME) {
      LOG_ERROR(logger_name_ptr, "Received unexpected message type: %d",
                msg_ptr->msg_type);
      // Type-aware free: an unexpected app-data/heartbeat/broadcast here would
      // leak its internal buffers under a plain free().
      spsecmessage_dispose(msg_ptr);
      continue;
    }
    int ret = participant_process_mtls_auth_time(
        participant_ptr, msg_ptr->msg_content_ptr,
        participant_ptr->timesync.last_random_ptr);
    timesyncresponse_free(msg_ptr->msg_content_ptr);
    spsecmessage_free(msg_ptr);
    if (ret == 0) {
      LOG_INFO(logger_name_ptr, "Time synchronized");
      free(participant_ptr->timesync.last_random_ptr);
      participant_ptr->timesync.last_random_ptr = NULL;
      return 0;
    }
    LOG_ERROR(logger_name_ptr, "Failed to process CPMT_AUTH_TIME response: %d",
              ret);
    if (ret == -8) {
      participant_report_security_event(participant_ptr, SPSEC_SYNC_REFR_AUTH_FAILURE);
    }
  }
  return 0;
}

// True once too long has passed since the last successful time sync
// (SPsec302 periodic re-sync requirement).
bool participant_should_abort_on_sync_failure(Participant *participant_ptr,
                                              uint64_t now_us) {
  if (!participant_ptr) {
    return false;
  }
  // Never abort a node that was never synchronized in the first place - it is
  // already in WAITING doing parameter authentication.
  if (!participant_ptr->timesync.is_synchronized) {
    return false;
  }
  // A zero window disables Sync-restart detection entirely.
  if (participant_ptr->timesync.broadcast_wait_us == 0) {
    return false;
  }
  // Wrap-safe: last_successful is sampled from the same monotonic timer.
  uint64_t since_last_ok = now_us - participant_ptr->timesync.last_successful;
  return since_last_ok > participant_ptr->timesync.broadcast_wait_us;
}

signed char participant_check_timesync_refresh(Participant *participant_ptr) {
  if (!participant_ptr || !participant_ptr->timesync.is_synchronized) {
    return 0; // Not synchronized yet, refresh check not applicable
  }

  if (participant_ptr->timesync.refresh_interval_us == 0) {
    return 0; // Refresh checking disabled
  }

  uint64_t current_time = timer_get_current_time_us(&participant_ptr->timer);
  uint64_t time_since_sync =
      current_time - participant_ptr->timesync.last_successful;

  if (time_since_sync >= participant_ptr->timesync.refresh_interval_us) {
    LOG_WARNING(
        logger_name_ptr,
        "Time sync refresh timeout: %llu us since last sync (limit: "
        "%llu us)",
        (unsigned long long)time_since_sync,
        (unsigned long long)participant_ptr->timesync.refresh_interval_us);

    // SPsec302 V40 Section 8.2: Generate SYNC_REFR_TIMEOUT security event
    participant_ptr->state_info.last_event = SPSEC_SYNC_REFR_TIMEOUT;
    participant_report_security_event(participant_ptr, SPSEC_SYNC_REFR_TIMEOUT);

    // Reset time sync status to force re-synchronization
    participant_ptr->timesync.is_synchronized = false;

    return 1;
  }

  return 0;
}
