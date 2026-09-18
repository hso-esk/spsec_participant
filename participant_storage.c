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

#include "participant_storage.h"
#include "keys.h"
#include "nvol_storage.h"
#include "participant.h"
#include "spsec_common.h"
#include "spsec_registers.h"

static const char *logger_name_ptr = "participant_storage";

// Forward declaration
signed char participant_storage_delete_key(Participant *participant_ptr,
                                           uint8_t key_index);

// Load all keys and configuration from storage.
signed char participant_storage_load_all(Participant *participant_ptr) {
  if (!participant_ptr) {
    LOG_ERROR(logger_name_ptr, "Invalid participant pointer");
    return -1;
  }

  signed char ret = 0;

  // Load keys (1=provisioning, 2=integrator, 3=seed)
  for (uint8_t i = 1; i <= 3; i++) {
    const char *key_names[] = {"", "provisioning", "integrator", "seed"};
    char key_path[128], salt_path[128], keyid_path[128];

    snprintf(key_path, sizeof(key_path), "keys/%s_key", key_names[i]);
    snprintf(salt_path, sizeof(salt_path), "keys/%s_salt", key_names[i]);
    snprintf(keyid_path, sizeof(keyid_path), "keys/%s_keyid", key_names[i]);

    // Load key
    uint8_t key[32];
    if (nvol_storage_read_key(key_path, key) == 0) {
      // Load key ID first if available; default to selector index i if key ID file absent
      uint32_t key_id = (uint32_t)i;
      nvol_storage_read_key_id(keyid_path, &key_id);

      if (participant_ptr->comm_keys.spsec_keys[i] == NULL) {
        participant_ptr->comm_keys.spsec_keys[i] = spseckey_new(key_id, key);
      } else {
        spseckey_set(participant_ptr->comm_keys.spsec_keys[i], key);
        if (key_id != (uint32_t)SPSEC_KEY_ID_RESERVED) {
          spseckey_set_id(participant_ptr->comm_keys.spsec_keys[i], key_id);
        }
      }
      LOG_INFO(logger_name_ptr, "Loaded %s key from storage", key_names[i]);
    }

    // Load salt (full SALT_LEN bytes)
    uint8_t salt[SALT_LEN];
    if (nvol_storage_read_salt(salt_path, salt) == 0) {
      if (participant_ptr->comm_keys.spsec_salt[i] == NULL) {
        participant_ptr->comm_keys.spsec_salt[i] = spsecsalt_new(salt);
      } else {
        spsecsalt_set(participant_ptr->comm_keys.spsec_salt[i], salt);
      }
      LOG_INFO(logger_name_ptr, "Loaded %s salt from storage", key_names[i]);
    }
  }

  // Load configuration
  uint8_t u8_val;
  if (nvol_storage_read_u8("config/participant_id", &u8_val) == 0) {
    if (u8_val >= 1 && u8_val <= 127) {
      participant_ptr->participant_id = u8_val;
      LOG_INFO(logger_name_ptr, "Loaded participant ID: %u", u8_val);
    }
  }

  if (nvol_storage_read_u8("config/heartbeat_timing", &u8_val) == 0) {
    // Validate against the known enum set (0-6 standard, 0x80-0x8F manufacturer)
    // before applying, mirroring the participant_id range check above.
    if (u8_val <= SPSEC_HEARTBEAT_250MS ||
        (u8_val >= SPSEC_HEARTBEAT_MANUFACTURER_MIN &&
         u8_val <= SPSEC_HEARTBEAT_MANUFACTURER_MAX)) {
      participant_ptr->heartbeat.timing = (spsec_heartbeat_timing_t)u8_val;
      LOG_INFO(logger_name_ptr, "Loaded heartbeat timing: %u", u8_val);
    } else {
      LOG_WARNING(logger_name_ptr,
                  "Ignoring invalid persisted heartbeat timing 0x%02X", u8_val);
    }
  }

  uint32_t u32_val;
  if (nvol_storage_read_u32("config/heartbeat_monitor", &u32_val) == 0) {
    memcpy(participant_ptr->heartbeat.monitor.participant_ids, &u32_val, 4);
    LOG_INFO(logger_name_ptr, "Loaded heartbeat monitor config");
  }

  if (nvol_storage_read_u8("config/sync_role", &u8_val) == 0) {
    participant_ptr->timesync.is_role_authority =
        (u8_val == SPSEC_SYNC_ROLE_ON);
    LOG_INFO(logger_name_ptr, "Loaded sync role: %s",
             participant_ptr->timesync.is_role_authority ? "ON" : "OFF");
  }

  uint16_t u16_val;
  if (nvol_storage_read_u16("config/can_bitrate", &u16_val) == 0) {
    participant_ptr->state_info.can_fd_bitrate.raw = u16_val;
    LOG_INFO(logger_name_ptr, "Loaded CAN bitrate: nominal=0x%02X, data=0x%02X",
             participant_ptr->state_info.can_fd_bitrate.rates.nominal_bitrate,
             participant_ptr->state_info.can_fd_bitrate.rates.data_bitrate);
  }

  // Load timestamp
  uint64_t persisted_timestamp;
  if (nvol_storage_read_u64("config/timestamp_ptr", &persisted_timestamp) == 0) {
    uint8_t ts_bytes[8];
    for (int i = 0; i < 8; i++) {
      ts_bytes[i] = (uint8_t)((persisted_timestamp >> (i * 8)) & 0xFF);
    }
    timer_set_timestamp(&participant_ptr->timer, ts_bytes);
    LOG_INFO(logger_name_ptr, "Loaded persistent timestamp");
  }

  // Check for manufacturer reset flag
  uint8_t reset_flag;
  if (nvol_storage_read_u8("config/manufacturer_reset", &reset_flag) == 0 &&
      reset_flag != 0) {
    LOG_WARNING(logger_name_ptr,
                "Manufacturer reset flag detected - applying reset");
    // Delete Integrator and Seed keys from storage and RAM
    participant_storage_delete_key(participant_ptr, 2); // Integrator
    participant_storage_delete_key(participant_ptr, 3); // Seed
    memset(participant_ptr->comm_keys.even_key, 0,
           sizeof(participant_ptr->comm_keys.even_key));
    memset(participant_ptr->comm_keys.odd_key, 0,
           sizeof(participant_ptr->comm_keys.odd_key));
    memset(participant_ptr->comm_keys.even_key_ts_part, 0,
           sizeof(participant_ptr->comm_keys.even_key_ts_part));
    memset(participant_ptr->comm_keys.odd_key_ts_part, 0,
           sizeof(participant_ptr->comm_keys.odd_key_ts_part));
    memset(participant_ptr->comm_keys.csalt, 0,
           sizeof(participant_ptr->comm_keys.csalt));
    // Clear reset flag
    nvol_storage_write_u8("config/manufacturer_reset", 0);
    LOG_INFO(logger_name_ptr,
             "Manufacturer reset applied - keys erased from storage");
  }

  return ret;
}

// Save a key to storage.
signed char participant_storage_save_key(Participant *participant_ptr,
                                         uint8_t key_index) {
  if (!participant_ptr || key_index < 1 || key_index > 3) {
    return -1;
  }

  if (!participant_ptr->comm_keys.spsec_keys[key_index]) {
    return -1;
  }

  const char *key_names[] = {"", "provisioning", "integrator", "seed"};
  char key_path[128];
  snprintf(key_path, sizeof(key_path), "keys/%s_key", key_names[key_index]);

  uint8_t *key_data_ptr =
      spseckey_get_key(participant_ptr->comm_keys.spsec_keys[key_index]);
  if (!key_data_ptr) {
    return -1;
  }

  signed char ret = nvol_storage_write_key(key_path, key_data_ptr);
  if (ret == 0) {
    LOG_INFO(logger_name_ptr, "Saved %s key to storage", key_names[key_index]);
  }
  return ret;
}

// Save a salt to storage.
signed char participant_storage_save_salt(Participant *participant_ptr,
                                          uint8_t salt_index) {
  if (!participant_ptr || salt_index < 1 || salt_index > 3) {
    return -1;
  }

  if (!participant_ptr->comm_keys.spsec_salt[salt_index]) {
    return -1;
  }

  const char *key_names[] = {"", "provisioning", "integrator", "seed"};
  char salt_path[128];
  snprintf(salt_path, sizeof(salt_path), "keys/%s_salt",
           key_names[salt_index]);

  uint8_t *salt_data_ptr =
      spsecsalt_get_salt(participant_ptr->comm_keys.spsec_salt[salt_index]);
  if (!salt_data_ptr) {
    return -1;
  }

  // Persist the full SALT_LEN (16) bytes so the salt round-trips across reboots.
  signed char ret = nvol_storage_write_salt(salt_path, salt_data_ptr);
  if (ret == 0) {
    LOG_INFO(logger_name_ptr, "Saved %s salt to storage", key_names[salt_index]);
  }
  return ret;
}

// Save a key ID to storage.
signed char participant_storage_save_key_id(Participant *participant_ptr,
                                            uint8_t key_index) {
  if (!participant_ptr || key_index < 1 || key_index > 3) {
    return -1;
  }

  if (!participant_ptr->comm_keys.spsec_keys[key_index]) {
    return -1;
  }

  const char *key_names[] = {"", "provisioning", "integrator", "seed"};
  char keyid_path[128];
  snprintf(keyid_path, sizeof(keyid_path), "keys/%s_keyid",
           key_names[key_index]);

  uint32_t *key_id_val_ptr =
      spseckey_get_id(participant_ptr->comm_keys.spsec_keys[key_index]);
  if (!key_id_val_ptr) {
    return -1;
  }

  signed char ret = nvol_storage_write_key_id(keyid_path, *key_id_val_ptr);
  if (ret == 0) {
    LOG_INFO(logger_name_ptr, "Saved %s key ID to storage", key_names[key_index]);
  }
  return ret;
}

// Get a key ID from storage.
signed char participant_storage_get_key_id(Participant *participant_ptr,
                                           uint8_t key_index,
                                           uint32_t *key_id_ptr) {
  if (!participant_ptr || key_index < 1 || key_index > 3 || !key_id_ptr) {
    return -1;
  }

  const char *key_names[] = {"", "provisioning", "integrator", "seed"};
  char keyid_path[128];
  snprintf(keyid_path, sizeof(keyid_path), "keys/%s_keyid",
           key_names[key_index]);

  *key_id_ptr = (uint32_t)SPSEC_KEY_ID_RESERVED;
  return nvol_storage_read_key_id(keyid_path, key_id_ptr);
}

// Save participant ID to storage.
signed char
participant_storage_save_participant_id(Participant *participant_ptr) {
  if (!participant_ptr) {
    return -1;
  }
  return nvol_storage_write_u8("config/participant_id",
                               participant_ptr->participant_id);
}

// Save heartbeat timing to storage.
signed char
participant_storage_save_heartbeat_timing(Participant *participant_ptr) {
  if (!participant_ptr) {
    return -1;
  }
  return nvol_storage_write_u8("config/heartbeat_timing",
                               (uint8_t)participant_ptr->heartbeat.timing);
}

// Save heartbeat monitor config to storage.
signed char
participant_storage_save_heartbeat_monitor(Participant *participant_ptr) {
  if (!participant_ptr) {
    return -1;
  }
  uint32_t monitor_val;
  memcpy(&monitor_val, participant_ptr->heartbeat.monitor.participant_ids, 4);
  return nvol_storage_write_u32("config/heartbeat_monitor", monitor_val);
}

// Save sync role activation to storage.
signed char participant_storage_save_sync_role(Participant *participant_ptr) {
  if (!participant_ptr) {
    return -1;
  }
  return nvol_storage_write_u8("config/sync_role",
                               participant_ptr->timesync.is_role_authority
                                   ? SPSEC_SYNC_ROLE_ON
                                   : SPSEC_SYNC_ROLE_OFF);
}

// Save CAN bitrate to storage.
signed char participant_storage_save_can_bitrate(Participant *participant_ptr) {
  if (!participant_ptr) {
    return -1;
  }
  return nvol_storage_write_u16("config/can_bitrate",
                                participant_ptr->state_info.can_fd_bitrate.raw);
}

// Save timestamp to storage.
signed char participant_storage_save_timestamp(Participant *participant_ptr) {
  if (!participant_ptr) {
    return -1;
  }
  uint8_t timestamp[8];
  timer_get_timestamp(&participant_ptr->timer, timestamp);
  uint64_t ts_value = 0;
  for (int i = 0; i < 8; i++) {
    ts_value |= ((uint64_t)timestamp[i]) << (i * 8);
  }
  return nvol_storage_write_u64("config/timestamp_ptr", ts_value);
}

// Delete a key from storage (used by manufacturer reset).
signed char participant_storage_delete_key(Participant *participant_ptr,
                                           uint8_t key_index) {
  if (!participant_ptr || key_index < 1 || key_index > 3) {
    return -1;
  }

  const char *key_names[] = {"", "provisioning", "integrator", "seed"};
  char key_path[128], salt_path[128], keyid_path[128];

  snprintf(key_path, sizeof(key_path), "keys/%s_key", key_names[key_index]);
  snprintf(salt_path, sizeof(salt_path), "keys/%s_salt",
           key_names[key_index]);
  snprintf(keyid_path, sizeof(keyid_path), "keys/%s_keyid",
           key_names[key_index]);

  nvol_storage_delete(key_path);
  nvol_storage_delete(salt_path);
  nvol_storage_delete(keyid_path);

  if (participant_ptr->comm_keys.spsec_keys[key_index]) {
    spseckey_free(participant_ptr->comm_keys.spsec_keys[key_index]);
    participant_ptr->comm_keys.spsec_keys[key_index] = NULL;
  }
  if (participant_ptr->comm_keys.spsec_salt[key_index]) {
    spsecsalt_free(participant_ptr->comm_keys.spsec_salt[key_index]);
    participant_ptr->comm_keys.spsec_salt[key_index] = NULL;
  }

  LOG_INFO(logger_name_ptr, "Deleted %s key from storage", key_names[key_index]);
  return 0;
}
