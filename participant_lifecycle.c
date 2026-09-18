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

#include "can_bitrate.h"
#include "config.h"
#include "device_info.h"
#include "dll_events.h"
#include "keys.h"
#include "led_status.h"
#include "nvol_storage.h"
#include "participant.h"
#include "participant_storage.h"
#include "spsec_common.h"

static const char *logger_name_ptr = "part_lifecycle";

static uint32_t capability_for_algorithm(CryptoAlgorithm algorithm) {
  switch (algorithm) {
  case CRYPTO_ALGO_AES_GCM:
    return SPSEC_CAPABILITY_AES_GCM;
  case CRYPTO_ALGO_CHACHA20_POLY1305:
    return SPSEC_CAPABILITY_CHACHA20_POLY1305;
  case CRYPTO_ALGO_ASCON128:
    return SPSEC_CAPABILITY_ASCON128;
  default:
    return 0;
  }
}

static const CryptoBackend *resolve_crypto_backend(void) {
  const char *env_ptr = getenv("SPSEC_CRYPTO_BACKEND");
  const CryptoBackend *backend_ptr = crypto_backend_by_id(env_ptr);
  if (!backend_ptr) {
    if (env_ptr && *env_ptr) {
      LOG_WARNING(logger_name_ptr, "Unknown backend '%s', falling back to default",
                  env_ptr);
    }
    backend_ptr = crypto_backend_default();
  }
  if (env_ptr && *env_ptr) {
    LOG_INFO(logger_name_ptr, "SPSEC_CRYPTO_BACKEND=%s -> %s", env_ptr, backend_ptr->name);
  } else {
    LOG_INFO(logger_name_ptr, "Using default crypto backend %s", backend_ptr->name);
  }
  return backend_ptr;
}

static CryptoAlgorithm
resolve_crypto_algorithm(const CryptoAlgorithm *cli_algorithm_ptr) {
  // If CLI algorithm is specified, use it directly
  if (cli_algorithm_ptr != NULL) {
    LOG_INFO(logger_name_ptr, "CLI flag: using %s",
             crypto_algorithm_name(*cli_algorithm_ptr));
    return *cli_algorithm_ptr;
  }

  // Otherwise, check environment variable
  const char *env_ptr = getenv("SPSEC_AEAD_ALGO");
  CryptoAlgorithm algorithm = crypto_algorithm_from_string(env_ptr);
  if (env_ptr && *env_ptr) {
    LOG_INFO(logger_name_ptr, "SPSEC_AEAD_ALGO=%s -> %s", env_ptr,
             crypto_algorithm_name(algorithm));
  } else {
    LOG_INFO(logger_name_ptr, "Using default AEAD algorithm %s",
             crypto_algorithm_name(algorithm));
  }
  return algorithm;
}

// Populate default configuration fields for a new participant instance.
static spsec_ret_t init_participant_config(Participant *participant_ptr,
                                           uint32_t id) {
  participant_ptr->participant_id = id & 0x7F; // Mask to 7-bit ID
  participant_ptr->session.auth_tag_data_ptr = NULL;

  // Time synchronization parameters
  participant_ptr->timesync.is_synchronized = false;
  participant_ptr->timesync.last_random_ptr = NULL;
  participant_ptr->timesync.retry_delay_seconds = 2;
  participant_ptr->timesync.last_successful = 0;
  participant_ptr->timesync.refresh_interval_us =
      60000000ULL; // Default: 60 seconds
  // Default sync-restart recovery wait window (30s).
  participant_ptr->timesync.broadcast_wait_us = 30000000ULL;
  participant_ptr->timesync.csalt_generated = false;
  participant_ptr->timesync.csalt_regen_mode = SPSEC_CSALT_REGEN_POWER_UP;
  participant_ptr->timesync.broadcast_high_watermark = 0;

  // Heartbeat parameters
  participant_ptr->heartbeat.timing = SPSEC_HEARTBEAT_8S;
  participant_ptr->heartbeat.last_sent = 0;
  memset(&participant_ptr->heartbeat.monitor, 0,
         sizeof(participant_ptr->heartbeat
                    .monitor)); // Monitor no participants by default
  memset(participant_ptr->heartbeat.last_received, 0,
         sizeof(participant_ptr->heartbeat.last_received));

  participant_ptr->timesync.broadcast_interval_us =
      10000000; // 10 seconds (paper v2 SS586/SS601/SS717 default)
  participant_ptr->timesync.last_broadcast = 0;

  // Session and state parameters
  participant_ptr->state_info.state = SPSEC_STATE_NOT_SET;
  participant_ptr->state_info.status = 0x00;
  participant_ptr->state_info.last_event = SPSEC_NO_SEC_EVENT;
  participant_ptr->state_info.version =
      0x00010000; // Version 1.0.0 (unused for string
                  // regs, keep for compatibility)
  participant_ptr->state_info.capabilities = 0;
  participant_ptr->state_info.alert_flag = false;
  participant_ptr->crypto_algorithm = SPSEC_DEFAULT_AEAD_ALGO;

  // Warning state hold time tracking
  participant_ptr->warning_state.entry_time = 0;
  participant_ptr->warning_state.hold_time_us =
      5000000ULL; // Default: 5 seconds
  participant_ptr->warning_state.event_occurred = false;
  {
    // SPsec302 V40 Section 2.3.4.3: Register 58h - SPsec Core Version
    const char *source_core_version_ptr = "0.34";
    size_t source_core_version_length = strlen(source_core_version_ptr);
    if (source_core_version_length >=
        sizeof(participant_ptr->device_info.core_version_info))
      source_core_version_length =
          sizeof(participant_ptr->device_info.core_version_info) - 1;
    memcpy(participant_ptr->device_info.core_version_info, source_core_version_ptr,
           source_core_version_length);
    participant_ptr->device_info.core_version_info[source_core_version_length] =
        '\0';
  }
  {
    // SPsec302 V40 Section 2.3.4.4: Register 59h - SPsec Mapping Version
    const char *source_mapping_version_ptr = "302-1.40";
    size_t source_mapping_version_length = strlen(source_mapping_version_ptr);
    if (source_mapping_version_length >=
        sizeof(participant_ptr->device_info.mapping_version_info))
      source_mapping_version_length =
          sizeof(participant_ptr->device_info.mapping_version_info) - 1;
    memcpy(participant_ptr->device_info.mapping_version_info,
           source_mapping_version_ptr, source_mapping_version_length);
    participant_ptr->device_info
        .mapping_version_info[source_mapping_version_length] = '\0';
  }

  // SPsec302 V40 Section 2.3.6: Initialize Device Information registers
  if (device_info_get_identification(
          participant_ptr->device_info.device_identification,
          sizeof(participant_ptr->device_info.device_identification)) != 0) {
    // Fallback to empty string if platform retrieval fails
    participant_ptr->device_info.device_identification[0] = '\0';
    LOG_WARNING(logger_name_ptr,
                "Failed to get device identification from platform");
  }

  // 82h: MCU Serial Number - read from platform
  if (device_info_get_mcu_serial(
          participant_ptr->device_info.mcu_serial_number) != 0) {
    // Fallback to zeros if platform retrieval fails
    memset(participant_ptr->device_info.mcu_serial_number, 0,
           sizeof(participant_ptr->device_info.mcu_serial_number));
    LOG_WARNING(logger_name_ptr, "Failed to get MCU serial number from platform");
  }

  // SPsec302 V40 Section 2.3.7: Initialize Code Updates registers (90h-9Fh)
  uint32_t capabilities = device_info_get_code_update_capabilities();
  participant_ptr->device_info.code_update_capabilities.raw = capabilities;
  memset(participant_ptr->session.key, 0, KEY_LEN);
  participant_ptr->session.cnt = 0;
  participant_ptr->session.active = false;
  memset(&participant_ptr->write_accum, 0, sizeof(participant_ptr->write_accum));
  memset(participant_ptr->last_tx_timestamp, 0, sizeof(participant_ptr->last_tx_timestamp));
  participant_ptr->last_tx_can_id = 0;

  LOG_INFO(logger_name_ptr, "Participant configuration initialized with ID: %u",
           participant_ptr->participant_id);
  return SPSEC_SUCCESS;
}

// Init communication channels, timer, crypto handler, RNG, and comm keys.
static spsec_ret_t init_participant_channels(Participant *participant_ptr,
                                             const char *secure_if_ptr,
                                             const char *insecure_if_ptr) {
  if (participant_secure_channel_init(&participant_ptr->secure_channel,
                                      secure_if_ptr,
                                      &participant_ptr->participant_id) < 0) {
    LOG_ERROR(logger_name_ptr, "Failed to initialize secure channel");
    return SPSEC_ERROR_CHANNEL_INIT;
  }
  if (participant_insecure_channel_init(&participant_ptr->insecure_channel,
                                        insecure_if_ptr) < 0) {
    LOG_ERROR(logger_name_ptr, "Failed to initialize insecure channel");
    return SPSEC_ERROR_CHANNEL_INIT;
  }

  if (timer_init(&participant_ptr->timer, 8) < 0) {
    LOG_ERROR(logger_name_ptr, "Failed to initialize timer");
    return SPSEC_ERROR_PLATFORM_TIMER;
  }
  if (crypto_handler_init(&participant_ptr->crypto_handler) != SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr, "Failed to initialize crypto handler");
    return SPSEC_ERROR_CRYPTO_INIT;
  }
  if (random_generator_init(&participant_ptr->random_generator) < 0) {
    LOG_ERROR(logger_name_ptr, "Failed to initialize random_ptr generator");
    return SPSEC_ERROR_PLATFORM_RANDOM;
  }
  if (communication_keys_init(&participant_ptr->comm_keys) < 0) {
    LOG_ERROR(logger_name_ptr, "Failed to initialize communication keys");
    return SPSEC_ERROR_KEY_LOAD_FAILED;
  }
  return SPSEC_SUCCESS;
}

// Load a specific key from the key dictionary file.
static spsec_ret_t load_key(Participant *participant_ptr, const char *keys_file_ptr,
                            const char *key_name_ptr, uint8_t key_selector_ptr) {
  size_t data_len;
  uint8_t *key_buffer_ptr = retrieve_dict_from_file(keys_file_ptr, key_name_ptr, &data_len);

  if (!key_buffer_ptr || data_len != KEY_LEN) {
    LOG_ERROR(logger_name_ptr,
              "Failed to read value '%s' or invalid length (%zu != %d)",
              key_name_ptr, data_len, KEY_LEN);
    free(key_buffer_ptr);
    return SPSEC_ERROR_KEY_LOAD_FAILED;
  } else {
    // Use selector index as default key ID for startup keys
    participant_ptr->comm_keys.spsec_keys[key_selector_ptr] =
        spseckey_new(key_selector_ptr, key_buffer_ptr);

    LOG_INFO(logger_name_ptr, "Key loaded successfully: %s", key_name_ptr);
    free(key_buffer_ptr);
    return SPSEC_SUCCESS;
  }
}

// Load a specific salt from the key dictionary file.
static spsec_ret_t load_salt(Participant *participant_ptr,
                             const char *keys_file_ptr, const char *salt_name_ptr,
                             uint8_t salt_selector) {
  size_t data_len;
  uint8_t *salt_buffer_ptr =
      retrieve_dict_from_file(keys_file_ptr, salt_name_ptr, &data_len);

  if (!salt_buffer_ptr || data_len != SALT_LEN) {
    LOG_ERROR(logger_name_ptr,
              "Failed to read salt '%s' or invalid length (%zu != %d)",
              salt_name_ptr, data_len, SALT_LEN);
    free(salt_buffer_ptr);
    return SPSEC_ERROR_KEY_LOAD_FAILED;
  }

  participant_ptr->comm_keys.spsec_salt[salt_selector] =
      spsecsalt_new(salt_buffer_ptr);
  LOG_INFO(logger_name_ptr, "Loaded salt '%s' successfully at selector %d",
           salt_name_ptr, salt_selector);
  free(salt_buffer_ptr);
  return SPSEC_SUCCESS;
}

// Load keys/salts for the participant.
static spsec_ret_t load_participant_keys(Participant *participant_ptr,
                                         const char *keys_file_ptr) {
  int keys_loaded = 0;

  // Provisioning key & salt (added manually by device manufacturer)
  if (load_key(participant_ptr, keys_file_ptr, "provisioning_key", 1) == 0) {
    keys_loaded++;
    load_salt(participant_ptr, keys_file_ptr, "provisioning_salt", 1);
  }

  // Integrator key & salt (optional at startup, can be provisioned later)
  if (load_key(participant_ptr, keys_file_ptr, "integrator_key", 2) == 0) {
    keys_loaded++;
    load_salt(participant_ptr, keys_file_ptr, "integrator_salt", 2);
  }

  // Seed key & salt (optional at startup)
  if (load_key(participant_ptr, keys_file_ptr, "seed_key", 3) == 0) {
    keys_loaded++;
    load_salt(participant_ptr, keys_file_ptr, "seed_salt", 3);
  }

  return (keys_loaded > 0) ? SPSEC_SUCCESS : SPSEC_ERROR_KEY_LOAD_FAILED;
}

// Init the crypto context: bind backend, pick a supported AEAD algorithm.
static spsec_ret_t
init_participant_crypto_context(Participant *participant_ptr,
                                const CryptoAlgorithm *cli_algorithm_ptr) {
  const CryptoBackend *backend_ptr = resolve_crypto_backend();
  if (crypto_handler_use_backend(&participant_ptr->crypto_handler, backend_ptr) !=
      SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr, "Failed to bind crypto backend %s", backend_ptr->name);
    return SPSEC_ERROR_CRYPTO_INIT;
  }
  participant_ptr->state_info.capabilities =
      (uint8_t)(backend_ptr->capability_flags & 0xFF);

  CryptoAlgorithm configured_algo = resolve_crypto_algorithm(cli_algorithm_ptr);
  uint32_t required_flag = capability_for_algorithm(configured_algo);
  if (required_flag == 0 || !(backend_ptr->capability_flags & required_flag)) {
    LOG_WARNING(
        logger_name_ptr,
        "Backend %s does not support algorithm %s, searching for alternative",
        backend_ptr->name, crypto_algorithm_name(configured_algo));
    const CryptoAlgorithm candidates[] = {CRYPTO_ALGO_AES_GCM,
                                          CRYPTO_ALGO_CHACHA20_POLY1305,
                                          CRYPTO_ALGO_ASCON128};
    bool found = false;
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); ++i) {
      if (backend_ptr->capability_flags & capability_for_algorithm(candidates[i])) {
        configured_algo = candidates[i];
        found = true;
        LOG_INFO(logger_name_ptr, "Selected fallback algorithm %s",
                 crypto_algorithm_name(configured_algo));
        break;
      }
    }
    if (!found) {
      LOG_ERROR(logger_name_ptr,
                "No supported AEAD algorithm available for backend %s",
                backend_ptr->name);
      return SPSEC_ERROR_CRYPTO_INIT;
    }
  }

  participant_ptr->crypto_algorithm = configured_algo;
  if (crypto_handler_select_algorithm(&participant_ptr->crypto_handler,
                                      configured_algo) != 0) {
    LOG_ERROR(logger_name_ptr,
              "Failed to configure crypto handler for algorithm %s",
              crypto_algorithm_name(configured_algo));
    return SPSEC_ERROR_CRYPTO_INIT;
  }
  return SPSEC_SUCCESS;
}

// If a manufacturer reset is pending, erase all keys except Provisioning.
static void handle_manufacturer_reset_logic(Participant *participant_ptr) {
  uint8_t reset_flag = 0;
  if (nvol_storage_read_u8("config/manufacturer_reset", &reset_flag) == 0 &&
      reset_flag != 0) {
    LOG_WARNING(
        logger_name_ptr,
        "Manufacturer reset pending - erasing keys (except Provisioning key)");

    // Erase Integrator Key (index 2)
    if (participant_ptr->comm_keys.spsec_keys[2]) {
      spseckey_free(participant_ptr->comm_keys.spsec_keys[2]);
      participant_ptr->comm_keys.spsec_keys[2] = NULL;
    }
    if (participant_ptr->comm_keys.spsec_salt[2]) {
      spsecsalt_free(participant_ptr->comm_keys.spsec_salt[2]);
      participant_ptr->comm_keys.spsec_salt[2] = NULL;
    }

    // Erase Seed Key (index 3)
    if (participant_ptr->comm_keys.spsec_keys[3]) {
      spseckey_free(participant_ptr->comm_keys.spsec_keys[3]);
      participant_ptr->comm_keys.spsec_keys[3] = NULL;
    }
    if (participant_ptr->comm_keys.spsec_salt[3]) {
      spsecsalt_free(participant_ptr->comm_keys.spsec_salt[3]);
      participant_ptr->comm_keys.spsec_salt[3] = NULL;
    }

    // Clear communication keys and reset timestamp cache
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

    // Delete keys from storage
    participant_storage_delete_key(participant_ptr, 2); // Integrator
    participant_storage_delete_key(participant_ptr, 3); // Seed

    // Clear the reset flag
    nvol_storage_write_u8("config/manufacturer_reset", 0);

    LOG_INFO(
        logger_name_ptr,
        "Manufacturer reset completed - device restored to provisioning state");
  }
}

// Init per-ID storage, load saved state, run manufacturer reset if pending,
// and load keys from keys_file_ptr if given.
static spsec_ret_t
init_participant_storage_and_keys(Participant *participant_ptr, uint32_t id,
                                  const char *keys_file_ptr, bool use_bin_storage) {
  const char *storage_path_ptr = getenv("SPSEC_STORAGE_PATH");
  if (!storage_path_ptr || storage_path_ptr[0] == '\0') {
    storage_path_ptr = "./participants_data"; // Default storage path
  }

  char dynamic_storage_path[256];
  size_t len = strlen(storage_path_ptr);
  if (len > 0 && storage_path_ptr[len - 1] == '/') {
    snprintf(dynamic_storage_path, sizeof(dynamic_storage_path), "%s%u",
             storage_path_ptr, id);
  } else {
    snprintf(dynamic_storage_path, sizeof(dynamic_storage_path), "%s/%u",
             storage_path_ptr, id);
  }

  if (nvol_storage_init(dynamic_storage_path, use_bin_storage) < 0) {
    LOG_ERROR(logger_name_ptr, "Failed to initialize storage at '%s'",
              dynamic_storage_path);
    return SPSEC_ERROR_IO;
  }
  LOG_INFO(logger_name_ptr, "Storage initialized at '%s'", dynamic_storage_path);

  // Load configuration from storage first (may override defaults)
  participant_storage_load_all(participant_ptr);

  handle_manufacturer_reset_logic(participant_ptr);

  // Load keys from keys_file_ptr if provided (for backward compatibility)
  if (keys_file_ptr) {
    if (load_participant_keys(participant_ptr, keys_file_ptr) < 0) {
      LOG_WARNING(logger_name_ptr, "Failed to load keys from %s, trying storage",
                  keys_file_ptr);
    } else {
      LOG_INFO(logger_name_ptr, "Keys loaded successfully from %s", keys_file_ptr);
      // Save loaded keys to storage for persistence
      for (uint8_t i = 1; i <= 3; i++) {
        if (participant_ptr->comm_keys.spsec_keys[i]) {
          participant_storage_save_key(participant_ptr, i);
          participant_storage_save_key_id(participant_ptr, i);
        }
        if (participant_ptr->comm_keys.spsec_salt[i]) {
          participant_storage_save_salt(participant_ptr, i);
        }
      }
    }
  }
  return SPSEC_SUCCESS;
}

// Fully initialize a participant instance.
spsec_ret_t participant_init(Participant *participant_ptr, uint32_t id,
                             const char *secure_if_ptr, const char *insecure_if_ptr,
                             const char *keys_file_ptr, bool enable_timesync_role,
                             uint16_t timesync_offset,
                             uint16_t broadcast_offset,
                             const CryptoAlgorithm *cli_algorithm_ptr,
                             bool auth_only_mode, bool use_bin_storage,
                             uint32_t accept_window_ticks) {
  if (!participant_ptr || !secure_if_ptr || !insecure_if_ptr) {
    LOG_ERROR(logger_name_ptr,
              "Invalid arguments for participant_ptr initialization");
    return -1;
  }

  if (init_participant_config(participant_ptr, id) != SPSEC_SUCCESS) {
    return SPSEC_ERROR_INVALID_ARGUMENT;
  }

  // Initialize sockets to -1 so cleanup only closes open channels
  participant_ptr->secure_channel.channel.socket = -1;
  participant_ptr->insecure_channel.socket = -1;

  // Initialize LED status system
  led_status_init();

  // STARTUP transition is deferred until CAN channels are open below

  if (init_participant_channels(participant_ptr, secure_if_ptr, insecure_if_ptr) !=
      SPSEC_SUCCESS) {
    participant_destroy(participant_ptr);
    return SPSEC_ERROR_CHANNEL_INIT;
  }

  if (init_participant_crypto_context(participant_ptr, cli_algorithm_ptr) !=
      SPSEC_SUCCESS) {
    participant_destroy(participant_ptr);
    return SPSEC_ERROR_CRYPTO_INIT;
  }

  // Initialize state machine
  participant_ptr->state_info.state = SPSEC_STATE_NOT_SET;
  participant_ptr->state_info.alert_flag = false;
  participant_ptr->state_info.status = 0x00;

  // Initialize DLL event detection (optional feature)
  dll_events_init(&participant_ptr->dll_event_ctx,
                  participant_ptr->participant_id);

  // SPsec302 V40 Section 2.3.5.4: Initialize Sync Role Activation register
  participant_ptr->timesync.is_role_authority = enable_timesync_role;

  // Data-plane acceptance window in reference ticks
  participant_ptr->accept_window_ticks = accept_window_ticks;
  LOG_INFO(logger_name_ptr, "Acceptance window: %u ticks (%u.%u ms)",
           accept_window_ticks, accept_window_ticks / 10,
           accept_window_ticks % 10);

  // Initialize authentication-only mode
  participant_ptr->auth_only_mode = auth_only_mode;
  if (auth_only_mode) {
    LOG_INFO(logger_name_ptr, "Authentication-only mode enabled: data_ptr plane "
                          "communication will use AAD-only authentication");
  }

  // SPsec302 V40 Section 2.3.5.5: Initialize CAN FD Bit Rate register (7Bh)
  participant_ptr->state_info.can_fd_bitrate.rates.nominal_bitrate =
      SPSEC_CAN_NOMINAL_1000KBPS;
  participant_ptr->state_info.can_fd_bitrate.rates.data_bitrate =
      SPSEC_CAN_DATA_1MBPS;
  participant_ptr->state_info.manufacturer_reset_pending = false;

  participant_ptr->timesync.offset = timesync_offset;
  participant_ptr->timesync.broadcast_offset = broadcast_offset;

  participant_ptr->timesync.last_broadcast = 0;

  if (init_participant_storage_and_keys(participant_ptr, id, keys_file_ptr,
                                        use_bin_storage) != SPSEC_SUCCESS) {
    participant_destroy(participant_ptr);
    return SPSEC_ERROR_IO;
  }

  // SPsec302 V40 Section 2.3.5.5: Apply CAN FD bitrate on power cycle
  if (nvol_storage_exists("config/can_bitrate")) {
    can_bitrate_apply(secure_if_ptr, participant_ptr->state_info.can_fd_bitrate);
  }

  // Scale timer tick resolution to configured CAN FD data bitrate
  timer_set_tick_ns(&participant_ptr->timer,
                    spsec_tick_ns_for_data_bitrate(
                        participant_ptr->state_info.can_fd_bitrate.rates.data_bitrate));

  // Clamp the acceptance window to the timestamp reconstruction bound.
  // Only known once tick_ns is set above - see spsec_max_accept_window_ticks().
  {
    uint32_t max_window_ticks = spsec_max_accept_window_ticks(
        timer_get_tick_ns(&participant_ptr->timer));
    if (participant_ptr->accept_window_ticks > max_window_ticks) {
      LOG_WARNING(logger_name_ptr,
                 "Acceptance window %u ticks exceeds the reconstruction "
                 "bound at this bitrate (max %u ticks) - clamping; replay "
                 "rejection would otherwise be silently disabled",
                 participant_ptr->accept_window_ticks, max_window_ticks);
      participant_ptr->accept_window_ticks = max_window_ticks;
    }
  }

  // Check for seed key presence (required for secure state)
  if (participant_ptr->comm_keys.spsec_keys[3] &&
      participant_ptr->comm_keys.spsec_salt[3]) {
    LOG_INFO(logger_name_ptr,
             "Seed key available, will attempt time synchronization");
  } else {
    LOG_WARNING(logger_name_ptr, "Seed key not available, configuration required");
  }

  LOG_DEBUG(logger_name_ptr, "Seed key after init: %p, Salt: %p",
            participant_ptr->comm_keys.spsec_keys[3],
            participant_ptr->comm_keys.spsec_salt[3]);

  LOG_INFO(logger_name_ptr, "Participant initialized successfully");
  // Trigger startup transition
  participant_state_transition(participant_ptr, SPSEC_EVENT_STARTUP);
  return SPSEC_SUCCESS;
}

// Release all resources owned by a participant.
void participant_destroy(Participant *participant_ptr) {
  if (!participant_ptr)
    return;

  // Save current timestamp_ptr before cleanup
  participant_storage_save_timestamp(participant_ptr);

  participant_channel_destroy(&participant_ptr->secure_channel);
  can_channel_destroy(&participant_ptr->insecure_channel);
  timer_destroy(&participant_ptr->timer);
  crypto_handler_destroy(&participant_ptr->crypto_handler);
  random_generator_free(&participant_ptr->random_generator);
  communication_keys_destroy(&participant_ptr->comm_keys);
  free(participant_ptr->timesync.last_random_ptr);
  authtagparticipantdata_free(participant_ptr->session.auth_tag_data_ptr);

  nvol_storage_cleanup();
}
