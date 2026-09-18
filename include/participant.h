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

#ifndef PARTICIPANT_H
#define PARTICIPANT_H

#include "config.h"
#include "crypto.h"
#include "dll_events.h"
#include "messages.h"
#include "participant_channel.h"
#include "participant_keys.h"
#include "randomgen.h"
#include "timer.h"

#include "spsec_registers.h"

/* 21h: 256-bit Provisioning Key, write-once via Zero Key session */
/* 22h: 256-bit Integrator Key, write-once via Provisioning Key session */
/* 23h: 256-bit Seed Key, write via Provisioning or Integrator Key session */

// Sub-structures for better organization

typedef struct {
  int retry_delay_seconds;
  bool is_synchronized;
  uint8_t *last_random_ptr;
  // Last successful sync of any kind (auth response or verified broadcast);
  // both refresh watchdog and Sync-restart detection measure from here.
  uint64_t last_successful;
  uint64_t refresh_interval_us;
  // Silence window before an invalid sync broadcast triggers restart recovery
  uint64_t broadcast_wait_us;

  bool is_role_authority;
  uint64_t last_broadcast;
  uint64_t broadcast_interval_us;
  uint16_t offset;
  uint16_t broadcast_offset;
  bool csalt_generated;                      // True if csalt has been generated
  spsec_csalt_regen_mode_t csalt_regen_mode; // When to regenerate csalt
  // Highest sync timestamp applied in current epoch to prevent replay.
  uint64_t broadcast_high_watermark;
} ParticipantTimeSync;

typedef struct {
  spsec_heartbeat_timing_t timing;   
  uint64_t last_sent;                
  spsec_heartbeat_monitor_t monitor; 
  uint64_t last_received[4];       
} ParticipantHeartbeat;

typedef struct {
  ConfigurationSessionAuthTagData *auth_tag_data_ptr;
  uint8_t key[32];                              
  uint32_t cnt;                                  
  bool active;                                  
  uint64_t start_time;                           
  uint64_t last_activity;                        
  uint64_t timeout_us;                            
  uint64_t response_timeout_us; 
} ParticipantSession;

typedef struct {
  spsec_state_t state;
  uint8_t status;      
  uint16_t last_event;  
  uint32_t version;   
  uint8_t capabilities;
  bool alert_flag;
  uint8_t prepared_write_register;
  uint8_t prepared_read_register;
  bool manufacturer_reset_pending;
  spsec_can_fd_bitrate_t can_fd_bitrate;
} ParticipantStateInfo;

typedef struct {
  uint64_t entry_time;   
  uint64_t hold_time_us; 
  bool event_occurred;   
} ParticipantWarningState;

typedef struct {
  char core_version_info[16];
  char mapping_version_info[16];
  char device_identification[128];
  uint8_t mcu_serial_number[16];
  spsec_code_update_capabilities_t code_update_capabilities;
} ParticipantDeviceInfo;

typedef struct {
  uint8_t buf[SPSEC_REG_CODE_UPDATE_FILE_MAX_LEN]; /* segment accumulator */
  uint32_t len;       /* bytes accumulated so far */
  uint32_t expected;  /* total negotiated at Write Initiate */
  bool active;        /* true while a multi-segment write is in progress */
} ParticipantWriteAccum;

typedef struct {
  SPsecCommChannel secure_channel;
  CommChannel insecure_channel;
  FreeRunningTimer timer;
  CryptoHandler crypto_handler;
  CommunicationKeys comm_keys;
  RandomGenerator random_generator;

  uint8_t participant_id;
  CryptoAlgorithm crypto_algorithm;
  bool auth_only_mode;
  // Replay acceptance window in 0.1ms reference ticks (default: SPSEC_ACCEPT_WINDOW_TICKS)
  uint32_t accept_window_ticks;
  volatile bool stop_requested;

  // Sub-structures
  ParticipantTimeSync timesync;
  ParticipantHeartbeat heartbeat;
  ParticipantSession session;
  ParticipantStateInfo state_info;
  ParticipantWarningState warning_state;
  ParticipantDeviceInfo device_info;
  ParticipantWriteAccum write_accum;  /* 92h multi-segment write state */

  // DLL event detection (optional)
  DLLEventContext dll_event_ctx;

  // Nonce reuse prevention (same-tick distinctness)
  uint8_t last_tx_timestamp[8];
  uint32_t last_tx_can_id;
} Participant;

// Initialize a participant instance.
spsec_ret_t participant_init(Participant *participant_ptr, uint32_t id,
                             const char *secure_if_ptr, const char *insecure_if_ptr,
                             const char *keys_file_ptr, bool enable_timesync_role,
                             uint16_t timesync_offset,
                             uint16_t broadcast_offset,
                             const CryptoAlgorithm *cli_algorithm_ptr,
                             bool auth_only_mode, bool use_bin_storage,
                             uint32_t accept_window_ticks);

// Destroy a participant instance and free all resources (NULL-safe).
void participant_destroy(Participant *participant_ptr);

// Start the main processing loop; does not return under normal operation.
spsec_ret_t participant_start_main_loop(Participant *participant_ptr);

// Request graceful shutdown of participant loops (async-signal-safe).
void participant_request_stop(void);

// True once participant_request_stop() has been called.
bool participant_shutdown_requested(void);

// Convert a spsec_state_t into a human-readable string.
const char *participant_get_state_name(spsec_state_t state);

spsec_ret_t participant_synchronize_time(Participant *participant_ptr);
spsec_ret_t participant_check_timesync_refresh(Participant *participant_ptr);

// True if an unverified sync broadcast means the Sync role restarted and we
// should transition to WAITING to re-authenticate.
bool participant_should_abort_on_sync_failure(Participant *participant_ptr,
                                              uint64_t now_us);
spsec_ret_t participant_handle_secure_message(Participant *participant_ptr,
                                              AppData *msg_ptr);
spsec_ret_t participant_process_spsec_appdata(Participant *participant_ptr,
                                              SPsecAppData *msg_ptr);
spsec_ret_t participant_decrypt_spsec_appdata(
    Participant *participant_ptr, SPsecAppData *msg_ptr, uint8_t *timestamp_ptr,
    uint8_t *key_ptr, uint8_t **plaintext_ptr, size_t *plaintext_len_ptr);
spsec_ret_t participant_process_mtls_auth_time(Participant *participant_ptr,
                                               SPsecTimeSyncResponse *msg_ptr,
                                               uint8_t *random_bytes_ptr);
uint8_t *participant_send_timesync_request(Participant *participant_ptr);

spsec_ret_t
participant_channel_send_timesync_response(SPsecCommChannel *channel_ptr,
                                           SPsecTimeSyncResponse *msg_ptr);

// Heartbeat functions
spsec_ret_t participant_send_heartbeat(Participant *participant_ptr);
spsec_ret_t participant_process_heartbeat(Participant *participant_ptr,
                                          SPsecHeartbeatMessage *msg_ptr);
spsec_ret_t participant_check_heartbeat_timing(Participant *participant_ptr);
spsec_ret_t participant_check_heartbeat_timeouts(Participant *participant_ptr);
uint32_t participant_get_heartbeat_cycle_ms(spsec_heartbeat_timing_t timing);

spsec_ret_t
participant_process_write_initiate(Participant *participant_ptr,
                                   SPsecWriteInitiateMessage *msg_ptr);

spsec_ret_t participant_process_client_hello(Participant *participant_ptr,
                                             SPsecClientHelloMessage *msg_ptr);
spsec_ret_t participant_send_server_hello(Participant *participant_ptr,
                                          uint8_t client_pid);
spsec_ret_t
participant_process_client_finished(Participant *participant_ptr,
                                    SPsecClientFinishedMessage *msg_ptr);
spsec_ret_t participant_send_server_finished(Participant *participant_ptr,
                                             uint8_t target_pid);
spsec_ret_t
participant_process_session_terminate(Participant *participant_ptr,
                                      SPsecSessionTerminateMessage *msg_ptr);
spsec_ret_t
participant_send_session_terminate_response(Participant *participant_ptr);

bool participant_state_transition(Participant *participant_ptr,
                                  spsec_event_t event);
uint8_t participant_get_status_register(const Participant *participant_ptr);
void participant_set_alert_flag(Participant *participant_ptr, bool alert);

// Internal event reporting functions
spsec_ret_t participant_report_internal_event(Participant *participant_ptr,
                                              uint8_t reg, uint32_t data);
spsec_ret_t participant_report_register_change(Participant *participant_ptr,
                                               uint8_t reg);
spsec_ret_t participant_report_state_transition(Participant *participant_ptr,
                                                spsec_state_t old_state,
                                                spsec_state_t new_state);
spsec_ret_t participant_report_security_event(Participant *participant_ptr,
                                              uint16_t event_code);
void participant_handle_security_event(Participant *participant_ptr,
                                       uint16_t event_code);

spsec_ret_t participant_run_waiting_loop(Participant *participant_ptr);
spsec_ret_t participant_run_configuration_loop(Participant *participant_ptr);
spsec_ret_t participant_run_secure_state_loop(Participant *participant_ptr);
spsec_ret_t participant_run_warning_state_loop(Participant *participant_ptr);
spsec_ret_t
participant_check_warning_state_hold_time(Participant *participant_ptr);

#endif