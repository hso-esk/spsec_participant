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
#include "timer.h"
#include <stdint.h>

static const char *logger_name_ptr = "part_session_heartbeat";

// Convert a heartbeat timing enum into its cycle duration in ms (0 if disabled/invalid).
uint32_t participant_get_heartbeat_cycle_ms(spsec_heartbeat_timing_t timing) {
  switch (timing) {
  case SPSEC_HEARTBEAT_DISABLED:
    return 0;
  case SPSEC_HEARTBEAT_8S:
    return 8000;
  case SPSEC_HEARTBEAT_4S:
    return 4000;
  case SPSEC_HEARTBEAT_2S:
    return 2000;
  case SPSEC_HEARTBEAT_1S:
    return 1000;
  case SPSEC_HEARTBEAT_500MS:
    return 500;
  case SPSEC_HEARTBEAT_250MS:
    return 250;
  default:
    if (timing >= SPSEC_HEARTBEAT_MANUFACTURER_MIN &&
        timing <= SPSEC_HEARTBEAT_MANUFACTURER_MAX) {
      return 1000;
    }
    return 0;
  }
}

// Send a heartbeat if we're in our assigned timeslot this cycle.
signed char participant_send_heartbeat(Participant *participant_ptr) {
  if (participant_ptr->heartbeat.timing == SPSEC_HEARTBEAT_DISABLED) {
    return 0;
  }
  uint8_t status = (participant_ptr->state_info.state & 0x0F) |
                   (participant_ptr->state_info.alert_flag ? 0x80 : 0x00);

  // Calculate time slot based on participant_ptr ID (SPsec302 Section 6.7)
  // Participant X transmits at full second + X milliseconds
  uint32_t cycle_ms =
      participant_get_heartbeat_cycle_ms(participant_ptr->heartbeat.timing);
  if (cycle_ms == 0) {
    return 0;
  }

  uint64_t current_time_us = timer_get_current_time_us(&participant_ptr->timer);
  uint64_t cycle_us = cycle_ms * 1000ULL;
  uint64_t time_since_last =
      current_time_us - participant_ptr->heartbeat.last_sent;

  // Check if it's time to send heartbeat based on cycle time
  if (time_since_last < cycle_us) {
    return 0; // Not time yet
  }

  // Calculate time slot offset: participant_ptr ID milliseconds
  uint64_t slot_offset_us =
      ((uint64_t)participant_ptr->participant_id * 1000ULL) % cycle_us;

  // Get current time modulo cycle time to find position in cycle
  uint64_t cycle_position = current_time_us % cycle_us;

  // Check if the current time matches the assigned time slot (with some tolerance)
  uint64_t tolerance_us = 1000ULL; // 1ms tolerance
  if (cycle_position >= slot_offset_us &&
      cycle_position < (slot_offset_us + tolerance_us)) {
    // Assigned time slot reached; send heartbeat
  } else if (cycle_position >= (slot_offset_us + tolerance_us)) {
    // Cycle time has passed and slot was missed, send immediately (fallback if
    // time sync or scheduling jitter caused a missed slot window)
  } else {
    return 0; // Not in assigned time slot yet (cycle_position < slot_offset_us)
  }

  SPsecHeartbeatMessage *hb_ptr =
      spsecheartbeat_new(participant_ptr->participant_id, status);
  if (!hb_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to create heartbeat message");
    return -1;
  }
  set_heartbeat_address(hb_ptr);
  signed char ret =
      participant_handle_secure_message(participant_ptr, hb_ptr->app_data_ptr);
  if (ret == 0) {
    participant_ptr->heartbeat.last_sent =
        timer_get_current_time_us(&participant_ptr->timer);
    LOG_DEBUG(logger_name_ptr, "Heartbeat sent successfully for participant_ptr %d",
              participant_ptr->participant_id);
  } else {
    LOG_ERROR(logger_name_ptr, "Failed to send heartbeat");
  }
  spsecheartbeat_free(hb_ptr);
  return ret;
}

// Decrypt a received heartbeat and update the sender's last-seen timer.
signed char participant_process_heartbeat(Participant *participant_ptr,
                                          SPsecHeartbeatMessage *msg_ptr) {
  SPsecAppData *app_data_ptr = msg_ptr->spsec_app_data_ptr;
  uint8_t timestamp[8];
  timer_get_timestamp(&participant_ptr->timer, timestamp);
  // Prefer restored timestamp for parity selection to reduce first-attempt
  // auth failures
  uint8_t restored_ts[8];
  participant_channel_restore_timestamp_and_padding(timestamp, app_data_ptr,
                                                    restored_ts);
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
            "DECRYPT_CALL site=session_heartbeat addr=%08x len=%u key=%s",
            (unsigned)app_data_ptr->address, (unsigned)app_data_ptr->secure_data_len,
            participant_ptr->comm_keys.use_odd_key ? "odd" : "even");
  ret = participant_decrypt_spsec_appdata(participant_ptr, app_data_ptr,
                                          timestamp, first_key_ptr,
                                          &plaintext_ptr, &plaintext_len);
  if (ret < 0) {
    LOG_INFO(logger_name_ptr,
             "Decryption with first key failed, trying fallback key");
    LOG_DEBUG(logger_name_ptr,
              "DECRYPT_CALL site=session_heartbeat addr=%08x len=%u key=%s",
              (unsigned)app_data_ptr->address, (unsigned)app_data_ptr->secure_data_len,
              participant_ptr->comm_keys.use_odd_key ? "even" : "odd");
    ret = participant_decrypt_spsec_appdata(participant_ptr, app_data_ptr,
                                            timestamp, second_key_ptr,
                                            &plaintext_ptr, &plaintext_len);
    if (ret < 0)
      return -1;
  }
  LOG_SECRET(logger_name_ptr, "Decrypted heartbeat message:", plaintext_ptr, plaintext_len);
  // Track last-seen timestamp for monitored participants
  for (int i = 0; i < 4; i++) {
    if (participant_ptr->heartbeat.monitor.participant_ids[i] ==
        msg_ptr->participant_id) {
      participant_ptr->heartbeat.last_received[i] =
          timer_get_current_time_us(&participant_ptr->timer);
      break;
    }
  }
  LOG_CRITICAL(logger_name_ptr,
               "Processed heartbeat from participant_ptr %d successfully",
               msg_ptr->participant_id);
  free(plaintext_ptr);
  return 0;
}

// Send the next heartbeat once its cycle duration has elapsed.
signed char participant_check_heartbeat_timing(Participant *participant_ptr) {
  if (participant_ptr->heartbeat.timing == SPSEC_HEARTBEAT_DISABLED) {
    return 0;
  }
  uint32_t cycle_ms =
      participant_get_heartbeat_cycle_ms(participant_ptr->heartbeat.timing);
  if (cycle_ms == 0) {
    return 0;
  }
  uint64_t current_time = timer_get_current_time_us(&participant_ptr->timer);
  uint64_t cycle_us = cycle_ms * 1000ULL;
  if (current_time - participant_ptr->heartbeat.last_sent >= cycle_us) {
    return participant_send_heartbeat(participant_ptr);
  }
  return 0;
}

// Flag monitored participants that missed heartbeats past the 2.5x window.
// NOTE: assumes ALL nodes share the local cycle time (register 0x61) -
// heterogeneous heartbeat cycles aren't supported and will misdetect.
signed char participant_check_heartbeat_timeouts(Participant *participant_ptr) {
  uint64_t current_time = timer_get_current_time_us(&participant_ptr->timer);
  uint32_t cycle_ms =
      participant_get_heartbeat_cycle_ms(participant_ptr->heartbeat.timing);
  if (cycle_ms == 0) {
    return 0;
  }
  uint64_t timeout_us = (uint64_t)cycle_ms * 2500ULL; // 2.5x per spec
  for (int i = 0; i < 4; i++) {
    uint8_t monitored_pid =
        participant_ptr->heartbeat.monitor.participant_ids[i];
    if (monitored_pid == 0 || monitored_pid >= 128) {
      continue;
    }
    uint64_t last_seen = participant_ptr->heartbeat.last_received[i];
    if (last_seen == 0) {
      // First check for this monitored node (never heard from it yet, e.g.
      // absent from startup or just added to the monitor list): arm the timeout
      // window from now so a node that is dead-from-start is still detected.
      participant_ptr->heartbeat.last_received[i] = current_time;
      continue;
    }
    if ((current_time - last_seen) > timeout_us) {
      LOG_WARNING(logger_name_ptr, "Heartbeat timeout for participant_ptr %d",
                  monitored_pid);
      participant_ptr->state_info.last_event =
          SPSEC_SDP_HB_LOSS_BASE + monitored_pid;
      participant_state_transition(participant_ptr, SPSEC_EVENT_SECURITY_EVENT);
      // Re-arm (not zero): keep re-detecting so the WARNING is refreshed each
      // timeout the node stays absent, instead of firing once and going blind.
      participant_ptr->heartbeat.last_received[i] = current_time;
    }
  }
  return 0;
}
