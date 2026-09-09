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
#include "participant_timesync.h"
#include "session_loops_internal.h"
#include "spsec_common.h"
#include "timer.h"
#include <stdint.h>

static const char *logger_name_ptr = "part_loop_warning";

signed char
participant_check_warning_state_hold_time(Participant *participant_ptr) {
  if (participant_ptr->state_info.state != SPSEC_STATE_WARNING) {
    return 0;
  }

  uint64_t current_time = timer_get_current_time_us(&participant_ptr->timer);
  uint64_t elapsed = current_time - participant_ptr->warning_state.entry_time;

  // Check if hold time has expired and no additional events occurred
  if (elapsed >= participant_ptr->warning_state.hold_time_us &&
      !participant_ptr->warning_state.event_occurred) {
    LOG_INFO(logger_name_ptr, "Warning state hold time expired, clearing events");
    participant_state_transition(participant_ptr, SPSEC_EVENT_EVENTS_CLEAR);
    return 1; // State transition occurred
  }

  return 0;
}

signed char participant_run_warning_state_loop(Participant *participant_ptr) {
  while (participant_ptr->state_info.state == SPSEC_STATE_WARNING &&
         !participant_shutdown_requested()) {
    uint8_t timestamp[8];
    timer_get_timestamp(&participant_ptr->timer, timestamp);
    communication_keys_update(&participant_ptr->comm_keys, timestamp);
    process_timesync_broadcasts(participant_ptr, timestamp);
    check_and_send_heartbeat(participant_ptr);
    participant_check_heartbeat_timeouts(participant_ptr);
    participant_check_warning_state_hold_time(participant_ptr);
    process_secure_messages(participant_ptr);
    process_insecure_messages(participant_ptr);
  }
  return 0;
}
