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
#include "participant_storage.h"
#include "participant_timesync.h" // for process_heartbeat_timeouts
#include "session_loops_internal.h"
#include "spsec_common.h"
#include "timer.h"
#include <stdint.h>

signed char participant_run_secure_state_loop(Participant *participant_ptr) {
  uint64_t last_timestamp_save =
      timer_get_current_time_us(&participant_ptr->timer);
  uint64_t last_timesync_refresh = last_timestamp_save;
  const uint64_t TIMESTAMP_SAVE_INTERVAL_US =
      10000000ULL; // Save every 10 seconds
  const uint64_t TIMESYNC_REFRESH_INTERVAL_US =
      1000000ULL; // Check timesync refresh every 1 second

  while (participant_ptr->state_info.state == SPSEC_STATE_SECURE &&
         !participant_shutdown_requested()) {
    uint8_t timestamp[8];
    timer_get_timestamp(&participant_ptr->timer, timestamp);
    communication_keys_update(&participant_ptr->comm_keys, timestamp);
    process_timesync_broadcasts(participant_ptr, timestamp);
    check_and_send_heartbeat(participant_ptr);
    participant_check_heartbeat_timeouts(participant_ptr);
    process_secure_messages(participant_ptr);
    process_insecure_messages(participant_ptr);

    // Periodically save timestamp to ensure persistence
    uint64_t current_time = timer_get_current_time_us(&participant_ptr->timer);
    if (current_time - last_timestamp_save >= TIMESTAMP_SAVE_INTERVAL_US) {
      participant_storage_save_timestamp(participant_ptr);
      last_timestamp_save = current_time;
    }

    // Check time sync refresh timeout (F-09)
    if (current_time - last_timesync_refresh >= TIMESYNC_REFRESH_INTERVAL_US) {
      participant_check_timesync_refresh(participant_ptr);
      last_timesync_refresh = current_time;
    }
  }
  return 0;
}
