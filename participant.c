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

#include <signal.h>

static const char *logger_name_ptr = "participant";

// Set from a signal handler (async-signal-safe), polled by all loops.
static volatile sig_atomic_t g_stop_requested = 0;

void participant_request_stop(void) { g_stop_requested = 1; }

bool participant_shutdown_requested(void) { return g_stop_requested != 0; }

// Main scheduling loop: dispatches to the loop for the current state, forever.
spsec_ret_t participant_start_main_loop(Participant *participant_ptr) {
  LOG_INFO(logger_name_ptr, "Starting main loop");
  while (!participant_ptr->stop_requested && !participant_shutdown_requested()) {
    switch (participant_ptr->state_info.state) {
    case SPSEC_STATE_WAITING:
      participant_run_waiting_loop(participant_ptr);
      break;
    case SPSEC_STATE_CONFIGURATION:
      participant_run_configuration_loop(participant_ptr);
      break;
    case SPSEC_STATE_SECURE:
      participant_run_secure_state_loop(participant_ptr);
      break;
    case SPSEC_STATE_WARNING:
      participant_run_warning_state_loop(participant_ptr);
      break;
    case SPSEC_STATE_SHUTDOWN:
    case SPSEC_STATE_NOT_SET:
    default:
      // No work loop for these states; exit rather than busy-spin a core.
      LOG_INFO(logger_name_ptr, "Main loop exiting (state=%d)",
               participant_ptr->state_info.state);
      return 0;
    }
  }
  LOG_INFO(logger_name_ptr, "Main loop exiting (shutdown requested)");
  return 0;
}