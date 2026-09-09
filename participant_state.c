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

#include "led_status.h"
#include "participant.h"
#include "spsec_common.h"
#include "timer.h"

static const char *logger_name_ptr = "participant_state";

// Convert a spsec_state_t into a human-readable string.
const char *participant_get_state_name(spsec_state_t state) {
  switch (state) {
  case SPSEC_STATE_NOT_SET:
    return "Not Set";
  case SPSEC_STATE_WAITING:
    return "Waiting";
  case SPSEC_STATE_SECURE:
    return "Secure";
  case SPSEC_STATE_WARNING:
    return "Warning";
  case SPSEC_STATE_CONFIGURATION:
    return "Configuration";
  case SPSEC_STATE_SHUTDOWN:
    return "Shutdown";
  default:
    return "Unknown";
  }
}

// Apply the SPsec201 state transition rules for event; returns true if the
// state changed.
bool participant_state_transition(Participant *participant_ptr,
                                  spsec_event_t event) {
  if (!participant_ptr) {
    LOG_ERROR(logger_name_ptr, "Invalid participant_ptr pointer");
    return false;
  }

  spsec_state_t old_state = participant_ptr->state_info.state;
  spsec_state_t new_state = old_state;

  LOG_DEBUG(logger_name_ptr, "State transition attempt: %s -> event %d",
            participant_get_state_name(old_state), event);

  // State transition logic based on SPsec201 specification
  switch (participant_ptr->state_info.state) {
  case SPSEC_STATE_NOT_SET:
    if (event == SPSEC_EVENT_STARTUP) {
      new_state = SPSEC_STATE_WAITING;
    }
    break;

  case SPSEC_STATE_WAITING:
    switch (event) {
    case SPSEC_EVENT_SECURITY_ESTABLISHED:
      new_state = SPSEC_STATE_SECURE;
      participant_ptr->state_info.alert_flag =
          false; // Reset alert on entering Secure
      break;
    case SPSEC_EVENT_ENTER_CONFIG:
      new_state = SPSEC_STATE_CONFIGURATION;
      break;
    case SPSEC_EVENT_SHUTDOWN:
      new_state = SPSEC_STATE_SHUTDOWN;
      break;
    default:
      break;
    }
    break;

  case SPSEC_STATE_SECURE:
    switch (event) {
    case SPSEC_EVENT_SECURITY_EVENT:
      new_state = SPSEC_STATE_WARNING;
      participant_ptr->state_info.alert_flag =
          true; // Set alert on Security Event
      // Initialize warning state tracking
      participant_ptr->warning_state.entry_time =
          timer_get_current_time_us(&participant_ptr->timer);
      participant_ptr->warning_state.event_occurred = false;
      // Default hold time: 5 seconds (can be configured)
      if (participant_ptr->warning_state.hold_time_us == 0) {
        participant_ptr->warning_state.hold_time_us =
            5000000ULL; // 5 seconds default
      }
      break;
    case SPSEC_EVENT_ENTER_CONFIG:
      new_state = SPSEC_STATE_CONFIGURATION;
      break;
    case SPSEC_EVENT_SECURITY_ABORT:
      new_state = SPSEC_STATE_WAITING;
      break;
    case SPSEC_EVENT_SHUTDOWN:
      new_state = SPSEC_STATE_SHUTDOWN;
      break;
    default:
      break;
    }
    break;

  case SPSEC_STATE_WARNING:
    switch (event) {
    case SPSEC_EVENT_SECURITY_EVENT:
      // Restart the hold window; event_occurred must reset to false or
      // WARNING becomes unrecoverable after a second event.
      participant_ptr->warning_state.event_occurred = false;
      participant_ptr->warning_state.entry_time =
          timer_get_current_time_us(&participant_ptr->timer);
      break;
    case SPSEC_EVENT_EVENTS_CLEAR:
      new_state = SPSEC_STATE_SECURE;
      participant_ptr->state_info.alert_flag =
          false; // Clear alert on returning to Secure
      break;
    case SPSEC_EVENT_SECURITY_ABORT:
      new_state = SPSEC_STATE_WAITING;
      break;
    case SPSEC_EVENT_ENTER_CONFIG:
      new_state = SPSEC_STATE_CONFIGURATION;
      break;
    case SPSEC_EVENT_SHUTDOWN:
      new_state = SPSEC_STATE_SHUTDOWN;
      break;
    default:
      break;
    }
    break;

  case SPSEC_STATE_CONFIGURATION:
    switch (event) {
    case SPSEC_EVENT_EXIT_CONFIG:
      if (participant_ptr->timesync.is_synchronized) {
        new_state = SPSEC_STATE_SECURE;
      } else {
        new_state = SPSEC_STATE_WAITING;
      }
      break;
    case SPSEC_EVENT_SHUTDOWN:
      new_state = SPSEC_STATE_SHUTDOWN;
      break;
    default:
      break;
    }
    break;

  case SPSEC_STATE_SHUTDOWN:
    if (event == SPSEC_EVENT_STARTUP) {
      new_state = SPSEC_STATE_WAITING;
      participant_ptr->state_info.alert_flag = false;
    }
    break;

  default:
    LOG_ERROR(logger_name_ptr, "Unknown state: %d",
              participant_ptr->state_info.state);
    return false;
  }

  // Update state if transition occurred
  if (new_state != old_state) {
    participant_ptr->state_info.state = new_state;

    // Update status register (bits 0-3: current state, bit 7: alert flag)
    participant_ptr->state_info.status =
        (participant_ptr->state_info.status & 0x70) | (new_state & 0x0F);
    if (participant_ptr->state_info.alert_flag) {
      participant_ptr->state_info.status |= 0x80;
    } else {
      participant_ptr->state_info.status &= 0x7F;
    }

    LOG_CRITICAL(logger_name_ptr, "State transition: %s -> %s",
                 participant_get_state_name(old_state),
                 participant_get_state_name(new_state));

    // Update LED status
    led_status_update(new_state, participant_ptr->state_info.alert_flag);

    // Report state transition via internal control plane
    participant_report_state_transition(participant_ptr, old_state, new_state);

    return true;
  }

  LOG_DEBUG(logger_name_ptr, "No state change occurred for event %d in state %s",
            event, participant_get_state_name(old_state));
  return false;
}

// Encode state + alert flag into the SPsec status register byte.
uint8_t participant_get_status_register(const Participant *participant_ptr) {
  if (!participant_ptr) {
    return 0;
  }

  uint8_t status = (uint8_t)participant_ptr->state_info.state &
                   0x0F; // Bits 0-3: current state
  if (participant_ptr->state_info.alert_flag) {
    status |= 0x80; // Bit 7: Alert flag
  }

  return status;
}

// Set/clear the alert flag and mirror it into the status register.
void participant_set_alert_flag(Participant *participant_ptr, bool alert) {
  if (participant_ptr) {
    participant_ptr->state_info.alert_flag = alert;
    // Update status register bit 7
    if (alert) {
      participant_ptr->state_info.status |= 0x80;
    } else {
      participant_ptr->state_info.status &= 0x7F;
    }
    LOG_DEBUG(logger_name_ptr, "Alert flag %s", alert ? "set" : "cleared");

    // Update LED status when alert flag changes
    led_status_update(participant_ptr->state_info.state, alert);
  }
}

// Record a security event and drive the state machine's security-event
// transition.
void participant_handle_security_event(Participant *participant_ptr,
                                       uint16_t event_code) {
  if (participant_ptr) {
    participant_ptr->state_info.last_event = event_code;
    // Report security event via internal control plane
    participant_report_security_event(participant_ptr, event_code);
    participant_state_transition(participant_ptr, SPSEC_EVENT_SECURITY_EVENT);
    LOG_WARNING(logger_name_ptr, "Security event detected: 0x%04X", event_code);
  }
}