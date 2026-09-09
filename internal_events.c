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

#include "messages.h"
#include "participant.h"

#include "spsec_common.h"
#include "spsec_registers.h"

static const char *logger_name_ptr = "part_internal_events";

// Internal control plane CAN ID base address (priority 6, bit 25 set)
// Format: 0x1E000000 | (CPMT_INTERN_EVT << 8) | (participant_id & 0x7F)
#define INTERNAL_EVENT_BASE_ID 0x1E000000

// Send an internal event as a CAN message on the insecure channel
// (SPsec302 §7: internal control plane protocol).
static signed char send_internal_event_can(CommChannel *channel_ptr,
                                           uint8_t participant_id, uint8_t reg,
                                           uint32_t data) {
  if (!channel_ptr) {
    LOG_ERROR(logger_name_ptr, "Invalid channel pointer");
    return -1;
  }

  // SPsec302 V40 Section 7: CAN ID format
  // Priority 6, bit 25 set, CPMT_INTERN_EVT, participant_id (source addressing,
  // bit 7 = 0)
  uint32_t can_id =
      INTERNAL_EVENT_BASE_ID | (CPMT_INTERN_EVT << 8) | (participant_id & 0x7F);

  // Message format: reg (8 bits) | data (32 bits, little-endian)
  uint8_t payload[5];
  payload[0] = reg;
  payload[1] = (uint8_t)(data & 0xFF);
  payload[2] = (uint8_t)((data >> 8) & 0xFF);
  payload[3] = (uint8_t)((data >> 16) & 0xFF);
  payload[4] = (uint8_t)((data >> 24) & 0xFF);

  AppData *ad_ptr = appdata_new(can_id, payload, sizeof(payload));
  if (!ad_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to allocate AppData for internal event");
    return -1;
  }

  signed char ret = channel_send_appdata(channel_ptr, ad_ptr);
  appdata_free(ad_ptr);

  if (ret == 0) {
    LOG_DEBUG(logger_name_ptr,
              "Sent internal event CAN message: ID=0x%08X, reg=0x%02X, "
              "data=0x%08X",
              can_id, reg, data);
  } else {
    LOG_ERROR(logger_name_ptr, "Failed to send internal event CAN message");
  }

  return ret;
}

// Emit an internal event notification for a register/value pair.
signed char participant_report_internal_event(Participant *participant_ptr,
                                              uint8_t reg, uint32_t data) {
  if (!participant_ptr) {
    LOG_ERROR(logger_name_ptr, "Invalid participant pointer");
    return -1;
  }

  // Sent over the insecure channel: it carries the internal control plane.
  signed char ret =
      send_internal_event_can(&participant_ptr->insecure_channel,
                              participant_ptr->participant_id, reg, data);

  if (ret < 0) {
    LOG_ERROR(logger_name_ptr,
              "Failed to send internal event CAN message for register 0x%02X",
              reg);
    return -1;
  }

  LOG_INFO(logger_name_ptr, "Reported internal event: Register 0x%02X = 0x%08X",
           reg, data);
  return 0;
}

// Read reg's current value and report it via participant_report_internal_event().
signed char participant_report_register_change(Participant *participant_ptr,
                                               uint8_t reg) {
  if (!participant_ptr) {
    return -1;
  }

  uint32_t reg_value = 0;

  switch (reg) {
  case SPSEC_REG_INTEGRATOR_KEY_ID:
    if (participant_ptr->comm_keys.spsec_keys[2] &&
        participant_ptr->comm_keys.spsec_keys[2]->key_id !=
            SPSEC_KEY_ID_INVALID) {
      reg_value = participant_ptr->comm_keys.spsec_keys[2]->key_id;
    } else {
      reg_value = (uint32_t)SPSEC_KEY_ID_RESERVED;
    }
    break;

  case SPSEC_REG_SEED_KEY_ID:
    if (participant_ptr->comm_keys.spsec_keys[3] &&
        participant_ptr->comm_keys.spsec_keys[3]->key_id !=
            SPSEC_KEY_ID_INVALID) {
      reg_value = participant_ptr->comm_keys.spsec_keys[3]->key_id;
    } else {
      reg_value = (uint32_t)SPSEC_KEY_ID_RESERVED;
    }
    break;

  case SPSEC_REG_STATUS:
    reg_value = participant_get_status_register(participant_ptr);
    break;

  case SPSEC_REG_LAST_SECURITY_EVENT:
    reg_value = participant_ptr->state_info.last_event;
    break;

  case SPSEC_REG_PARTICIPANT_ID:
    reg_value = participant_ptr->participant_id;
    break;

  default:
    // Unknown register, don't report
    return 0;
  }

  return participant_report_internal_event(participant_ptr, reg, reg_value);
}

// Report a state transition: always the status register, plus the
// participant ID when entering WAITING.
signed char participant_report_state_transition(Participant *participant_ptr,
                                                spsec_state_t old_state,
                                                spsec_state_t new_state) {
  if (!participant_ptr) {
    return -1;
  }

  // Always report status register change on state transition
  participant_report_register_change(participant_ptr, SPSEC_REG_STATUS);

  // Report Participant ID when entering Waiting state (SPsec302 Section 7.1)
  if (new_state == SPSEC_STATE_WAITING && old_state != SPSEC_STATE_WAITING) {
    participant_report_register_change(participant_ptr,
                                       SPSEC_REG_PARTICIPANT_ID);
  }

  return 0;
}

// Record and broadcast the last security event register.
signed char participant_report_security_event(Participant *participant_ptr,
                                              uint16_t event_code) {
  if (!participant_ptr) {
    return -1;
  }

  // Update last security event register
  participant_ptr->state_info.last_event = event_code;

  // Report the change
  return participant_report_register_change(participant_ptr,
                                            SPSEC_REG_LAST_SECURITY_EVENT);
}
