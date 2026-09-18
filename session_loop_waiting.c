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
#include "participant_channel.h"
#include "participant_timesync.h"
#include "register_operations.h"
#include "session_loops_internal.h"
#include "spsec_common.h"
#include "timer.h"
#include "crypto_kdf.h"
#include <stdint.h>

static const char *logger_name_ptr = "part_loop_waiting";

static signed char handle_time_synchronization(Participant *participant_ptr,
                                               uint64_t current_time_us,
                                               uint64_t *last_sync_attempt_ptr,
                                               uint64_t sync_interval_us) {
  if (!participant_ptr->timesync.is_synchronized &&
      current_time_us - *last_sync_attempt_ptr >= sync_interval_us) {
    LOG_INFO(logger_name_ptr,
             "Send timesync request because participant_ptr is ready");
    uint8_t *random_bytes_ptr = participant_send_timesync_request(participant_ptr);
    if (random_bytes_ptr) {
      free(participant_ptr->timesync.last_random_ptr);
      participant_ptr->timesync.last_random_ptr = random_bytes_ptr;
      LOG_CRITICAL(logger_name_ptr, "Sent time sync request");
    } else {
      LOG_ERROR(logger_name_ptr, "Failed to send time sync request");
    }
    *last_sync_attempt_ptr = current_time_us;
  }
  return 0;
}

signed char participant_check_timesync_ready(Participant *participant_ptr) {
  if (participant_ptr->comm_keys.spsec_keys[3] == NULL ||
      participant_ptr->comm_keys.spsec_salt[3] == NULL) {
    return -1;
  } else {
    return 0;
  }
}

static signed char process_waiting_loop_message(Participant *participant_ptr,
                                                SPsecMessage *msg_ptr) {
  signed char ret = 0;
  switch (msg_ptr->msg_type) {
  case MSGTYPE_CLIENT_HELLO:
    ret = participant_process_client_hello(participant_ptr,
                                           msg_ptr->msg_content_ptr);
    if (ret == 0) {
      ret = participant_send_server_hello(
          participant_ptr, ((SPsecClientHelloMessage *)msg_ptr->msg_content_ptr)
                               ->participant_id);
    }
    break;
  case MSGTYPE_CLIENT_FINISHED:
    ret = participant_process_client_finished(participant_ptr,
                                              msg_ptr->msg_content_ptr);
    if (ret == 0) {
      participant_ptr->session.cnt++;
      ret = participant_send_server_finished(
          participant_ptr,
          ((SPsecClientFinishedMessage *)msg_ptr->msg_content_ptr)
              ->participant_id);
      if (ret != 0) {
        LOG_ERROR(logger_name_ptr, "Failed to send Server Finished: %d", ret);
        return ret;
      }
      LOG_INFO(logger_name_ptr, "Set CONFIGURATION state");
      // participant_ptr->timesync.is_synchronized = false;
      participant_state_transition(participant_ptr, SPSEC_EVENT_ENTER_CONFIG);
      return 0;
    }
    break;
  case MSGTYPE_SYNC_TIME_BROADCAST:
    LOG_INFO(logger_name_ptr, "Received sync time broadcast in waiting state; "
                          "ignoring until time synchronized");
    break;
  case MSGTYPE_HEARTBEAT:
    LOG_INFO(logger_name_ptr, "Received heartbeat in waiting state; ignoring until "
                          "time synchronized");
    break;
  case MSGTYPE_TIME_SYNC_RESPONSE:
    ret = participant_process_mtls_auth_time(
        participant_ptr, msg_ptr->msg_content_ptr,
        participant_ptr->timesync.last_random_ptr);
    if (ret == 0) {

      LOG_INFO(logger_name_ptr, "Time synchronized, set SECURE state");
      participant_state_transition(participant_ptr,
                                   SPSEC_EVENT_SECURITY_ESTABLISHED);
      return 0;
    }
    break;
  default:
    LOG_WARNING(logger_name_ptr, "Unexpected message type %u in waiting mode",
                msg_ptr->msg_type);
    break;
  }
  return ret;
}

signed char participant_run_waiting_loop(Participant *participant_ptr) {
  LOG_INFO(logger_name_ptr, "Entering waiting loop");
  const uint64_t sync_interval_us =
      (uint64_t)(unsigned int)participant_ptr->timesync.retry_delay_seconds *
      1000000ULL;
  uint64_t last_sync_attempt_ptr = 0;
  while (participant_ptr->state_info.state == SPSEC_STATE_WAITING &&
         !participant_shutdown_requested()) {
    signed char ret = participant_check_timesync_ready(participant_ptr);
    if (ret == 0) {
      if (participant_ptr->timesync.is_role_authority == true) {
        // Generate random csalt if uninitialized or configured to redraw on entry
        bool need_csalt =
            !participant_ptr->timesync.csalt_generated ||
            participant_ptr->timesync.csalt_regen_mode ==
                SPSEC_CSALT_REGEN_SECURE_ENTRY;
        if (need_csalt) {
          uint8_t *csalt_bytes_ptr =
              random_generator_get_bytes(&participant_ptr->random_generator, 4);
          if (!csalt_bytes_ptr) {
            LOG_ERROR(logger_name_ptr,
                      "Time sync role: Failed to generate csalt from TRNG");
            return -1;
          }
          communication_keys_set_csalt(&participant_ptr->comm_keys, csalt_bytes_ptr);
          free(csalt_bytes_ptr);
          participant_ptr->timesync.csalt_generated = true;
          LOG_SECRET(logger_name_ptr, "Time sync role: Generated csalt from TRNG:",
                    participant_ptr->comm_keys.csalt, 4);
        } else {
          LOG_INFO(logger_name_ptr,
                   "Time sync role: reusing csalt drawn at power-up "
                   "(--csalt-regen powerup)");
        }
        // Sync role owns timer; mark synchronized and record timestamp.
        participant_ptr->timesync.is_synchronized = true;
        participant_ptr->timesync.last_successful =
            timer_get_current_time_us(&participant_ptr->timer);
        // New epoch: reset forward-only broadcast watermark.
        participant_ptr->timesync.broadcast_high_watermark = 0;
        participant_state_transition(participant_ptr,
                                     SPSEC_EVENT_SECURITY_ESTABLISHED);
        return 0;
      }
      uint64_t current_time_us =
          timer_get_current_time_us(&participant_ptr->timer);
      handle_time_synchronization(participant_ptr, current_time_us,
                                  &last_sync_attempt_ptr, sync_interval_us);
    }
    SPsecMessage *msg_ptr = participant_channel_receive(
        &participant_ptr->secure_channel, SECURE_RX_TIMEOUT_MS);
    // Check for session timeout to abort half-open handshakes (REQ-PART-013)
    check_session_timeout(participant_ptr);
    if (!msg_ptr) {
      continue;
    }
    // Update session activity on message receipt for timeout tracking
    participant_ptr->session.last_activity =
        timer_get_current_time_us(&participant_ptr->timer);
    LOG_INFO(logger_name_ptr, "Received secure message type: %u",
             msg_ptr->msg_type);
    ret = process_waiting_loop_message(participant_ptr, msg_ptr);
    uint8_t msg_type = msg_ptr->msg_type;
    // Type-aware free: a plain free() leaked app-data/heartbeat/broadcast
    // internal buffers (remotely-triggerable leak in WAITING).
    spsecmessage_dispose(msg_ptr);
    if (ret < 0) {
      LOG_ERROR(logger_name_ptr, "Failed to process message type %u: %d", msg_type,
                ret);
    }
  }
  return 0;
}
