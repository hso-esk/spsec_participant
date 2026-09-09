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

#include "dll_events.h"
#include "keys.h"
#include "messages.h"
#include "participant.h"
#include "participant_channel.h"
#include "participant_storage.h"
#include "participant_timesync.h"
#include "session_loops_internal.h"
#include "spsec_common.h"
#include "spsec_registers.h"
#include "timer.h"
#include "utils_bytes.h"
#include <stdint.h>

static const char *logger_name_ptr = "part_session_common";

signed char
participant_handle_timesync_broadcast(Participant *participant_ptr,
                                      SPsecSyncTimeBroadcastMessage *tsb_msg_ptr) {
  SPsecAppData *msg_ptr = tsb_msg_ptr->spsec_app_data_ptr;
  LOG_DEBUG(logger_name_ptr, "=== TIMESYNC BROADCAST DECRYPTION DEBUG START ===");
  uint8_t timestamp_ptr[8];
  timer_get_timestamp(&participant_ptr->timer, timestamp_ptr);
  LOG_DEBUG_ARRAY(logger_name_ptr, "Current timestamp_ptr for app data decryption:",
                  timestamp_ptr, 8);
  LOG_DEBUG(logger_name_ptr, "Message address: 0x%08x", msg_ptr->address);
  LOG_DEBUG(logger_name_ptr, "Secure data length: %u",
            msg_ptr->secure_data_len);
  LOG_SECRET(logger_name_ptr, "Encrypted secure data:", msg_ptr->secure_data_ptr, msg_ptr->secure_data_len);
  LOG_SECRET(logger_name_ptr, "Auth tag:", msg_ptr->auth_tag_ptr, AUTH_TAG_SIZE);

  uint8_t *plaintext_ptr;
  size_t plaintext_len;
  signed char ret;

  uint8_t *first_key_ptr = participant_ptr->comm_keys.use_odd_key
                           ? participant_ptr->comm_keys.odd_key
                           : participant_ptr->comm_keys.even_key;
  uint8_t *second_key_ptr = participant_ptr->comm_keys.use_odd_key
                            ? participant_ptr->comm_keys.even_key
                            : participant_ptr->comm_keys.odd_key;
  LOG_DEBUG(logger_name_ptr,
            "DECRYPT_CALL site=session_loops.timesync addr=%08x len=%u key=%s",
            (unsigned)msg_ptr->address, (unsigned)msg_ptr->secure_data_len,
            participant_ptr->comm_keys.use_odd_key ? "odd" : "even");
  ret = participant_decrypt_spsec_appdata(participant_ptr, msg_ptr,
                                          timestamp_ptr, first_key_ptr,
                                          &plaintext_ptr, &plaintext_len);
  if (ret < 0) {
    LOG_INFO(logger_name_ptr,
             "Decryption with first key failed, trying fallback key");
    LOG_DEBUG(
        logger_name_ptr,
        "DECRYPT_CALL site=session_loops.timesync addr=%08x len=%u key=%s",
        (unsigned)msg_ptr->address, (unsigned)msg_ptr->secure_data_len,
        participant_ptr->comm_keys.use_odd_key ? "even" : "odd");
    ret = participant_decrypt_spsec_appdata(participant_ptr, msg_ptr,
                                            timestamp_ptr, second_key_ptr,
                                            &plaintext_ptr, &plaintext_len);
    if (ret < 0) {
      LOG_INFO(logger_name_ptr,
               "=== TIMESYNC BROADCAST DECRYPTION DEBUG END (FAILED) ===");
      // If sync broadcast verification fails after timeout, trigger recovery
      uint64_t now_us = timer_get_current_time_us(&participant_ptr->timer);
      if (participant_should_abort_on_sync_failure(participant_ptr, now_us)) {
        LOG_WARNING(logger_name_ptr,
                    "Sync broadcast unverifiable and no successful sync for "
                    "%llu us (limit %llu us) - assuming Sync role restarted; "
                    "aborting to WAITING to re-authenticate",
                    (unsigned long long)(now_us -
                                         participant_ptr->timesync.last_successful),
                    (unsigned long long)participant_ptr->timesync.broadcast_wait_us);
        participant_ptr->state_info.last_event = SPSEC_SYNC_REFR_TIMEOUT;
        participant_report_security_event(participant_ptr,
                                          SPSEC_SYNC_REFR_TIMEOUT);
        // Must clear this so the WAITING loop actually re-requests time sync.
        participant_ptr->timesync.is_synchronized = false;
        participant_state_transition(participant_ptr,
                                     SPSEC_EVENT_SECURITY_ABORT);
      }
      return -1;
    }
    LOG_DEBUG(logger_name_ptr, "Decryption successful with fallback key");
  } else {
    LOG_DEBUG(logger_name_ptr, "Decryption successful with first key");
  }
    LOG_DEBUG(logger_name_ptr, "Received timesync broadcast message with length %d",
              plaintext_len);
    LOG_SECRET(logger_name_ptr, "Decrypted timesync broadcast message:", plaintext_ptr,
              plaintext_len);
    LOG_DEBUG(logger_name_ptr,
              "=== TIMESYNC BROADCAST DECRYPTION DEBUG END (SUCCESS) ===");
    if (ret == 0 && plaintext_len == TIMESTAMP_SIZE + 2) {
      uint8_t adjusted_ts[8];
      memcpy(adjusted_ts, plaintext_ptr, TIMESTAMP_SIZE);
      if (participant_ptr->timesync.broadcast_offset != 0) {
        uint64_t ts = bytes_to_u64_le(adjusted_ts);
        // broadcast_offset is in reference 0.1ms ticks - convert to the
        // timer's actual tick domain (see timer_reference_ticks()).
        ts += timer_reference_ticks(
            &participant_ptr->timer,
            (uint64_t)participant_ptr->timesync.broadcast_offset);
        u64_to_bytes_le(ts, adjusted_ts);
      }

      LOG_DEBUG_ARRAY(logger_name_ptr, "Received timestamp_ptr:",
                      msg_ptr->timestamp, TIMESTAMP_SIZE);
      LOG_DEBUG_ARRAY(logger_name_ptr, "Adjusted timestamp_ptr:",
                      adjusted_ts, sizeof(adjusted_ts));

      timer_set_timestamp(&participant_ptr->timer, adjusted_ts);
      LOG_DEBUG(logger_name_ptr, "Attempt to set timestamp_ptr");

      // A verified broadcast counts as a successful sync too - without this,
      // the refresh watchdog fired 60s after onboarding regardless of
      // subsequently verified broadcasts.
      participant_ptr->timesync.last_successful =
          timer_get_current_time_us(&participant_ptr->timer);
    }
  // participant_decrypt_spsec_appdata allocates plaintext on success; free it
  // (on the failure paths above it already freed and returned).
  free(plaintext_ptr);
  return 0;
}

static spsec_ret_t handle_msg_client_hello(Participant *participant_ptr,
                                           SPsecClientHelloMessage *msg_ptr) {
  spsec_ret_t ret = participant_process_client_hello(participant_ptr, msg_ptr);
  if (ret == SPSEC_SUCCESS) {
    ret = participant_send_server_hello(participant_ptr, msg_ptr->participant_id);
  }
  return ret;
}

static spsec_ret_t
handle_msg_client_finished(Participant *participant_ptr,
                           SPsecClientFinishedMessage *msg_ptr) {
  spsec_ret_t ret = participant_process_client_finished(participant_ptr, msg_ptr);
  if (ret == SPSEC_SUCCESS) {
    participant_ptr->session.cnt++;
    ret = participant_send_server_finished(participant_ptr, msg_ptr->participant_id);
    LOG_INFO(logger_name_ptr, "Set CONFIGURATION state");
    participant_state_transition(participant_ptr, SPSEC_EVENT_ENTER_CONFIG);
  }
  return ret;
}

static spsec_ret_t handle_msg_app_data(Participant *participant_ptr,
                                       SPsecAppData *msg_ptr) {
  spsec_ret_t ret = SPSEC_SUCCESS;
  if (participant_ptr->state_info.state == SPSEC_STATE_SECURE) {
    ret = participant_process_spsec_appdata(participant_ptr, msg_ptr);
  } else {
    LOG_WARNING(logger_name_ptr,
                "Received MSGTYPE_APP_DATA before SECURE state; ignoring");
  }
  spsecappdata_free(msg_ptr);
  return ret;
}

static void
handle_msg_timesync_broadcast(Participant *participant_ptr,
                              SPsecSyncTimeBroadcastMessage *msg_ptr) {
  LOG_INFO(logger_name_ptr, "Received sync time broadcast");
  // A failure here is not fatal to the loop - the handler has already decided
  // whether it warrants a Security Abort (Sync restart) or is just a bad
  // frame to drop. Log it rather than discarding the result silently.
  if (participant_handle_timesync_broadcast(participant_ptr, msg_ptr) < 0) {
    LOG_DEBUG(logger_name_ptr, "Sync time broadcast could not be processed");
  }
  // Frees the attached SPsecAppData (+ its buffers), not just the outer struct.
  spsecsynctimebroadcast_free(msg_ptr);
}

static signed char process_secure_message(Participant *participant_ptr,
                                          SPsecMessage *msg_ptr) {
  signed char ret = 0;
  switch (msg_ptr->msg_type) {
  case MSGTYPE_TIME_SYNC_RESPONSE:
    LOG_DEBUG(logger_name_ptr,
              "Ignoring MSGTYPE_TIME_SYNC_RESPONSE in SECURE state");
    timesyncresponse_free((SPsecTimeSyncResponse *)msg_ptr->msg_content_ptr);
    ret = 0;
    break;
  case MSGTYPE_CLIENT_HELLO:
    ret = (signed char)handle_msg_client_hello(participant_ptr,
                                               msg_ptr->msg_content_ptr);
    spsecclienthello_free(msg_ptr->msg_content_ptr);
    break;
  case MSGTYPE_CLIENT_FINISHED:
    ret = (signed char)handle_msg_client_finished(participant_ptr,
                                                  msg_ptr->msg_content_ptr);
    spsecclientfinished_free(msg_ptr->msg_content_ptr);
    if (ret == 0)
      return 0; // State transition already handled
    break;
  case MSGTYPE_APP_DATA:
    ret = (signed char)handle_msg_app_data(participant_ptr,
                                           msg_ptr->msg_content_ptr);
    break;
  case MSGTYPE_SYNC_TIME_BROADCAST:
    handle_msg_timesync_broadcast(participant_ptr, msg_ptr->msg_content_ptr);
    ret = 0;
    break;
  case MSGTYPE_HEARTBEAT:
    ret = participant_process_heartbeat(participant_ptr,
                                        msg_ptr->msg_content_ptr);
    spsecheartbeat_free(msg_ptr->msg_content_ptr);
    break;
  case MSGTYPE_SECURITY_EVENT:
    free(msg_ptr->msg_content_ptr);
    break;
  case CPMT_AUTH_TIME:
    ret = 0;
    if (participant_ptr->timesync.is_role_authority) {
      ret = timesync_process_mtls_auth_time(
          participant_ptr, (SPsecTimeSyncRequest *)msg_ptr->msg_content_ptr);
    }
    timesyncrequest_free((SPsecTimeSyncRequest *)msg_ptr->msg_content_ptr);
    break;
  default:
    LOG_INFO(logger_name_ptr, "Unexpected message type in SECURE state: %u",
             msg_ptr->msg_type);
    free(msg_ptr->msg_content_ptr);
    break;
  }
  return ret;
}

void process_secure_messages(Participant *participant_ptr) {
  SPsecMessage *sec_msg_ptr = participant_channel_receive(
      &participant_ptr->secure_channel, SECURE_RX_TIMEOUT_MS);
  if (!sec_msg_ptr) {
    uint16_t dll_event =
        dll_events_check_rx_overrun(&participant_ptr->dll_event_ctx);
    if (dll_event != 0) {
      participant_handle_security_event(participant_ptr, dll_event);
    }
    return;
  }

  uint32_t can_id = 0;
  if (sec_msg_ptr->msg_type == MSGTYPE_APP_DATA) {
    SPsecAppData *sad_ptr = (SPsecAppData *)sec_msg_ptr->msg_content_ptr;
    if (sad_ptr) {
      can_id = sad_ptr->address;
    }
  }

  if (can_id != 0) {
    uint64_t current_time = timer_get_current_time_us(&participant_ptr->timer);
    uint16_t dll_event = dll_events_process_received_frame(
        &participant_ptr->dll_event_ctx, can_id, current_time);
    if (dll_event != 0) {
      participant_handle_security_event(participant_ptr, dll_event);
      // Own/duplicate frame looped back (e.g. vcan loopback): drop it here
      // instead of processing, or the resulting event report would loop back
      // too and retrigger this guard forever.
      spsecappdata_free(sec_msg_ptr->msg_content_ptr);
      spsecmessage_free(sec_msg_ptr);
      return;
    }
  }

  signed char ret = process_secure_message(participant_ptr, sec_msg_ptr);
  spsecmessage_free(sec_msg_ptr);
  if (ret < 0) {
    LOG_ERROR(logger_name_ptr, "Failed to process secure message: %d", ret);
  }
}

void process_insecure_messages(Participant *participant_ptr) {
  SPsecMessage *insec_msg_ptr = participant_receive_insecure_channel_message(
      &participant_ptr->insecure_channel, INSECURE_RX_TIMEOUT_MS);
  if (!insec_msg_ptr) {
    uint16_t dll_event =
        dll_events_check_rx_overrun(&participant_ptr->dll_event_ctx);
    if (dll_event != 0) {
      participant_handle_security_event(participant_ptr, dll_event);
    }
    return;
  }

  uint32_t can_id = 0;
  if (insec_msg_ptr->msg_type == MSGTYPE_APP_DATA) {
    AppData *ad_ptr = (AppData *)insec_msg_ptr->msg_content_ptr;
    if (ad_ptr) {
      can_id = ad_ptr->address;
    }
  }

  if (can_id != 0) {
    uint64_t current_time = timer_get_current_time_us(&participant_ptr->timer);
    uint16_t dll_event = dll_events_process_received_frame(
        &participant_ptr->dll_event_ctx, can_id, current_time);
    if (dll_event != 0) {
      participant_handle_security_event(participant_ptr, dll_event);
      // Own/duplicate frame looped back (e.g. vcan loopback): drop it here
      // instead of bridging it, or the resulting event report would loop
      // back too and retrigger this guard forever.
      appdata_free(insec_msg_ptr->msg_content_ptr);
      spsecmessage_free(insec_msg_ptr);
      return;
    }
  }

  // Never bridge data-plane frames before the initial time sync completes
  if (!participant_ptr->timesync.is_synchronized) {
    LOG_DEBUG(logger_name_ptr,
             "Insecure RX dropped: not yet time-synchronized");
    appdata_free(insec_msg_ptr->msg_content_ptr);
    spsecmessage_free(insec_msg_ptr);
    return;
  }

  LOG_DEBUG(logger_name_ptr, "Insecure RX bridged: msg_type=%u",
            (unsigned)insec_msg_ptr->msg_type);
  signed char ret = participant_handle_secure_message(
      participant_ptr, insec_msg_ptr->msg_content_ptr);
  appdata_free(insec_msg_ptr->msg_content_ptr);
  spsecmessage_free(insec_msg_ptr);
  if (ret < 0) {
    LOG_ERROR(logger_name_ptr, "Failed to process insecure message: %d", ret);
  }
}

void check_and_send_heartbeat(Participant *participant_ptr) {
  if (participant_ptr->state_info.state != SPSEC_STATE_SECURE)
    return;
  participant_check_heartbeat_timing(participant_ptr);
}

static signed char
participant_send_timesync_broadcast(Participant *participant_ptr,
                                    uint8_t *timestamp_ptr) {
  SPsecSyncTimeBroadcastMessage *msg_ptr = spsecsynctimebroadcast_new(0);
  if (!msg_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to allocate sync time broadcast message");
    return -1;
  }
  if (set_spsecsynctimebroadcast_timestamp(msg_ptr, timestamp_ptr) != 0) {
    spsecsynctimebroadcast_free(msg_ptr);
    return -1;
  }
  set_broadcast_timesync_address(msg_ptr->app_data_ptr);
  signed char ret =
      participant_handle_secure_message(participant_ptr, msg_ptr->app_data_ptr);
  spsecsynctimebroadcast_free(msg_ptr);
  return ret;
}

void process_timesync_broadcasts(Participant *participant_ptr,
                                 uint8_t *timestamp_ptr) {
  if (participant_ptr->timesync.is_role_authority != true)
    return;
  uint64_t current_time_us = timer_get_current_time_us(&participant_ptr->timer);
  if (current_time_us - participant_ptr->timesync.last_broadcast >=
      participant_ptr->timesync.broadcast_interval_us) {
    signed char sync_ret =
        participant_send_timesync_broadcast(participant_ptr, timestamp_ptr);
    if (sync_ret == 0) {
      participant_ptr->timesync.last_broadcast = current_time_us;
    } else {
      LOG_ERROR(logger_name_ptr, "Failed to send timesync broadcast: %d", sync_ret);
    }
  }
}
