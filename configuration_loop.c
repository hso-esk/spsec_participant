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

// Main loop for CONFIGURATION state: dispatches read/write ops and
// session termination.

#include "configuration_loop.h"
#include "messages.h"
#include "participant.h"
#include "participant_channel.h"
#include "register_operations.h"
#include "register_read.h"
#include "register_write.h"
#include "spsec_common.h"
#include "timer.h"

static const char *logger_name_ptr = "configuration_loop";

// Process a read-initiate message.
static signed char handle_read_initiate(Participant *participant_ptr,
                                        SPsecMessage *msg_ptr) {
  uint8_t read_register;
  uint32_t real_len;
  signed char ret = register_process_read_initiate(
      participant_ptr, (SPsecReadInitiateMessage *)msg_ptr->msg_content_ptr,
      &read_register, &real_len);
  if (ret == 0) {
    participant_ptr->session.cnt++;
    ret = register_send_read_initiate_response(participant_ptr, &read_register,
                                               &real_len);
    if (ret == 0) {
      participant_ptr->state_info.prepared_read_register = read_register;
      LOG_INFO(logger_name_ptr, "Read initiate response sent");
    }
  }
  return ret;
}

// Handle an inbound read-segment request.
static signed char handle_read_segment(Participant *participant_ptr,
                                       SPsecMessage *msg_ptr) {
  signed char ret = register_check_read_segment_request(
      participant_ptr,
      (SPsecClientReadSegmentRequest *)msg_ptr->msg_content_ptr);
  if (ret == 0) {
    participant_ptr->session.cnt++;
    ret = register_send_read_segment_response(participant_ptr);
    if (ret == 0) {
      LOG_INFO(logger_name_ptr, "Read segment response sent");
    }
  }
  return ret;
}

// Handle a write-initiate request.
static signed char handle_write_initiate(Participant *participant_ptr,
                                         SPsecMessage *msg_ptr) {
  SPsecWriteInitiateMessage *write_init_ptr =
      (SPsecWriteInitiateMessage *)msg_ptr->msg_content_ptr;
  signed char ret =
      register_process_write_initiate(participant_ptr, write_init_ptr);
  if (ret == 0) {
    ret = register_check_write_status(participant_ptr, write_init_ptr->reg,
                                      write_init_ptr->len);
    if (ret == 0) {
      participant_ptr->session.cnt++;
      ret = register_send_write_initiate_response(participant_ptr, write_init_ptr);
      if (ret == 0) {
        LOG_INFO(logger_name_ptr, "Write initiate response sent");
      }
    }
  }
  return ret;
}

// Handle write-segment data from the client.
static signed char handle_write_segment(Participant *participant_ptr,
                                        SPsecMessage *msg_ptr) {
  SPsecClientWriteSegmentRequest *write_seg_ptr =
      (SPsecClientWriteSegmentRequest *)msg_ptr->msg_content_ptr;
  signed char ret = register_check_write_segment(participant_ptr, write_seg_ptr);
  if (ret == 0) {
    ret = register_apply_write_segment(participant_ptr, write_seg_ptr);
    participant_ptr->session.cnt++;
    signed char send_ret =
        register_send_write_segment_response(participant_ptr, (uint8_t)ret);
    if (send_ret == 0) {
      LOG_INFO(logger_name_ptr, "ServerWriteSegmentResponse sent");
    }
    return send_ret < 0 ? send_ret : ret;
  }
  return ret;
}

// Handle a session-termination request in configuration mode.
static signed char handle_terminate(Participant *participant_ptr,
                                    SPsecMessage *msg_ptr) {
  signed char ret = participant_process_session_terminate(
      participant_ptr,
      (SPsecSessionTerminateMessage *)msg_ptr->msg_content_ptr);
  if (ret == 0) {
    participant_ptr->session.cnt++;
    ret = participant_send_session_terminate_response(participant_ptr);
    if (ret == 0) {
      LOG_INFO(logger_name_ptr,
               "Session terminate response sent, exit CONFIGURATION state");
      participant_ptr->session.active = false;
      if (participant_ptr->session.auth_tag_data_ptr) {
        authtagparticipantdata_free(participant_ptr->session.auth_tag_data_ptr);
        participant_ptr->session.auth_tag_data_ptr = NULL;
      }
      spsec_explicit_bzero(participant_ptr->session.key, KEY_LEN);
      participant_state_transition(participant_ptr, SPSEC_EVENT_EXIT_CONFIG);
    }
  }
  return ret;
}

signed char participant_run_configuration_loop(Participant *participant_ptr) {
  while (participant_ptr->state_info.state == SPSEC_STATE_CONFIGURATION &&
         !participant_shutdown_requested()) {
    // Check session timeout
    if (check_session_timeout(participant_ptr) < 0) {
      LOG_INFO(logger_name_ptr, "Session terminated due to timeout");
      break;
    }

    SPsecMessage *msg_ptr =
        participant_channel_receive(&participant_ptr->secure_channel, 20);
    if (!msg_ptr) {
      continue;
    }

    // Update session activity on message receipt
    participant_ptr->session.last_activity =
        timer_get_current_time_us(&participant_ptr->timer);

    signed char ret = 0;
    switch (msg_ptr->msg_type) {
    case MSGTYPE_CLIENT_READ_INITIATE:
      LOG_INFO(logger_name_ptr,
               "Processing read initiate request in configuration mode");
      ret = handle_read_initiate(participant_ptr, msg_ptr);
      break;
    case MSGTYPE_CLIENT_READ_SEGMENT:
      LOG_INFO(logger_name_ptr, "Processing read segment in configuration mode");
      ret = handle_read_segment(participant_ptr, msg_ptr);
      break;
    case MSGTYPE_CLIENT_WRITE_INITIATE:
      LOG_INFO(logger_name_ptr,
               "Processing write initiate request in configuration mode");
      ret = handle_write_initiate(participant_ptr, msg_ptr);
      break;
    case MSGTYPE_CLIENT_WRITE_SEGMENT:
      LOG_INFO(logger_name_ptr, "Processing write segment in configuration mode");
      ret = handle_write_segment(participant_ptr, msg_ptr);
      break;
    case MSGTYPE_CLIENT_TERMINATE:
      LOG_INFO(logger_name_ptr,
               "Processing terminate request in configuration mode");
      ret = handle_terminate(participant_ptr, msg_ptr);
      break;
    case MSGTYPE_SYNC_TIME_BROADCAST:
      LOG_DEBUG(logger_name_ptr,
                "Ignoring sync time broadcast in configuration mode");
      break;
    case MSGTYPE_HEARTBEAT:
      LOG_DEBUG(logger_name_ptr,
                "Ignoring heartbeat message in configuration mode");
      break;
    default:
      LOG_WARNING(logger_name_ptr,
                  "Unexpected message type %u in configuration mode",
                  msg_ptr->msg_type);
      break;
    }

    // Free message content using the correct destructor per type
    uint8_t msg_type = msg_ptr->msg_type; // capture before free (used below)
    switch (msg_ptr->msg_type) {
    case MSGTYPE_CLIENT_READ_INITIATE:
      spsecreadinitiatemessage_free(
          (SPsecReadInitiateMessage *)msg_ptr->msg_content_ptr);
      break;
    case MSGTYPE_CLIENT_READ_SEGMENT:
      spsecreadsegmentrequest_free(
          (SPsecClientReadSegmentRequest *)msg_ptr->msg_content_ptr);
      break;
    case MSGTYPE_CLIENT_WRITE_INITIATE:
      spsecwriteinitiatemessage_free(
          (SPsecWriteInitiateMessage *)msg_ptr->msg_content_ptr);
      break;
    case MSGTYPE_CLIENT_WRITE_SEGMENT:
      spsecwritesegmentrequest_free(
          (SPsecClientWriteSegmentRequest *)msg_ptr->msg_content_ptr);
      break;
    case MSGTYPE_CLIENT_TERMINATE:
      spsecsessionterminatemsg_free(
          (SPsecSessionTerminateMessage *)msg_ptr->msg_content_ptr);
      break;
    case MSGTYPE_SYNC_TIME_BROADCAST:
      spsecsynctimebroadcast_free(
          (SPsecSyncTimeBroadcastMessage *)msg_ptr->msg_content_ptr);
      break;
    case MSGTYPE_HEARTBEAT:
      spsecheartbeat_free((SPsecHeartbeatMessage *)msg_ptr->msg_content_ptr);
      break;
    default:
      free(msg_ptr->msg_content_ptr);
      break;
    }
    spsecmessage_free(msg_ptr);
    if (ret < 0) {
      LOG_ERROR(logger_name_ptr, "Failed to process message type %u: %d", msg_type,
                ret);
    }
  }

  LOG_INFO(logger_name_ptr, "Exiting configuration loop");
  return 0;
}
