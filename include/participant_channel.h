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

#ifndef PARTICIPANT_CHANNEL_H
#define PARTICIPANT_CHANNEL_H

#include "communication_interface.h"
#include "messages.h"

typedef struct {
  CommChannel channel;
  uint8_t participant_id;
} SPsecCommChannel;

signed char participant_secure_channel_init(SPsecCommChannel *channel_ptr,
                                            const char *interface_name_ptr,
                                            uint8_t *participant_id_ptr);
signed char participant_insecure_channel_init(CommChannel *channel_ptr,
                                              const char *interface_name_ptr);

void participant_channel_destroy(SPsecCommChannel *channel_ptr);
SPsecMessage *participant_channel_receive(SPsecCommChannel *channel_ptr,
                                          int timeout);

signed char participant_channel_calculate_padding(int message_length);
signed char participant_channel_restore_timestamp_and_padding(
    uint8_t *original_timestamp_ptr, SPsecAppData *msg_ptr, uint8_t *result_ptr);

signed char
participant_channel_send_timesync_request(SPsecCommChannel *channel_ptr,
                                          SPsecTimeSyncRequest *msg_ptr);
signed char participant_channel_send_spapp_data(SPsecCommChannel *channel_ptr,
                                                SPsecAppData *msg_ptr);

void set_heartbeat_address(SPsecHeartbeatMessage *msg_ptr);

signed char
participant_channel_send_server_hello(SPsecCommChannel *channel_ptr,
                                      SPsecServerHelloMessage *msg_ptr);
void set_server_finished_address(SPsecServerFinishedMessage *msg_ptr);
signed char
participant_channel_send_server_finished(SPsecCommChannel *channel_ptr,
                                         SPsecServerFinishedMessage *msg_ptr);

void set_read_initiate_response_address(SPsecReadInitiateMessage *msg_ptr);
signed char participant_channel_send_read_initiate_response(
    SPsecCommChannel *channel_ptr, SPsecReadInitiateMessage *msg_ptr);

void set_read_segment_response_address(SPsecServerReadSegmentResponse *msg_ptr);
signed char participant_channel_send_read_segment_response(
    SPsecCommChannel *channel_ptr, SPsecServerReadSegmentResponse *msg_ptr);

void set_write_initiate_response_address(SPsecWriteInitiateMessage *msg_ptr);
signed char participant_channel_send_write_initiate_response(
    SPsecCommChannel *channel_ptr, SPsecWriteInitiateMessage *msg_ptr);
void set_write_segment_response_address(
    SPsecClientWriteSegmentResponse *msg_ptr);
signed char participant_channel_send_write_segment_response(
    SPsecCommChannel *channel_ptr, SPsecClientWriteSegmentResponse *msg_ptr);

void set_session_terminate_response_address(
    SPsecSessionTerminateMessage *msg_ptr);
signed char participant_channel_send_session_terminate_response(
    SPsecCommChannel *channel_ptr, SPsecSessionTerminateMessage *msg_ptr);

void set_broadcast_timesync_address(AppData *msg_ptr);

signed char participant_send_insecure_channel_message(CommChannel *channel_ptr,
                                                      AppData *msg_ptr);
SPsecMessage *participant_receive_insecure_channel_message(CommChannel *channel_ptr,
                                                           int timeout);

#endif