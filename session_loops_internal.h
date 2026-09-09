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

#ifndef SESSION_LOOPS_INTERNAL_H
#define SESSION_LOOPS_INTERNAL_H

#include "messages.h"
#include "participant.h"

// RX poll timeouts shared by every state loop that calls
// participant_channel_receive_secure/insecure().
#define SECURE_RX_TIMEOUT_MS 2
#define INSECURE_RX_TIMEOUT_MS 5

// Shared Message Processing and Loop Helpers
void process_secure_messages(Participant *participant_ptr);
void process_insecure_messages(Participant *participant_ptr);

// Decrypts one Sync Time broadcast against the rolling comm keys
signed char
participant_handle_timesync_broadcast(Participant *participant_ptr,
                                      SPsecSyncTimeBroadcastMessage *tsb_msg_ptr);
void check_and_send_heartbeat(Participant *participant_ptr);
void process_timesync_broadcasts(Participant *participant_ptr,
                                 uint8_t *timestamp_ptr);

// Helper exposed for use if needed, check usage
signed char participant_check_timesync_ready(Participant *participant_ptr);

// Warning state helper
signed char
participant_check_warning_state_hold_time(Participant *participant_ptr);

// Main loops
signed char participant_run_waiting_loop(Participant *participant_ptr);
signed char participant_run_secure_state_loop(Participant *participant_ptr);
signed char participant_run_warning_state_loop(Participant *participant_ptr);

#endif
