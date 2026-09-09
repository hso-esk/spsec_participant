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

#ifndef REGISTER_WRITE_H
#define REGISTER_WRITE_H

#include "messages.h"
#include "participant.h"
#include <stdint.h>

// Register write operations: write-initiate processing, write-segment
// handling, and applying writes to registers.

// Process a WriteInitiate request.
spsec_ret_t register_process_write_initiate(Participant *participant_ptr,
                                            SPsecWriteInitiateMessage *msg_ptr);

// Validate a write's register/length and prepare for it.
spsec_ret_t register_check_write_status(Participant *participant_ptr,
                                        uint8_t reg, uint32_t len);

// Send the WriteInitiate response.
spsec_ret_t
register_send_write_initiate_response(Participant *participant_ptr,
                                      SPsecWriteInitiateMessage *msg_ptr);

// Validate a client write-segment request.
spsec_ret_t
register_check_write_segment(Participant *participant_ptr,
                             SPsecClientWriteSegmentRequest *msg_ptr);

// Apply a write segment to its targeted register.
spsec_ret_t
register_apply_write_segment(Participant *participant_ptr,
                             SPsecClientWriteSegmentRequest *msg_ptr);

// Send the write-segment response.
spsec_ret_t register_send_write_segment_response(Participant *participant_ptr,
                                                 uint8_t err);

// Reset the segmented write accumulator buffer and state.
void write_accum_reset(ParticipantWriteAccum *accum_ptr);

#endif /* REGISTER_WRITE_H */
