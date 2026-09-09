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

#ifndef REGISTER_READ_H
#define REGISTER_READ_H

#include "messages.h"
#include "participant.h"
#include <stdint.h>

// Register read operations: read-initiate processing, read-segment
// handling, and preparing register data for reading.

// Process a ReadInitiate request.
spsec_ret_t register_process_read_initiate(Participant *participant_ptr,
                                           SPsecReadInitiateMessage *msg_ptr,
                                           uint8_t *read_register_ptr,
                                           uint32_t *real_len_ptr);

// Send the ReadInitiate response.
spsec_ret_t register_send_read_initiate_response(Participant *participant_ptr,
                                                 uint8_t *read_register_ptr,
                                                 uint32_t *real_len_ptr);

// Validate a read-segment request.
spsec_ret_t
register_check_read_segment_request(Participant *participant_ptr,
                                    SPsecClientReadSegmentRequest *msg_ptr);

// Prepare read-segment data from the targeted register.
spsec_ret_t register_prepare_read_segment_data(Participant *participant_ptr,
                                               uint8_t **data_bytes_ptr,
                                               uint32_t *data_len_ptr);

// Send the read-segment response.
spsec_ret_t register_send_read_segment_response(Participant *participant_ptr);

#endif /* REGISTER_READ_H */
