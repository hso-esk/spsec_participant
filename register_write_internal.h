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

// Internal declarations for register write operations.

#ifndef REGISTER_WRITE_INTERNAL_H
#define REGISTER_WRITE_INTERNAL_H

#include "participant.h"
#include "spsec_common.h"

// Store a crypto key into the participant's key inventory.
spsec_ret_t apply_key(Participant *participant_ptr, uint8_t reg_index,
                      uint8_t *data_ptr);

// Store a salt value in the participant's key store.
spsec_ret_t apply_salt(Participant *participant_ptr, uint8_t salt_index,
                       uint8_t *data_ptr);

// Update the key identifier associated with a stored key.
spsec_ret_t apply_key_id(Participant *participant_ptr, uint8_t reg_index,
                         uint8_t *data_ptr, uint32_t data_len);

#endif // REGISTER_WRITE_INTERNAL_H
