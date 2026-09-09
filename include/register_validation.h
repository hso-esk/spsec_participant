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

#ifndef REGISTER_VALIDATION_H
#define REGISTER_VALIDATION_H

#include "participant.h"
#include <stdbool.h>
#include <stdint.h>

// Register access validation: permission checks and key-installation
// sequence rules.

// True if the key slot exists and has a valid key ID.
bool register_is_key_set(Participant *participant_ptr, uint8_t key_index);

// True if the key slot holds non-zero key material (vs. only a key ID).
bool register_is_key_material_set(Participant *participant_ptr, uint8_t key_index);

// Enforce write-once protection and warn if a key ID wasn't erased before
// installing a new provisioned key.
signed char
register_validate_key_installation_sequence(Participant *participant_ptr,
                                            uint8_t reg);

// Check whether reg is readable/writable in the current session.
signed char register_check_access(Participant *participant_ptr, uint8_t reg,
                                  bool is_write);

#endif /* REGISTER_VALIDATION_H */
