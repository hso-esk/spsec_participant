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

#ifndef PARTICIPANT_KEYS_H
#define PARTICIPANT_KEYS_H

#include "keys.h"
#include <stdint.h>

signed char communication_keys_update(CommunicationKeys *comm_keys_ptr,
                                      uint8_t *timestamp_ptr);

// Store new csalt and invalidate cached communication keys.
void communication_keys_set_csalt(CommunicationKeys *comm_keys_ptr,
                                  const uint8_t new_csalt[4]);

#endif