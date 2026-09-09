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

#ifndef CONFIGURATION_LOOP_H
#define CONFIGURATION_LOOP_H

#include "participant.h"

// Main loop for CONFIGURATION state: dispatches read/write ops and
// session termination.

// Run the configuration loop until the state machine exits CONFIGURATION.
signed char participant_run_configuration_loop(Participant *participant_ptr);

#endif /* CONFIGURATION_LOOP_H */
