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

#ifndef PARTICIPANT_TIMESYNC_H
#define PARTICIPANT_TIMESYNC_H

#include "messages.h"
#include "participant.h"

signed char timesync_process_mtls_auth_time(Participant *participant_ptr,
                                            SPsecTimeSyncRequest *msg_ptr);

#endif