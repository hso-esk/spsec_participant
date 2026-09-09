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

#ifndef PARTICIPANT_STORAGE_H
#define PARTICIPANT_STORAGE_H

#include "participant.h"
#include <stdint.h>

// Load all keys and configuration from storage.
signed char participant_storage_load_all(Participant *participant_ptr);

// Save a key to storage.
signed char participant_storage_save_key(Participant *participant_ptr,
                                         uint8_t key_index);

// Save a salt to storage.
signed char participant_storage_save_salt(Participant *participant_ptr,
                                          uint8_t salt_index);

// Save a key ID to storage.
signed char participant_storage_save_key_id(Participant *participant_ptr,
                                            uint8_t key_index);

// Get a key ID from storage.
signed char participant_storage_get_key_id(Participant *participant_ptr,
                                           uint8_t key_index,
                                           uint32_t *key_id_ptr);

// Save participant ID to storage.
signed char
participant_storage_save_participant_id(Participant *participant_ptr);

// Save heartbeat timing to storage.
signed char
participant_storage_save_heartbeat_timing(Participant *participant_ptr);

// Save heartbeat monitor config to storage.
signed char
participant_storage_save_heartbeat_monitor(Participant *participant_ptr);

// Save sync role activation to storage.
signed char participant_storage_save_sync_role(Participant *participant_ptr);

// Save CAN bitrate to storage.
signed char participant_storage_save_can_bitrate(Participant *participant_ptr);

// Save timestamp to storage.
signed char participant_storage_save_timestamp(Participant *participant_ptr);

// Delete a key from storage (used by manufacturer reset).
signed char participant_storage_delete_key(Participant *participant_ptr,
                                           uint8_t key_index);

#endif // PARTICIPANT_STORAGE_H
