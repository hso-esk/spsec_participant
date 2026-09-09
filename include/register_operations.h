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

#ifndef REGISTER_OPERATIONS_H
#define REGISTER_OPERATIONS_H

#include "participant.h"
#include "spsec_common.h"
#include <stdint.h>

// Check the active config session for overall/inactivity timeout.
spsec_ret_t check_session_timeout(Participant *participant_ptr);

// Configure the crypto handler with the given key and nonce.
spsec_ret_t setup_crypto_context(Participant *participant_ptr, uint8_t *nonce_ptr,
                                 size_t nonce_len, uint8_t *session_key_ptr,
                                 size_t auth_tag_size);

// Decrypt a register-operation ciphertext with the session key.
spsec_ret_t decrypt_message(Participant *participant_ptr,
                            uint8_t *ciphertext_ptr, size_t ciphertext_len,
                            uint8_t *auth_tag_ptr, uint8_t *plaintext_ptr,
                            uint8_t *assoc_data_ptr, size_t assoc_data_len);

// Encrypt a register-operation plaintext block with the session key.
spsec_ret_t encrypt_message(Participant *participant_ptr,
                            uint8_t *plaintext_ptr, size_t plaintext_len,
                            uint8_t *ciphertext_ptr, uint8_t *auth_tag_ptr,
                            uint8_t *assoc_data_ptr, size_t assoc_data_len);

#endif // REGISTER_OPERATIONS_H

// Generate a nonce for the current session counter.
spsec_ret_t participant_generate_nonce(Participant *participant_ptr,
                                       uint8_t **nonce_ptr);
