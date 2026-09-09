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

#include "config.h"
#include "keys.h"
#include "participant.h"
#include "participant_channel.h"
#include "spsec_common.h"
#include "spsec_registers.h"
#include "timer.h"
#include "utils_bytes.h"

#include "crypto_kdf.h"

static const char *logger_name_ptr = "part_session_handshake";

// Init session auth data from a ClientHello: store key selector + client
// random, generate the server random.
static spsec_ret_t setup_session_auth_data(Participant *participant_ptr,
                                           SPsecClientHelloMessage *msg_ptr) {
  if (participant_ptr->session.auth_tag_data_ptr) {
    authtagparticipantdata_free(participant_ptr->session.auth_tag_data_ptr);
    participant_ptr->session.auth_tag_data_ptr = NULL;
  }
  participant_ptr->session.auth_tag_data_ptr = authtagparticipantdata_new();
  if (!participant_ptr->session.auth_tag_data_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to allocate session auth tag data_ptr");
    return SPSEC_ERROR_OUT_OF_MEMORY;
  }
  memcpy(participant_ptr->session.auth_tag_data_ptr->key_selector,
         msg_ptr->key_selector, KEY_SELECTOR_SIZE);
  memcpy(participant_ptr->session.auth_tag_data_ptr->cli_random,
         msg_ptr->random, RANDOM_SIZE);
  uint8_t *server_random_ptr = random_generator_get_bytes(
      &participant_ptr->random_generator, RANDOM_SIZE);
  if (!server_random_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to generate server random");
    authtagparticipantdata_free(participant_ptr->session.auth_tag_data_ptr);
    participant_ptr->session.auth_tag_data_ptr = NULL;
    return SPSEC_ERROR_PLATFORM_RANDOM;
  }
  memcpy(participant_ptr->session.auth_tag_data_ptr->srv_random, server_random_ptr,
         RANDOM_SIZE);
  free(server_random_ptr);
  return SPSEC_SUCCESS;
}

// Look up the base key for a ClientHello key selector, or NULL if invalid.
static uint8_t *select_base_key(Participant *participant_ptr,
                                uint8_t key_selector) {
  switch (key_selector) {
  case KEY_SELECTOR_ZERO:
    LOG_INFO(logger_name_ptr, "Using zero key for handshake");
    if (!participant_ptr->comm_keys.spsec_keys[0]) {
      LOG_ERROR(logger_name_ptr, "Zero key not initialized");
      return NULL;
    }
    participant_ptr->session.auth_tag_data_ptr->spsec_salt_ptr =
        participant_ptr->comm_keys.spsec_salt[0];
    return participant_ptr->comm_keys.spsec_keys[0]->key;
  case KEY_SELECTOR_PROVISIONING:
    LOG_INFO(logger_name_ptr, "Using provisioning key for handshake");
    if (!participant_ptr->comm_keys.spsec_keys[1]) {
      LOG_ERROR(logger_name_ptr, "Provisioning key not initialized");
      return NULL;
    }
    participant_ptr->session.auth_tag_data_ptr->spsec_salt_ptr =
        participant_ptr->comm_keys.spsec_salt[1];
    return participant_ptr->comm_keys.spsec_keys[1]->key;
  case KEY_SELECTOR_INTEGRATOR:
    LOG_INFO(logger_name_ptr, "Using integrator key for handshake");
    if (!participant_ptr->comm_keys.spsec_keys[2]) {
      LOG_ERROR(logger_name_ptr, "Integrator key not initialized");
      return NULL;
    }
    participant_ptr->session.auth_tag_data_ptr->spsec_salt_ptr =
        participant_ptr->comm_keys.spsec_salt[2];
    return participant_ptr->comm_keys.spsec_keys[2]->key;
  case KEY_SELECTOR_SEED:
    // Seed key is reserved for communication key derivations and cannot open sessions
    LOG_ERROR(logger_name_ptr,
              "Seed key rejected for handshake: it is a derivation key for "
              "Communication Keys, not a configuration-session key");
    return NULL;
  default:
    LOG_ERROR(logger_name_ptr, "Unknown key selector: %u", key_selector);
    return NULL;
  }
}

// HKDF the session key from base_key_ptr using client||server random as salt.
static spsec_ret_t derive_session_key(Participant *participant_ptr,
                                      uint8_t *base_key_ptr) {
  uint8_t salt[32];
  memcpy(salt, participant_ptr->session.auth_tag_data_ptr->cli_random, RANDOM_SIZE);
  memcpy(salt + RANDOM_SIZE, participant_ptr->session.auth_tag_data_ptr->srv_random,
         RANDOM_SIZE);

  LOG_SECRET(logger_name_ptr, "Base key for session derivation:", base_key_ptr, KEY_LEN);
  LOG_SECRET(logger_name_ptr, "Client random for salt:",
            participant_ptr->session.auth_tag_data_ptr->cli_random, RANDOM_SIZE);
  LOG_SECRET(logger_name_ptr, "Server random for salt:",
            participant_ptr->session.auth_tag_data_ptr->srv_random, RANDOM_SIZE);
  LOG_SECRET(logger_name_ptr, "Salt for session key derivation:", salt, 32);

  if (crypto_hkdf_sha256(base_key_ptr, KEY_LEN, salt, sizeof(salt), NULL, 0,
                         participant_ptr->session.key,
                         KEY_LEN) != SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr, "Failed to derive session key");
    return SPSEC_ERROR_CRYPTO_KEY_DERIVATION;
  }
  LOG_SECRET(logger_name_ptr, "Derived session key:", participant_ptr->session.key, KEY_LEN);
  return SPSEC_SUCCESS;
}

// Handle an inbound ClientHello: validate target ID, derive the session key,
// and start timeout tracking.
spsec_ret_t participant_process_client_hello(Participant *participant_ptr,
                                             SPsecClientHelloMessage *msg_ptr) {
  if (participant_ptr->participant_id != msg_ptr->participant_id) {
    LOG_WARNING(
        logger_name_ptr,
        "Client Hello for other participant_ptr ID: %u (our participant_id %u)",
        msg_ptr->participant_id, participant_ptr->participant_id);
    return SPSEC_STATUS_MSG_IGNORED;
  }
  spsec_ret_t ret = setup_session_auth_data(participant_ptr, msg_ptr);
  if (ret != SPSEC_SUCCESS)
    return ret;
  uint8_t *base_key_ptr =
      select_base_key(participant_ptr, msg_ptr->key_selector[0]);
  if (!base_key_ptr) {
    authtagparticipantdata_free(participant_ptr->session.auth_tag_data_ptr);
    participant_ptr->session.auth_tag_data_ptr = NULL;
    participant_report_security_event(participant_ptr, SPSEC_SESS_HELLO_KEY_NOT_FOUND);
    return SPSEC_ERROR_KEY_NOT_FOUND;
  }
  ret = derive_session_key(participant_ptr, base_key_ptr);
  if (ret != SPSEC_SUCCESS) {
    authtagparticipantdata_free(participant_ptr->session.auth_tag_data_ptr);
    participant_ptr->session.auth_tag_data_ptr = NULL;
    return ret;
  }
  participant_ptr->session.cnt =
      calculate_shared_cnt(participant_ptr->session.auth_tag_data_ptr);
  LOG_DEBUG(logger_name_ptr, "Calculated session counter: %u (0x%08x)",
            participant_ptr->session.cnt, participant_ptr->session.cnt);
  participant_ptr->session.active = true;
  // Initialize session timeout tracking
  participant_ptr->session.start_time =
      timer_get_current_time_us(&participant_ptr->timer);
  participant_ptr->session.last_activity = participant_ptr->session.start_time;
  participant_ptr->session.timeout_us = DEFAULT_SESSION_TIMEOUT_US;
  participant_ptr->session.response_timeout_us =
      DEFAULT_SESSION_RESPONSE_TIMEOUT_US;
  LOG_INFO(logger_name_ptr, "Processed Client Hello successfully");
  return SPSEC_SUCCESS;
}

// Send the ServerHello response with the generated server random.
spsec_ret_t participant_send_server_hello(Participant *participant_ptr,
                                          uint8_t client_pid) {
  SPsecServerHelloMessage *hello_msg_ptr = spsecserverhello_new(
      client_pid, participant_ptr->session.auth_tag_data_ptr->srv_random);
  if (!hello_msg_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to create Server Hello message");
    return SPSEC_ERROR_OUT_OF_MEMORY;
  }
  spsec_ret_t ret = participant_channel_send_server_hello(
      &participant_ptr->secure_channel, hello_msg_ptr);
  spsecserverhello_free(hello_msg_ptr);
  if (ret != SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr, "Failed to send Server Hello to PID %u: %d",
              client_pid, ret);
    return SPSEC_ERROR_CHANNEL_SEND;
  }
  LOG_INFO(logger_name_ptr, "Sent Server Hello to PID %u", client_pid);
  return SPSEC_SUCCESS;
}

// Build the associated data for ClientFinished tag verification.
static void
prepare_client_finished_assoc_data(Participant *participant_ptr,
                                  uint32_t address, uint8_t *assoc_data_out_ptr) {
  memcpy(assoc_data_out_ptr, participant_ptr->session.auth_tag_data_ptr->key_selector,
         KEY_SELECTOR_SIZE);
  memcpy(assoc_data_out_ptr + 4, participant_ptr->session.auth_tag_data_ptr->cli_random,
         RANDOM_SIZE);
  memcpy(assoc_data_out_ptr + 20, participant_ptr->session.auth_tag_data_ptr->srv_random,
         RANDOM_SIZE);
  u32_to_bytes_le(address, assoc_data_out_ptr + 36);
}

// Validate ClientFinished's auth tag and, if it checks out, advance the
// session counter and cache the client's tag for ServerFinished.
spsec_ret_t
participant_process_client_finished(Participant *participant_ptr,
                                    SPsecClientFinishedMessage *msg_ptr) {
  if (msg_ptr->participant_id != participant_ptr->participant_id) {
    LOG_WARNING(
        logger_name_ptr,
        "Received Client Finished message for wrong participant_ptr ID: %u "
        "(our participant_id %u)",
        msg_ptr->participant_id, participant_ptr->participant_id);
    return SPSEC_STATUS_MSG_IGNORED;
  }
  // A ClientFinished is only meaningful after a ClientHello allocated the
  // session auth-tag context. Without this guard an unsolicited ClientFinished
  // dereferences a NULL pointer and crashes the participant.
  if (!participant_ptr->session.auth_tag_data_ptr) {
    LOG_WARNING(logger_name_ptr,
                "ClientFinished with no active session (no ClientHello) - "
                "ignoring");
    return SPSEC_STATUS_MSG_IGNORED;
  }
  participant_ptr->session.auth_tag_data_ptr->address = msg_ptr->address;
  uint8_t assoc_data_ptr[KEY_SELECTOR_SIZE + RANDOM_SIZE * 2 +
                     sizeof(msg_ptr->address)];
  prepare_client_finished_assoc_data(participant_ptr, msg_ptr->address,
                                     assoc_data_ptr);

  LOG_SECRET(logger_name_ptr, "ClientFinished assoc_data_ptr:", assoc_data_ptr, sizeof(assoc_data_ptr));
  LOG_SECRET(logger_name_ptr, "ClientFinished received auth_tag:", msg_ptr->auth_tag,
            AUTH_TAG_SIZE);
  LOG_DEBUG(logger_name_ptr,
            "ClientFinished: session_cnt before increment: %u (0x%08x)",
            participant_ptr->session.cnt, participant_ptr->session.cnt);
  // The sender advanced its counter before sending; validate against cnt+1 but
  // only commit the increment once the tag verifies, so a forged/bad-tag
  // ClientFinished cannot desynchronize the counter from the legitimate peer.
  uint32_t validated_cnt = participant_ptr->session.cnt + 1;
  LOG_DEBUG(logger_name_ptr, "ClientFinished: validating against cnt %u (0x%08x)",
            validated_cnt, validated_cnt);
  uint8_t *nonce_ptr = NULL;
  spsec_ret_t ret = generate_nonce_from_session_cnt(
      validated_cnt, &nonce_ptr,
      participant_ptr->session.auth_tag_data_ptr->spsec_salt_ptr);
  if (ret != SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr, "Failed to generate nonce_ptr from session counter");
    if (nonce_ptr)
      free(nonce_ptr);
    return ret;
  }
  LOG_SECRET(logger_name_ptr, "ClientFinished: generated nonce_ptr:", nonce_ptr, REQUIRED_NONCE_LEN);
  LOG_SECRET(logger_name_ptr, "ClientFinished: session_key (32 bytes):",
            participant_ptr->session.key, KEY_LEN);
  LOG_DEBUG(logger_name_ptr,
            "ClientFinished: calling setup_crypto_context_and_calculate_tag "
            "with key_len=%d, nonce_len=%d, assoc_len=%zu, tag_size=%d",
            KEY_LEN, REQUIRED_NONCE_LEN, sizeof(assoc_data_ptr), AUTH_TAG_SIZE);
  uint8_t calculated_tag[AUTH_TAG_SIZE];
  ret = setup_crypto_context_and_calculate_tag(
      &participant_ptr->crypto_handler, participant_ptr->session.key, nonce_ptr,
      REQUIRED_NONCE_LEN, assoc_data_ptr, sizeof(assoc_data_ptr), calculated_tag,
      AUTH_TAG_SIZE);
  if (ret != SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr, "setup_crypto_context_and_calculate_tag failed: %d",
              ret);
    free(nonce_ptr);
    return ret;
  }
  LOG_SECRET(logger_name_ptr, "ClientFinished: calculated_tag:", calculated_tag, AUTH_TAG_SIZE);
  LOG_SECRET(logger_name_ptr, "ClientFinished: received auth_tag:", msg_ptr->auth_tag,
            AUTH_TAG_SIZE);
  if (spsec_ct_memcmp(calculated_tag, msg_ptr->auth_tag, AUTH_TAG_SIZE) !=
      0) {
    LOG_ERROR(
        logger_name_ptr,
        "Invalid auth tag in Client Finished message - tags do not match");
    free(nonce_ptr);
    participant_report_security_event(participant_ptr, SPSEC_SESS_FINISH_AUTH_FAILURE);
    return SPSEC_ERROR_CRYPTO_AUTH;
  }
  free(nonce_ptr);
  // Tag verified: now commit the counter advance.
  participant_ptr->session.cnt = validated_cnt;
  memcpy(participant_ptr->session.auth_tag_data_ptr->cli_auth_tag,
         msg_ptr->auth_tag, AUTH_TAG_SIZE);
  LOG_INFO(logger_name_ptr, "Auth tag in Client Finished message is valid");

  // Don't reset lower-priority keys here - it used to wipe the Provisioning
  // key on every handshake (breaks SPsec102/302 §2.3.6). Erasure now only
  // happens in handle_manufacturer_reset_logic().
  return SPSEC_SUCCESS;
}

// Build the associated data for ServerFinished tag calculation.
static void
prepare_server_finished_assoc_data(Participant *participant_ptr,
                                  uint32_t address, uint8_t *assoc_data_out_ptr) {
  u32_to_bytes_le(participant_ptr->session.auth_tag_data_ptr->address,
                  assoc_data_out_ptr);
  memcpy(assoc_data_out_ptr + sizeof(uint32_t),
         participant_ptr->session.auth_tag_data_ptr->cli_random, RANDOM_SIZE);
  memcpy(assoc_data_out_ptr + sizeof(uint32_t) + RANDOM_SIZE,
         participant_ptr->session.auth_tag_data_ptr->srv_random, RANDOM_SIZE);
  memcpy(assoc_data_out_ptr + sizeof(uint32_t) + RANDOM_SIZE * 2,
         participant_ptr->session.auth_tag_data_ptr->cli_auth_tag, AUTH_TAG_SIZE);
  u32_to_bytes_le(address,
                  assoc_data_out_ptr + sizeof(uint32_t) + RANDOM_SIZE * 2 +
                      AUTH_TAG_SIZE);
}

// Build, sign, and send the ServerFinished message for the active session.
spsec_ret_t participant_send_server_finished(Participant *participant_ptr,
                                             uint8_t target_pid) {
  SPsecServerFinishedMessage *msg_ptr =
      spsecserverfinished_new(target_pid, participant_ptr->session.cnt);
  if (!msg_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to create Server Finished message");
    return SPSEC_ERROR_OUT_OF_MEMORY;
  }
  set_server_finished_address(msg_ptr);
  uint8_t assoc_data_ptr[sizeof(uint32_t) + RANDOM_SIZE * 2 + AUTH_TAG_SIZE +
                     sizeof(msg_ptr->address)];
  prepare_server_finished_assoc_data(participant_ptr, msg_ptr->address,
                                     assoc_data_ptr);

  uint8_t *nonce_ptr = NULL;
  if (generate_nonce_from_session_cnt(
          participant_ptr->session.cnt, &nonce_ptr,
          participant_ptr->session.auth_tag_data_ptr->spsec_salt_ptr) < 0 ||
      !nonce_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to generate nonce_ptr for ServerFinished");
    spsecserverfinished_free(msg_ptr);
    free(nonce_ptr);
    return SPSEC_ERROR_OUT_OF_MEMORY;
  }
  LOG_SECRET(logger_name_ptr, "Assoc data for ServerFinished auth tag:", assoc_data_ptr,
            sizeof(assoc_data_ptr));
  LOG_SECRET(logger_name_ptr, "Session key for ServerFinished auth tag:",
            participant_ptr->session.key, KEY_LEN);
  LOG_SECRET(logger_name_ptr, "Nonce for ServerFinished auth tag:", nonce_ptr, REQUIRED_NONCE_LEN);
  spsec_ret_t ret = setup_crypto_context_and_calculate_tag(
      &participant_ptr->crypto_handler, participant_ptr->session.key, nonce_ptr,
      REQUIRED_NONCE_LEN, assoc_data_ptr, sizeof(assoc_data_ptr), msg_ptr->auth_tag,
      AUTH_TAG_SIZE);
  if (ret == SPSEC_SUCCESS) {
    LOG_SECRET(logger_name_ptr, "Server Finished message auth_tag:", msg_ptr->auth_tag,
              AUTH_TAG_SIZE);
  } else {
    LOG_ERROR(logger_name_ptr,
              "Failed to calculate auth tag for Server Finished message: %d",
              ret);
    spsecserverfinished_free(msg_ptr);
    free(nonce_ptr);
    return ret;
  }
  ret = participant_channel_send_server_finished(
      &participant_ptr->secure_channel, msg_ptr);
  spsecserverfinished_free(msg_ptr);
  free(nonce_ptr);
  if (ret != SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr, "Failed to send Server Finished to PID %u: %d",
              target_pid, ret);
    return SPSEC_ERROR_CHANNEL_SEND;
  }
  LOG_INFO(logger_name_ptr, "Sent Server Finished to PID %u", target_pid);
  return SPSEC_SUCCESS;
}

// Build and sign a SessionTerminate response with the current session key.
static spsec_ret_t
create_session_terminate_response(Participant *participant_ptr,
                                  SPsecSessionTerminateMessage **response_msg_ptr) {

  *response_msg_ptr = spsecsessionterminatemsg_new(participant_ptr->participant_id,
                                               participant_ptr->session.cnt);
  if (!*response_msg_ptr)
    return SPSEC_ERROR_OUT_OF_MEMORY;
  set_session_terminate_response_address(*response_msg_ptr);
  uint8_t *nonce_ptr = NULL;
  if (generate_nonce_from_session_cnt(
          participant_ptr->session.cnt, &nonce_ptr,
          participant_ptr->session.auth_tag_data_ptr->spsec_salt_ptr) < 0 ||
      !nonce_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to generate nonce_ptr for session terminate");
    spsecsessionterminatemsg_free(*response_msg_ptr);
    *response_msg_ptr = NULL;
    free(nonce_ptr);
    return SPSEC_ERROR_OUT_OF_MEMORY;
  }
  LOG_INFO(logger_name_ptr, "Session counter: %u", participant_ptr->session.cnt);
  LOG_SECRET(logger_name_ptr, "Session terminate response nonce_ptr:", nonce_ptr, REQUIRED_NONCE_LEN);
  spsec_ret_t ret = crypto_handler_set_context(
      &participant_ptr->crypto_handler, participant_ptr->session.key, nonce_ptr,
      REQUIRED_NONCE_LEN, AUTH_TAG_SIZE);
  if (ret != SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr,
              "Failed to set crypto context for session terminate response");
    free(nonce_ptr);
    return ret;
  }
  uint8_t *assoc_data_ptr = (uint8_t *)&(*response_msg_ptr)->address;
  ret = setup_crypto_context_and_calculate_tag(
      &participant_ptr->crypto_handler, participant_ptr->session.key, nonce_ptr,
      REQUIRED_NONCE_LEN, assoc_data_ptr, sizeof(uint32_t),
      (*response_msg_ptr)->auth_tag, AUTH_TAG_SIZE);
  if (ret != SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr, "Failed to encrypt session terminate response");
    free(nonce_ptr);
    return ret;
  }
  free(nonce_ptr);
  LOG_INFO(logger_name_ptr, "Session terminate response prepared for address: %08x",
           (*response_msg_ptr)->address);
  return SPSEC_SUCCESS;
}

// Recompute the expected auth tag for the current session counter and
// compare it to received_tag_ptr.
static spsec_ret_t participant_validate_auth_tag(Participant *participant_ptr,
                                                 uint8_t *received_tag_ptr,
                                                 uint8_t *msg_address_ptr,
                                                 size_t addr_size) {
  uint8_t *nonce_ptr = NULL;
  spsec_ret_t ret = generate_nonce_from_session_cnt(
      participant_ptr->session.cnt, &nonce_ptr,
      participant_ptr->session.auth_tag_data_ptr->spsec_salt_ptr);
  if (ret != SPSEC_SUCCESS || !nonce_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to generate nonce_ptr for auth tag validation");
    free(nonce_ptr);
    return ret != SPSEC_SUCCESS ? ret : SPSEC_ERROR_OUT_OF_MEMORY;
  }

  uint8_t expected_auth_tag[AUTH_TAG_SIZE];
  ret = setup_crypto_context_and_calculate_tag(
      &participant_ptr->crypto_handler, participant_ptr->session.key, nonce_ptr,
      REQUIRED_NONCE_LEN, msg_address_ptr, addr_size, expected_auth_tag,
      AUTH_TAG_SIZE);
  if (ret != SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr, "Failed to calculate expected authentication tag");
    if (nonce_ptr)
      free(nonce_ptr);
    return ret;
  }

  if (spsec_ct_memcmp(received_tag_ptr, expected_auth_tag, AUTH_TAG_SIZE) != 0) {
    LOG_ERROR(logger_name_ptr, "Authentication tag mismatch");
    free(nonce_ptr);
    return SPSEC_ERROR_CRYPTO_AUTH;
  }

  LOG_INFO(logger_name_ptr, "Authentication tag verified successfully");
  free(nonce_ptr);
  return SPSEC_SUCCESS;
}

// Validate a client's SessionTerminate and, on success, advance the counter
// and clear any in-progress multi-segment write.
spsec_ret_t
participant_process_session_terminate(Participant *participant_ptr,
                                      SPsecSessionTerminateMessage *msg_ptr) {
  if (msg_ptr->participant_id != participant_ptr->participant_id) {
    LOG_ERROR(
        logger_name_ptr,
        "Session termination request for another participant_ptr with ID: %u",
        msg_ptr->participant_id);
    return SPSEC_STATUS_MSG_IGNORED;
  }
  // Reject an unsolicited SessionTerminate (no ClientHello established a
  // session): validating it would dereference a NULL auth_tag_data_ptr.
  if (!participant_ptr->session.auth_tag_data_ptr) {
    LOG_WARNING(logger_name_ptr,
                "SessionTerminate with no active session - ignoring");
    return SPSEC_STATUS_MSG_IGNORED;
  }
  LOG_INFO(logger_name_ptr, "Processing session termination request");
  uint32_t client_cnt_lsb = (uint32_t)((msg_ptr->address >> 16) & 0xFF);
  uint32_t server_cnt_lsb_before =
      (uint32_t)(participant_ptr->session.cnt & 0xFF);
  LOG_INFO(logger_name_ptr,
           "Terminate counters: client_cnt_lsb=%u, server_cnt_lsb(before)=%u",
           client_cnt_lsb, server_cnt_lsb_before);
  participant_ptr->session.cnt++;
  uint8_t *msg_address_ptr = (uint8_t *)&msg_ptr->address;
  spsec_ret_t ret = participant_validate_auth_tag(
      participant_ptr, msg_ptr->auth_tag, msg_address_ptr, 4);
  if (ret != SPSEC_SUCCESS) {
    // Roll back the counter so a forged/bad-tag terminate cannot desync it.
    participant_ptr->session.cnt--;
    participant_report_security_event(participant_ptr, SPSEC_SESS_KEY_AUTH_FAILURE);
  } else {
    // Session terminated cleanly: clear any uncommitted multi-segment write accumulator
    memset(participant_ptr->write_accum.buf, 0, sizeof(participant_ptr->write_accum.buf));
    participant_ptr->write_accum.len = 0;
    participant_ptr->write_accum.expected = 0;
    participant_ptr->write_accum.active = false;
  }
  return ret;
}

// Build, sign, and send the SessionTerminate response.
spsec_ret_t
participant_send_session_terminate_response(Participant *participant_ptr) {
  SPsecSessionTerminateMessage *response_msg_ptr = NULL;
  spsec_ret_t ret =
      create_session_terminate_response(participant_ptr, &response_msg_ptr);
  if (ret != SPSEC_SUCCESS) {
    if (response_msg_ptr)
      spsecsessionterminatemsg_free(response_msg_ptr);
    return ret;
  }
  ret = participant_channel_send_session_terminate_response(
      &participant_ptr->secure_channel, response_msg_ptr);
  if (ret != SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr, "Failed to send session terminate response");
    spsecsessionterminatemsg_free(response_msg_ptr);
    return SPSEC_ERROR_CHANNEL_SEND;
  }
  LOG_INFO(logger_name_ptr, "Session terminate response sent successfully");
  spsecsessionterminatemsg_free(response_msg_ptr);
  return SPSEC_SUCCESS;
}