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

#include "participant_keys.h"
#include "crypto_kdf.h"
#include "keys.h"
#include "spsec_common.h"
#include "spsec_registers.h"
#include <stdint.h>

static const char *logger_name_ptr = "participant_keys";

// Decode an unsigned 64-bit little-endian value.
static inline uint64_t read_le64(const uint8_t ts_le_ptr[8]) {
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i)
    v |= ((uint64_t)ts_le_ptr[i]) << (8 * i);
  return v;
}

// Write the least-significant 40 bits of v in little-endian format.
static inline void write_le40(uint64_t v, uint8_t out5_ptr[5]) {
  for (int i = 0; i < 5; ++i)
    out5_ptr[i] = (uint8_t)((v >> (8 * i)) & 0xFF);
}

// Find the previous/next even-odd key transition instants around T.
static int compute_transition_pair(uint64_t T, uint64_t *N_last_ptr,
                                   int64_t *m_last_ptr, uint64_t *N_next_ptr,
                                   int64_t *m_next_ptr) {
  const uint64_t BIT23 = (1ULL << 23);
  const uint64_t PERIOD = (1ULL << 24);

  uint64_t r = T & (PERIOD - 1ULL); // low 24 bits
  uint64_t hi = T >> 24;            // m candidate

  int64_t m_n = (r < BIT23) ? (int64_t)hi : (int64_t)hi + 1;
  int64_t m_l = m_n - 1;

  // Guard against T extremely small (before the very first transition)
  if (m_l < 0)
    return -1;

  *m_last_ptr = m_l;
  *m_next_ptr = m_n;
  *N_last_ptr = ((uint64_t)m_l << 24) + BIT23;
  *N_next_ptr = ((uint64_t)m_n << 24) + BIT23;
  return 0;
}

// Split the timestamp into the 5-byte even/odd transition fragments and
// report which key is currently active.
unsigned char get_required_ts_parts(const uint8_t timestamp_le8_ptr[8],
                                    uint8_t even_ts_part_ptr[5],
                                    uint8_t odd_ts_part_ptr[5], bool *use_odd_now_ptr) {
  uint64_t T = read_le64(timestamp_le8_ptr);

  uint64_t N_last, N_next;
  int64_t m_last, m_next;
  int rc = compute_transition_pair(T, &N_last, &m_last, &N_next, &m_next);
  if (rc != 0)
    return (unsigned char)rc;

  // Selector: bit 24 of the current timestamp_ptr
  if (use_odd_now_ptr)
    *use_odd_now_ptr = ((T >> 24) & 1ULL) != 0;

  // At transition m: bit24 == (m & 1). 0 => even, 1 => odd.
  bool last_is_odd = (m_last & 1) != 0;

  if (last_is_odd) {
    // Current window uses odd from N_last; next will be even at N_next.
    write_le40(N_next, even_ts_part_ptr);
    write_le40(N_last, odd_ts_part_ptr);
  } else {
    // Current window uses even from N_last; next will be even at N_next.
    write_le40(N_last, even_ts_part_ptr);
    write_le40(N_next, odd_ts_part_ptr);
  }
  return 0;
}

// Store new csalt and clear derived key cache on change.
void communication_keys_set_csalt(CommunicationKeys *comm_keys_ptr,
                                  const uint8_t new_csalt[4]) {
  if (!comm_keys_ptr || !new_csalt)
    return;
  if (memcmp(comm_keys_ptr->csalt, new_csalt, 4) != 0) {
    memset(comm_keys_ptr->even_key_ts_part, 0,
          sizeof(comm_keys_ptr->even_key_ts_part));
    memset(comm_keys_ptr->odd_key_ts_part, 0,
          sizeof(comm_keys_ptr->odd_key_ts_part));
  }
  memcpy(comm_keys_ptr->csalt, new_csalt, 4);
}

// HKDF a communication key from the seed key, transition timestamp, and csalt.
static int derive_key_with_ts_part(uint8_t out_key_ptr[KEY_LEN],
                                   const uint8_t timestamp_ptr[8],
                                   const uint8_t csalt_ptr[4],
                                   const uint8_t seed_key_ptr[KEY_LEN]) {
  // Communication key salt: 64-bit timer || csalt (12 bytes = 96 bits)
  uint8_t salt[12];
  memcpy(salt, timestamp_ptr, 8);
  memcpy(salt + 8, csalt_ptr, 4);

  int ret = crypto_hkdf_sha256(seed_key_ptr, KEY_LEN, salt, sizeof(salt), NULL, 0,
                               out_key_ptr, KEY_LEN);
  // Clear salt from stack
  memset(salt, 0, sizeof(salt));
  return ret == 0 ? 0 : -10;
}

// Re-derive even/odd comm keys if their time-slot fragment changed, and
// update the odd/even selector.
signed char communication_keys_update(CommunicationKeys *comm_keys_ptr,
                                      uint8_t *timestamp_ptr) {
  if (!comm_keys_ptr || !timestamp_ptr)
    return -1;
  if (!comm_keys_ptr->spsec_keys[3])
    return -2;

  // Check if csalt is available (non-zero)
  bool csalt_available = false;
  for (int i = 0; i < 4; i++) {
    if (comm_keys_ptr->csalt[i] != 0) {
      csalt_available = true;
      break;
    }
  }
  if (!csalt_available) {
    LOG_ERROR(logger_name_ptr,
              "csalt not available for communication key derivation");
    return -6;
  }

  uint8_t even_ts_part[5], odd_ts_part[5];
  bool use_odd_now = false;

  unsigned char rc = get_required_ts_parts(timestamp_ptr, even_ts_part,
                                           odd_ts_part, &use_odd_now);
  if (rc != 0)
    return -3;

  if (!comm_keys_ptr->spsec_keys[3]) {
    LOG_ERROR(logger_name_ptr,
              "Seed key not initialized for communication key update");
    return -1;
  }
  const uint8_t *seed_key_ptr = comm_keys_ptr->spsec_keys[3]->key; // KEY_LEN bytes
  const uint8_t *csalt_ptr = comm_keys_ptr->csalt;                 // 4 bytes

  // Derive even key only if ts_part changed
  // Compute the full 64-bit transition timestamp from current timestamp
  if (memcmp(comm_keys_ptr->even_key_ts_part, even_ts_part, 5) != 0) {
    uint64_t T = read_le64(timestamp_ptr);
    uint64_t N_last, N_next;
    int64_t m_last, m_next;
    int rc_trans =
        compute_transition_pair(T, &N_last, &m_last, &N_next, &m_next);
    if (rc_trans != 0)
      return -3;

    // Determine transition timestamp for even communication key.
    bool last_is_odd = (m_last & 1) != 0;
    uint64_t even_transition_ts = last_is_odd ? N_next : N_last;

    // Convert to little-endian 8-byte array
    uint8_t even_timestamp[8];
    for (int i = 0; i < 8; i++) {
      even_timestamp[i] = (uint8_t)((even_transition_ts >> (i * 8)) & 0xFF);
    }

    int ret_even = derive_key_with_ts_part(comm_keys_ptr->even_key, even_timestamp,
                                           csalt_ptr, seed_key_ptr);
    if (ret_even != 0)
      return -4;
    memcpy(comm_keys_ptr->even_key_ts_part, even_ts_part, 5);
  }

  // Derive odd key only if ts_part changed
  if (memcmp(comm_keys_ptr->odd_key_ts_part, odd_ts_part, 5) != 0) {
    uint64_t T = read_le64(timestamp_ptr);
    uint64_t N_last, N_next;
    int64_t m_last, m_next;
    int rc_trans =
        compute_transition_pair(T, &N_last, &m_last, &N_next, &m_next);
    if (rc_trans != 0)
      return -3;

    // Determine transition timestamp for odd communication key.
    bool last_is_odd = (m_last & 1) != 0;
    uint64_t odd_transition_ts = last_is_odd ? N_last : N_next;

    // Convert to little-endian 8-byte array
    uint8_t odd_timestamp[8];
    for (int i = 0; i < 8; i++) {
      odd_timestamp[i] = (uint8_t)((odd_transition_ts >> (i * 8)) & 0xFF);
    }

    int ret_odd = derive_key_with_ts_part(comm_keys_ptr->odd_key, odd_timestamp,
                                          csalt_ptr, seed_key_ptr);
    if (ret_odd != 0)
      return -5;
    memcpy(comm_keys_ptr->odd_key_ts_part, odd_ts_part, 5);
  }

  // Selector: bit 24 of the current timestamp
  comm_keys_ptr->use_odd_key = use_odd_now;

  return 0;
}