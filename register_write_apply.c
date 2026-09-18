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

// Applies validated register writes: keys, salts, key IDs.

#include <string.h>

#include "keys.h"
#include "nvol_storage.h"
#include "participant.h"
#include "participant_storage.h"
#include "register_operations.h"
#include "register_validation.h"
#include "register_write_internal.h"
#include "spsec_common.h"
#include "spsec_registers.h"

static const char *logger_name_ptr = "register_write_apply";

// Store a crypto key into the participant's key inventory.
spsec_ret_t apply_key(Participant *participant_ptr, uint8_t reg_index,
                      uint8_t *data_ptr) {
  // Provisioning key (reg_index 1) cannot be written via protocol (manufacturer only)
  if (reg_index == 1) {
    LOG_ERROR(logger_name_ptr,
              "Provisioning Key cannot be written via protocol. It must be added manually by device manufacturer");
    return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
  }

  bool is_prov_installed = register_is_key_set(participant_ptr, 1);
  // Integrator key (index 2) is write-once only if Provisioning key is NOT installed
  if (reg_index == 2 && !is_prov_installed) {
    if (register_is_key_material_set(participant_ptr, reg_index)) {
      LOG_ERROR(logger_name_ptr, "Integrator Key is write-once when Provisioning Key is not installed");
      return SPSEC_ERROR_KEY_ALREADY_SET;
    }
  }

  if (participant_ptr->comm_keys.spsec_keys[reg_index] == NULL) {
    LOG_INFO(logger_name_ptr, "Key not initialized, initializing now");
    // Create key with key_id = 0 (will be set by apply_key_id if ID-first write)
    participant_ptr->comm_keys.spsec_keys[reg_index] =
        spseckey_new(0, data_ptr);
    if (participant_ptr->comm_keys.spsec_keys[reg_index] == NULL) {
      LOG_ERROR(logger_name_ptr, "Failed to allocate key");
      return SPSEC_ERROR_OUT_OF_MEMORY;
    }
  } else {
    spseckey_set(participant_ptr->comm_keys.spsec_keys[reg_index], data_ptr);
  }

  // Report key ID register change if key was set
  if (reg_index == 2) {
    participant_report_register_change(participant_ptr,
                                       SPSEC_REG_INTEGRATOR_KEY_ID);
  } else if (reg_index == 3) {
    participant_report_register_change(participant_ptr, SPSEC_REG_SEED_KEY_ID);

    // Invalidate derived communication keys so they re-derive from the new seed
    memset(participant_ptr->comm_keys.even_key, 0,
           sizeof(participant_ptr->comm_keys.even_key));
    memset(participant_ptr->comm_keys.odd_key, 0,
           sizeof(participant_ptr->comm_keys.odd_key));
    memset(participant_ptr->comm_keys.even_key_ts_part, 0,
           sizeof(participant_ptr->comm_keys.even_key_ts_part));
    memset(participant_ptr->comm_keys.odd_key_ts_part, 0,
           sizeof(participant_ptr->comm_keys.odd_key_ts_part));
    LOG_INFO(logger_name_ptr,
             "Seed key replaced - communication keys invalidated, will "
             "re-derive from the new seed");
  }

  participant_storage_save_key(participant_ptr, reg_index);
  // Key ID is persisted by apply_key_id (ID-first path) or when key_id is explicitly set
  return SPSEC_SUCCESS;
}

// Store a salt value in the participant's key store.
spsec_ret_t apply_salt(Participant *participant_ptr, uint8_t salt_index,
                       uint8_t *data_ptr) {
  if (salt_index == 1) {
    LOG_ERROR(logger_name_ptr,
              "Provisioning Key Salt cannot be written via protocol. It must be added manually by device manufacturer");
    return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
  }
  if (participant_ptr->comm_keys.spsec_salt[salt_index] == NULL) {
    LOG_INFO(logger_name_ptr, "Salt not initialized, initializing now");
    participant_ptr->comm_keys.spsec_salt[salt_index] =
        spsecsalt_new(data_ptr);
    if (participant_ptr->comm_keys.spsec_salt[salt_index] == NULL) {
      LOG_ERROR(logger_name_ptr, "Failed to create new salt");
      return SPSEC_ERROR_OUT_OF_MEMORY;
    }
  } else {
    if (spsecsalt_set(participant_ptr->comm_keys.spsec_salt[salt_index],
                      data_ptr) < 0) {
      LOG_ERROR(logger_name_ptr, "Failed to set salt");
      return SPSEC_ERROR_INVALID_ARGUMENT;
    }
  }

  participant_storage_save_salt(participant_ptr, salt_index);
  return SPSEC_SUCCESS;
}

// Update the key identifier associated with a stored key.
spsec_ret_t apply_key_id(Participant *participant_ptr, uint8_t reg_index,
                         uint8_t *data_ptr, uint32_t data_len) {
  if (data_len != sizeof(uint32_t)) {
    LOG_ERROR(logger_name_ptr, "Invalid data_ptr length for key ID: %u", data_len);
    return SPSEC_ERROR_INVALID_ARGUMENT;
  }

  uint32_t key_id = (uint32_t)data_ptr[0] | ((uint32_t)data_ptr[1] << 8) |
                    ((uint32_t)data_ptr[2] << 16) |
                    ((uint32_t)data_ptr[3] << 24);

  if (key_id == SPSEC_KEY_ID_INVALID) {
    LOG_ERROR(logger_name_ptr, "Invalid key ID value: 0x%08X (invalid)", key_id);
    return SPSEC_ERROR_KEY_INVALID_ID;
  }

  // Provisioning key ID (reg_index 1) cannot be written via protocol (manufacturer only)
  if (reg_index == 1) {
    LOG_ERROR(logger_name_ptr,
              "Provisioning Key ID cannot be written via protocol; must be added manually by device manufacturer");
    return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
  }

  bool is_prov_installed = register_is_key_set(participant_ptr, 1);
  if (reg_index == 2 && !is_prov_installed) {
    if (register_is_key_set(participant_ptr, reg_index)) {
      LOG_ERROR(logger_name_ptr, "Integrator Key ID is write-once when Provisioning Key is not installed");
      return SPSEC_ERROR_KEY_ALREADY_SET;
    }
  }

  if (participant_ptr->comm_keys.spsec_keys[reg_index] == NULL) {
    LOG_INFO(logger_name_ptr, "Key not initialized, initializing now");
    uint8_t zero_key[KEY_LEN] = {0};
    participant_ptr->comm_keys.spsec_keys[reg_index] =
        spseckey_new(key_id, zero_key);
  } else {
    if (reg_index == 2 && !is_prov_installed && register_is_key_set(participant_ptr, reg_index)) {
      LOG_ERROR(logger_name_ptr, "Cannot overwrite write-once key ID at index 2");
      return SPSEC_ERROR_KEY_ALREADY_SET;
    }
    spseckey_set_id(participant_ptr->comm_keys.spsec_keys[reg_index], key_id);
  }

  uint8_t key_id_reg = (reg_index == 1)   ? SPSEC_REG_PROVISIONING_KEY_ID
                       : (reg_index == 2) ? SPSEC_REG_INTEGRATOR_KEY_ID
                                          : SPSEC_REG_SEED_KEY_ID;
  participant_report_register_change(participant_ptr, key_id_reg);
  participant_storage_save_key_id(participant_ptr, reg_index);

  return SPSEC_SUCCESS;
}
