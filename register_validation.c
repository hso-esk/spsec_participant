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

// Register access validation: permission checks and key-installation
// sequence rules.

#include "register_validation.h"
#include "spsec_common.h"
#include "spsec_registers.h"

static const char *logger_name_ptr = "register_validation";

// A key-salt register (0x31-0x33) minus this offset yields its key register
// (0x21-0x23); the salt shares the key's installation-sequence rules.
#define SPSEC_REG_KEY_SALT_TO_KEY_OFFSET 0x10

// True if spsec_keys[key_index] holds a non-reserved key ID.
bool register_is_key_set(Participant *participant_ptr, uint8_t key_index) {
  if (!participant_ptr->comm_keys.spsec_keys[key_index])
    return false;

  // Check if key ID is valid (not 0x00000000 or 0xFFFFFFFF)
  uint32_t key_id = participant_ptr->comm_keys.spsec_keys[key_index]->key_id;
  return (key_id != SPSEC_KEY_ID_INVALID &&
          key_id != (uint32_t)SPSEC_KEY_ID_RESERVED);
}

// True if spsec_keys[key_index] holds non-zero key bytes.
bool register_is_key_material_set(Participant *participant_ptr, uint8_t key_index) {
  if (!participant_ptr->comm_keys.spsec_keys[key_index])
    return false;

  SPsecKey *k_ptr = participant_ptr->comm_keys.spsec_keys[key_index];
  static const uint8_t zero_buf[KEY_LEN] = {0};
  return (memcmp(k_ptr->key, zero_buf, KEY_LEN) != 0);
}

// Enforce write-once protection and warn if a key ID wasn't erased before
// installing a new provisioned key.
signed char
register_validate_key_installation_sequence(Participant *participant_ptr,
                                            uint8_t reg) {
  uint8_t key_index = 0;

  // Map register to key index and key ID register
  switch (reg) {
  case SPSEC_REG_PROVISIONING_KEY:
    LOG_ERROR(logger_name_ptr,
              "Provisioning Key cannot be written via protocol. It must be added manually by device manufacturer");
    return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
  case SPSEC_REG_INTEGRATOR_KEY:
    key_index = 2;
    break;
  case SPSEC_REG_SEED_KEY:
    key_index = 3;
    // Seed key can be overwritten, so sequence validation is less strict
    return SPSEC_SUCCESS;
  default:
    // Not a key register
    return SPSEC_SUCCESS;
  }

  // Integrator Key: 1-time write without Provisioning Key, mutable with it.
  bool is_prov_installed = register_is_key_set(participant_ptr, 1);
  if (!is_prov_installed) {
    if (register_is_key_set(participant_ptr, 2)) {
      LOG_ERROR(logger_name_ptr,
                "Integrator Key is write-once when Provisioning Key is not installed");
      return SPSEC_ERROR_KEY_ALREADY_SET;
    }
  }

  // Check if Key ID was properly erased (set to FFFFFFFFh) before writing key
  if (participant_ptr->comm_keys.spsec_keys[key_index] &&
      participant_ptr->comm_keys.spsec_keys[key_index]->key_id !=
          (uint32_t)SPSEC_KEY_ID_RESERVED) {
    LOG_WARNING(logger_name_ptr,
                "Key ID for register 0x%02x should be erased (0xFFFFFFFF) "
                "before writing key",
                reg);
    // This is a warning, not an error, to allow flexibility
  }

  return SPSEC_SUCCESS;
}

// Check whether reg is readable/writable in the current session.
signed char register_check_access(Participant *participant_ptr, uint8_t reg,
                                  bool is_write) {
  uint8_t current_key_selector = KEY_SELECTOR_ZERO;
  if (participant_ptr->session.auth_tag_data_ptr) {
    current_key_selector = participant_ptr->session.auth_tag_data_ptr->key_selector[0];
  }

  // Check read-only and write-only registers
  if (!is_write) {
    // Key registers (20h-2Fh) can never be read
    if (reg >= 0x20 && reg <= 0x2F) {
      LOG_ERROR(logger_name_ptr, "Register 0x%02x is write-only and cannot be read",
                reg);
      return SPSEC_ERROR_REGISTER_WRITE_ONLY;
    }
    // Pre-shared salts (30h-3Fh) are write-only and never readable.
    if (reg >= 0x30 && reg <= 0x3F) {
      LOG_ERROR(logger_name_ptr, "Register 0x%02x is write-only and cannot be read",
                reg);
      return SPSEC_ERROR_REGISTER_WRITE_ONLY;
    }
    // Write-only configuration registers
    if (reg == SPSEC_REG_CAN_FD_BIT_RATE ||
        reg == SPSEC_REG_MANUFACTURER_RESET ||
        reg == SPSEC_REG_CODE_UPDATE_FILE) {
      LOG_ERROR(logger_name_ptr, "Register 0x%02x is write-only and cannot be read",
                reg);
      return SPSEC_ERROR_REGISTER_WRITE_ONLY;
    }
    // Zero Key sessions are unauthenticated; restrict reads to discovery.
    if (current_key_selector == KEY_SELECTOR_ZERO) {
      switch (reg) {
      case SPSEC_REG_STATUS:               // 50h - liveness / security state
      case SPSEC_REG_LAST_SECURITY_EVENT:  // 51h
      case SPSEC_REG_CORE_VERSION_INFO:    // 58h - firmware identity
      case SPSEC_REG_MAPPING_VERSION_INFO: // 59h
      case SPSEC_REG_DEVICE_IDENTIFICATION: // 81h - hardware identity
      case SPSEC_REG_MCU_SERIAL_NUMBER:     // 82h
      case SPSEC_REG_PROVISIONING_KEY_ID:   // 41h - which keys are installed
      case SPSEC_REG_INTEGRATOR_KEY_ID:     // 42h
      case SPSEC_REG_SEED_KEY_ID:           // 43h
        break;
      default:
        LOG_ERROR(logger_name_ptr,
                  "Register 0x%02x is not readable in a Zero Key session",
                  reg);
        return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
      }
    }
    return SPSEC_SUCCESS;
  }

  bool is_prov_installed = register_is_key_set(participant_ptr, 1);

  // Rule 3: If provisioning key is installed, Zero Key session cannot write anything, only read.
  if (current_key_selector == KEY_SELECTOR_ZERO && is_prov_installed) {
    LOG_ERROR(logger_name_ptr,
              "Zero Key session is read-only when Provisioning Key is installed");
    return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
  }

  // Check write permissions
  switch (reg) {
  // Key registers - write-only, conditional
  case SPSEC_REG_PROVISIONING_KEY:
    LOG_ERROR(logger_name_ptr,
              "Provisioning Key cannot be written via session. It must be added manually by device manufacturer");
    return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
  case SPSEC_REG_INTEGRATOR_KEY:
    if (is_prov_installed) {
      // Rule 4: If provisioning key installed - integrator key can be changed only via provisioning key session and integrator key session.
      if (current_key_selector != KEY_SELECTOR_PROVISIONING &&
          current_key_selector != KEY_SELECTOR_INTEGRATOR) {
        LOG_ERROR(logger_name_ptr,
                  "Integrator Key requires Provisioning or Integrator Key session when Provisioning Key is installed");
        return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
      }
    } else {
      // Rule 1 & 5: If provisioning key is not installed, zero key should allow to write integrator key but only one time.
      if (current_key_selector != KEY_SELECTOR_ZERO) {
        LOG_ERROR(logger_name_ptr,
                  "Integrator Key can only be written via Zero Key session when Provisioning Key is not installed");
        return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
      }
    }
    return register_validate_key_installation_sequence(participant_ptr, reg);
  case SPSEC_REG_SEED_KEY:
    // Rule 2: Seed Key write allowed only by Integrator key session use.
    if (current_key_selector != KEY_SELECTOR_INTEGRATOR) {
      LOG_ERROR(logger_name_ptr, "Seed Key requires Integrator Key session");
      return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
    }
    return register_validate_key_installation_sequence(participant_ptr, reg);

  // Key salt registers - write-only, conditional
  case SPSEC_REG_PROVISIONING_KEY_SALT:
    LOG_ERROR(logger_name_ptr,
              "Provisioning Key Salt cannot be written via session. It must be added manually by device manufacturer");
    return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
  case SPSEC_REG_INTEGRATOR_KEY_SALT:
    if (is_prov_installed) {
      if (current_key_selector != KEY_SELECTOR_PROVISIONING &&
          current_key_selector != KEY_SELECTOR_INTEGRATOR) {
        LOG_ERROR(logger_name_ptr,
                  "Integrator Key Salt requires Provisioning or Integrator Key session when Provisioning Key is installed");
        return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
      }
    } else {
      if (current_key_selector != KEY_SELECTOR_ZERO) {
        LOG_ERROR(logger_name_ptr,
                  "Integrator Key Salt can only be written via Zero Key session when Provisioning Key is not installed");
        return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
      }
    }
    return register_validate_key_installation_sequence(participant_ptr, reg - SPSEC_REG_KEY_SALT_TO_KEY_OFFSET);
  case SPSEC_REG_SEED_KEY_SALT:
    // Rule 2: Seed Key Salt requires Integrator Key session
    if (current_key_selector != KEY_SELECTOR_INTEGRATOR) {
      LOG_ERROR(logger_name_ptr, "Seed Key Salt requires Integrator Key session");
      return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
    }
    return register_validate_key_installation_sequence(participant_ptr, reg - SPSEC_REG_KEY_SALT_TO_KEY_OFFSET);

  // Key ID registers - write access follows the same hierarchy as the key itself
  case SPSEC_REG_PROVISIONING_KEY_ID:
    LOG_ERROR(logger_name_ptr,
              "Provisioning Key ID cannot be written via session; must be added manually by device manufacturer");
    return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
  case SPSEC_REG_INTEGRATOR_KEY_ID:
    if (is_prov_installed) {
      if (current_key_selector != KEY_SELECTOR_PROVISIONING &&
          current_key_selector != KEY_SELECTOR_INTEGRATOR) {
        LOG_ERROR(logger_name_ptr,
                  "Integrator Key ID requires Provisioning or Integrator Key session when Provisioning Key is installed");
        return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
      }
    } else {
      if (current_key_selector != KEY_SELECTOR_ZERO) {
        LOG_ERROR(logger_name_ptr,
                  "Integrator Key ID can only be written via Zero Key session when Provisioning Key is not installed");
        return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
      }
    }
    return register_validate_key_installation_sequence(participant_ptr,
                                                       SPSEC_REG_INTEGRATOR_KEY);
  case SPSEC_REG_SEED_KEY_ID:
    // Rule 2: Seed Key ID requires Integrator Key session
    if (current_key_selector != KEY_SELECTOR_INTEGRATOR) {
      LOG_ERROR(logger_name_ptr, "Seed Key ID requires Integrator Key session");
      return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
    }
    return SPSEC_SUCCESS;

  // Read-only registers
  case SPSEC_REG_STATUS:
  case SPSEC_REG_LAST_SECURITY_EVENT:
  case SPSEC_REG_CORE_VERSION_INFO:
  case SPSEC_REG_MAPPING_VERSION_INFO:
  case SPSEC_REG_DEVICE_IDENTIFICATION:
  case SPSEC_REG_MCU_SERIAL_NUMBER:
  case SPSEC_REG_CODE_UPDATE_CAPABILITIES:
  case SPSEC_REG_PUBLIC_AUTH_KEY:
    LOG_ERROR(logger_name_ptr, "Register 0x%02x is read-only", reg);
    return SPSEC_ERROR_REGISTER_READ_ONLY;

  // Write-only registers (Rule 2: allowed only by Integrator key session use)
  case SPSEC_REG_CODE_UPDATE_FILE:
  case SPSEC_REG_CAN_FD_BIT_RATE:
    if (current_key_selector != KEY_SELECTOR_INTEGRATOR) {
      LOG_ERROR(logger_name_ptr, "Register 0x%02x requires Integrator Key session", reg);
      return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
    }
    return SPSEC_SUCCESS;
  case SPSEC_REG_MANUFACTURER_RESET:
    // Spec: Manufacturer Reset to Default (7Fh) requires an Integrator Key session
    if (current_key_selector != KEY_SELECTOR_INTEGRATOR) {
      LOG_ERROR(logger_name_ptr,
                "Manufacturer Reset requires Integrator Key session (current: %u)",
                current_key_selector);
      return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
    }
    return SPSEC_SUCCESS;

  // Read-write configuration registers (Rule 2: allowed only by Integrator key session use)
  case SPSEC_REG_PARTICIPANT_ID:
  case SPSEC_REG_SECURE_HEARTBEAT_TIMING:
  case SPSEC_REG_SECURE_HEARTBEAT_MONITOR:
  case SPSEC_REG_SYNC_ROLE_ACTIVATION:
    if (current_key_selector != KEY_SELECTOR_INTEGRATOR) {
      LOG_ERROR(logger_name_ptr, "Configuration register 0x%02x requires Integrator Key session", reg);
      return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
    }
    return SPSEC_SUCCESS;

  default:
    // Unknown register
    LOG_ERROR(logger_name_ptr, "Unknown register 0x%02x", reg);
    return SPSEC_ERROR_REGISTER_INVALID;
  }
}
