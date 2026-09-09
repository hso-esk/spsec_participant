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
    key_index = 1;
    break;
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

  // Check if key is already set (write-once protection for Provisioning and
  // Integrator keys)
  if (register_is_key_set(participant_ptr, key_index)) {
    LOG_ERROR(logger_name_ptr, "Key register 0x%02x is write-once and already set",
              reg);
    return SPSEC_ERROR_KEY_ALREADY_SET;
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
    // Key pre-shared salts (30h-3Fh) are also never readable (SPsec302
    // §2.3.2: same access type as their key, write-then-immutable). Used to
    // fall through to SPSEC_SUCCESS, letting a Zero Key session read them.
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
    // Zero Key session is unauthenticated (anyone can open one), so
    // SPsec201 §2.4 restricts its reads to discovery/identity registers
    // only - not general register access like higher key selectors get.
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

  // Check write permissions
  switch (reg) {
  // Key registers - write-only, conditional
  case SPSEC_REG_PROVISIONING_KEY:
    if (current_key_selector != KEY_SELECTOR_ZERO) {
      LOG_ERROR(logger_name_ptr, "Provisioning Key can only be written via Zero Key session");
      return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
    }
    return register_validate_key_installation_sequence(participant_ptr, reg);
  case SPSEC_REG_INTEGRATOR_KEY:
    if (current_key_selector != KEY_SELECTOR_PROVISIONING) {
      LOG_ERROR(logger_name_ptr, "Integrator Key requires Provisioning Key session");
      return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
    }
    return register_validate_key_installation_sequence(participant_ptr, reg);
  case SPSEC_REG_SEED_KEY:
    if (current_key_selector != KEY_SELECTOR_PROVISIONING &&
        current_key_selector != KEY_SELECTOR_INTEGRATOR) {
      LOG_ERROR(logger_name_ptr, "Seed Key requires Provisioning or Integrator Key session");
      return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
    }
    return register_validate_key_installation_sequence(participant_ptr, reg);

  // Key salt registers - write-only, conditional
  case SPSEC_REG_PROVISIONING_KEY_SALT:
    if (current_key_selector != KEY_SELECTOR_ZERO) {
      LOG_ERROR(logger_name_ptr, "Provisioning Key Salt can only be written via Zero Key session");
      return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
    }
    return register_validate_key_installation_sequence(participant_ptr, reg - SPSEC_REG_KEY_SALT_TO_KEY_OFFSET);
  case SPSEC_REG_INTEGRATOR_KEY_SALT:
    if (current_key_selector != KEY_SELECTOR_PROVISIONING) {
      LOG_ERROR(logger_name_ptr, "Integrator Key Salt requires Provisioning Key session");
      return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
    }
    return register_validate_key_installation_sequence(participant_ptr, reg - SPSEC_REG_KEY_SALT_TO_KEY_OFFSET);
  case SPSEC_REG_SEED_KEY_SALT:
    if (current_key_selector != KEY_SELECTOR_PROVISIONING &&
        current_key_selector != KEY_SELECTOR_INTEGRATOR) {
      LOG_ERROR(logger_name_ptr, "Seed Key Salt requires Provisioning or Integrator Key session");
      return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
    }
    return register_validate_key_installation_sequence(participant_ptr, reg - SPSEC_REG_KEY_SALT_TO_KEY_OFFSET);

  // Key ID registers - write access follows the same hierarchy as the key itself
  case SPSEC_REG_PROVISIONING_KEY_ID:
    // Write-once: same access rule as the Provisioning Key (Zero Key session only,
    // and only before the key is installed)
    if (current_key_selector != KEY_SELECTOR_ZERO) {
      LOG_ERROR(logger_name_ptr, "Provisioning Key ID can only be written via Zero Key session");
      return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
    }
    // Enforce write-once here too: this used to return success unconditionally,
    // letting any Zero Key session rewrite an already-provisioned device's
    // reported key ID and break configurator inventory/key selection.
    return register_validate_key_installation_sequence(participant_ptr,
                                                       SPSEC_REG_PROVISIONING_KEY);
  case SPSEC_REG_INTEGRATOR_KEY_ID:
    // Writing the Integrator Key ID requires a Provisioning Key session
    if (current_key_selector != KEY_SELECTOR_PROVISIONING) {
      LOG_ERROR(logger_name_ptr, "Integrator Key ID requires Provisioning Key session");
      return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
    }
    return SPSEC_SUCCESS;
  case SPSEC_REG_SEED_KEY_ID:
    // Writing the Seed Key ID requires a Provisioning or Integrator Key session
    if (current_key_selector != KEY_SELECTOR_PROVISIONING &&
        current_key_selector != KEY_SELECTOR_INTEGRATOR) {
      LOG_ERROR(logger_name_ptr, "Seed Key ID requires Provisioning or Integrator Key session");
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

  // Write-only registers
  case SPSEC_REG_CODE_UPDATE_FILE:
  case SPSEC_REG_CAN_FD_BIT_RATE:
    // Accessible from any non-Zero-Key session (Zero Key cannot write config)
    if (current_key_selector == KEY_SELECTOR_ZERO) {
      LOG_ERROR(logger_name_ptr, "Register 0x%02x cannot be written via Zero Key session", reg);
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

  // Read-write configuration registers
  case SPSEC_REG_PARTICIPANT_ID:
  case SPSEC_REG_SECURE_HEARTBEAT_TIMING:
  case SPSEC_REG_SECURE_HEARTBEAT_MONITOR:
  case SPSEC_REG_SYNC_ROLE_ACTIVATION:
    if (current_key_selector == KEY_SELECTOR_ZERO) {
      LOG_ERROR(logger_name_ptr, "Configuration registers cannot be written via Zero Key session");
      return SPSEC_ERROR_REGISTER_ACCESS_DENIED;
    }
    return SPSEC_SUCCESS;

  default:
    // Unknown register
    LOG_ERROR(logger_name_ptr, "Unknown register 0x%02x", reg);
    return SPSEC_ERROR_REGISTER_INVALID;
  }
}
