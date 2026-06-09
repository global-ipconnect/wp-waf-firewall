<?php
/**
 * Encryption and salt management functions
 */

if (!defined('ABSPATH')) exit;

/**
 * Encrypt data using AES-256-CBC
 */
function pcr_ac_encrypt($data, $salt) {
    $key = hash('sha256', $salt, true);
    $iv = openssl_random_pseudo_bytes(16);
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $encrypted);
}

/**
 * Decrypt data using AES-256-CBC
 */
function pcr_ac_decrypt($data, $salt) {
    $key = hash('sha256', $salt, true);
    $data = base64_decode($data);
    if (!$data || strlen($data) < 17) return null;
    $iv = substr($data, 0, 16);
    $encrypted = substr($data, 16);
    return openssl_decrypt($encrypted, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
}

/**
 * Get API option payload (cipher and salt)
 */
function pcr_ac_get_api_option_payload() {
    $value = get_option(PCR_OPTION_KEY);

    if (is_string($value)) {
        $decoded = json_decode($value, true);
        if (is_array($decoded) && (isset($decoded['cipher']) || isset($decoded['salt']))) {
            $value = $decoded;
        }
    }

    if (is_array($value)) {
        $cipher = isset($value['cipher']) ? $value['cipher'] : null;
        $salt = isset($value['salt']) ? $value['salt'] : null;
        return array('cipher' => $cipher, 'salt' => $salt);
    }

    return array('cipher' => $value, 'salt' => null);
}

/**
 * Store salt in file and option
 */
function pcr_ac_store_salt($salt) {
    // Persist salt in both the file and as an option so we can recover if the file is deleted.
    update_option(PCR_SALT_OPTION, $salt);

    $target_dir = dirname(PCR_SALT_FILE);
    if (!wp_mkdir_p($target_dir)) {
        return;
    }

    // Escape the salt value to prevent code injection
    $safe_salt = addslashes($salt);
    $bytes_written = @file_put_contents(PCR_SALT_FILE, '<?php return "' . $safe_salt . '";');
    if ($bytes_written === false) {
        // Silent failure - salt is already saved as option
    }
}

/**
 * Get salt from file or option (with fallback creation)
 */
function pcr_ac_get_salt($fallback = null) {
    if (file_exists(PCR_SALT_FILE)) {
        $salt = include PCR_SALT_FILE;
        if ($salt && !get_option(PCR_SALT_OPTION)) {
            update_option(PCR_SALT_OPTION, $salt);
        }
        return $salt;
    }

    // Legacy location (inside plugin directory) kept for backward compatibility.
    if (file_exists(PCR_SALT_FILE_LEGACY)) {
        $salt = include PCR_SALT_FILE_LEGACY;
        if ($salt) {
            if (!get_option(PCR_SALT_OPTION)) {
                update_option(PCR_SALT_OPTION, $salt);
            }
            // Copy forward into the new persistent location.
            pcr_ac_store_salt($salt);
            return $salt;
        }
    }

    $salt = get_option(PCR_SALT_OPTION);
    if ($salt) {
        // Recreate missing salt file from stored option for resilience.
        pcr_ac_store_salt($salt);
        return $salt;
    }

    if ($fallback) {
        pcr_ac_store_salt($fallback);
        return $fallback;
    }

    return null;
}
