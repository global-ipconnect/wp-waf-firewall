<?php
/**
 * Data sanitization functions
 * Handles sensitive data redaction for GDPR compliance
 */

if (!defined('ABSPATH')) exit;

/**
 * Sanitize sensitive personal data from request parameters
 * Redacts PII, payment info, passwords, addresses, etc.
 */
function pcr_ac_sanitize_sensitive_data($data) {
    if (!is_array($data)) {
        return $data;
    }
    
    $sanitized = array();
    
    // List of sensitive field patterns to redact
    $sensitive_patterns = array(
        '/email/i',           // Email addresses
        '/^(billing_|shipping_|s_)?first_?name$/i', // First names
        '/^(billing_|shipping_|s_)?last_?name$/i',  // Last names
        '/^(billing_|shipping_|s_)?name$/i',        // Generic name fields
        '/^(billing_|shipping_|s_)?company$/i',     // Company names
        '/^(billing_|shipping_|s_)?address/i',      // All address fields
        '/^(billing_|shipping_|s_)?city$/i',        // Cities
        '/^(billing_|shipping_|s_)?state$/i',       // States/regions
        '/^(billing_|shipping_|s_)?postcode$/i',    // Postcodes
        '/^(billing_|shipping_|s_)?zip$/i',         // ZIP codes
        '/^(billing_|shipping_|s_)?phone/i',        // Phone numbers
        '/pwd|password|pass/i',                     // Passwords
        '/card|cvv|ccv|cc_/i',                      // Credit card data
        '/^stripe_/i',                              // Stripe tokens/methods
        '/payment[_-]?method[_-]?(token|id)/i',     // Payment method tokens
    );
    
    // Fields to completely remove (often contain embedded sensitive data)
    $remove_patterns = array(
        '/^post_data$/i',     // WooCommerce checkout data (contains everything)
        '/^checkout_data$/i', // Checkout form data
    );
    
    foreach ($data as $key => $value) {
        $should_redact = false;
        $should_remove = false;
        
        // Check if field should be completely removed
        foreach ($remove_patterns as $pattern) {
            if (preg_match($pattern, $key)) {
                $should_remove = true;
                break;
            }
        }
        
        if ($should_remove) {
            $sanitized[$key] = '[REMOVED - Contains sensitive data]';
            continue;
        }
        
        // Check if field should be redacted
        foreach ($sensitive_patterns as $pattern) {
            if (preg_match($pattern, $key)) {
                $should_redact = true;
                break;
            }
        }
        
        if ($should_redact) {
            $sanitized[$key] = '[REDACTED]';
        } elseif (is_array($value)) {
            // Recursively sanitize nested arrays
            $sanitized[$key] = pcr_ac_sanitize_sensitive_data($value);
        } else {
            $sanitized[$key] = $value;
        }
    }
    
    return $sanitized;
}

/**
 * Get user display name (first + last name, or email, or username)
 */
function pcr_ac_get_user_display_name($user) {
    if (!$user || !is_object($user)) {
        return null;
    }
    
    $first_name = get_user_meta($user->ID, 'first_name', true);
    $last_name = get_user_meta($user->ID, 'last_name', true);
    
    // If both first and last name exist, combine them
    if (!empty($first_name) && !empty($last_name)) {
        return trim($first_name . ' ' . $last_name);
    }
    
    // If only first name exists
    if (!empty($first_name)) {
        return $first_name;
    }
    
    // If only last name exists
    if (!empty($last_name)) {
        return $last_name;
    }
    
    // Fall back to email address
    if (!empty($user->user_email)) {
        return $user->user_email;
    }
    
    // Last resort: username
    return $user->user_login;
}
