<?php
/**
 * IP utility functions
 * Handles IP detection, normalization, and validation
 */

if (!defined('ABSPATH')) exit;

/**
 * Normalize IP address (handles IPv6 canonicalization)
 */
function pcr_ac_normalize_ip($ip) {
    $ip = trim($ip);
    // Strip brackets that some proxies add around IPv6 addresses.
    if (strlen($ip) > 2 && $ip[0] === '[' && substr($ip, -1) === ']') {
        $ip = substr($ip, 1, -1);
    }
    // Normalise IPv6 to its compact canonical form so that
    // 2001:0db8::1 and 2001:db8:0:0:0:0:0:1 hash identically.
    $packed = @inet_pton($ip);
    if ($packed !== false) {
        $ip = inet_ntop($packed);
    }
    return $ip;
}

/**
 * Check if IP is public (not private or reserved)
 */
function pcr_ac_is_public_ip($ip) {
    return filter_var(
        $ip,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    ) !== false;
}

/**
 * Get real IP address from headers (Cloudflare, proxy, etc.)
 */
function pcr_ac_get_real_ip() {
    // Always trust Cloudflare's connecting IP when present to avoid spoofed XFF entries.
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $cf_ip = pcr_ac_normalize_ip($_SERVER['HTTP_CF_CONNECTING_IP']);
        if (pcr_ac_is_public_ip($cf_ip)) {
            return $cf_ip;
        }
    }

    if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
        $real_ip = pcr_ac_normalize_ip($_SERVER['HTTP_X_REAL_IP']);
        if (pcr_ac_is_public_ip($real_ip)) {
            return $real_ip;
        }
    }

    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ips = array_map('pcr_ac_normalize_ip', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']));

        // Walk from the rightmost hop to the left, returning the closest public address.
        for ($i = count($ips) - 1; $i >= 0; $i--) {
            if (pcr_ac_is_public_ip($ips[$i])) {
                return $ips[$i];
            }
        }
    }

    $remote = isset($_SERVER['REMOTE_ADDR']) ? pcr_ac_normalize_ip($_SERVER['REMOTE_ADDR']) : '';
    if (pcr_ac_is_public_ip($remote)) {
        return $remote;
    }

    return filter_var($remote, FILTER_VALIDATE_IP) ? $remote : '';
}

/**
 * Get hostname from IP address (with transient caching)
 */
function pcr_ac_get_ip_hostname($ip) {
    // Check transient cache first (24-hour cache)
    $cache_key = 'pcr_hostname_' . md5($ip);
    $cached_hostname = get_transient($cache_key);
    
    if ($cached_hostname !== false) {
        return $cached_hostname === 'none' ? null : $cached_hostname;
    }
    
    // Perform reverse DNS lookup with short timeout
    $hostname = @gethostbyaddr($ip);
    
    // If gethostbyaddr fails, it returns the IP itself
    if ($hostname === $ip || $hostname === false) {
        // Cache negative result for 24 hours
        set_transient($cache_key, 'none', 24 * HOUR_IN_SECONDS);
        return null;
    }
    
    // Cache successful result for 24 hours
    set_transient($cache_key, $hostname, 24 * HOUR_IN_SECONDS);
    
    return $hostname;
}
