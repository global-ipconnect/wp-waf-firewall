<?php
/**
 * Cache management functions
 * Handles IP cache and timeout cache operations
 */

if (!defined('ABSPATH')) exit;

/**
 * Get cached IP data from database
 */
function pcr_ac_get_cached_ip($ip_hash) {
    global $wpdb;
    $table_name = $wpdb->prefix . PCR_CACHE_TABLE;
    
    return $wpdb->get_row($wpdb->prepare(
        "SELECT * FROM $table_name WHERE ip_hash = %s", $ip_hash
    ));
}

/**
 * Update IP cache in database
 */
function pcr_ac_update_ip_cache($ip, $ip_hash, $is_proxy) {
    global $wpdb;
    $table_name = $wpdb->prefix . PCR_CACHE_TABLE;
    
    $wpdb->replace($table_name, array(
        'ip_hash' => $ip_hash,
        'ip_address' => $ip,
        'is_proxy' => $is_proxy ? 1 : 0,
        'last_checked' => current_time('mysql', 1)
    ));
}

/**
 * Clean expired cache entries
 */
function pcr_ac_clean_expired_cache() {
    global $wpdb;
    $table_name = $wpdb->prefix . PCR_CACHE_TABLE;
    $expiry_time = gmdate('Y-m-d H:i:s', time() - PCR_CACHE_EXPIRY);
    
    $wpdb->query($wpdb->prepare(
        "DELETE FROM $table_name WHERE last_checked < %s", $expiry_time
    ));
}

/**
 * Flush all IP cache
 */
function pcr_ac_flush_ip_cache() {
    global $wpdb;
    $table_name = $wpdb->prefix . PCR_CACHE_TABLE;
    $count = $wpdb->query("DELETE FROM $table_name WHERE 1=1");
    
    // Also clear transient hostname cache
    global $wpdb;
    $wpdb->query(
        "DELETE FROM {$wpdb->options} 
         WHERE option_name LIKE '_transient_pcr_hostname_%' 
         OR option_name LIKE '_transient_timeout_pcr_hostname_%'"
    );
    
    return $count;
}

/**
 * Generate timeout cache key
 */
function pcr_ac_timeout_cache_key($ip_hash) {
    return 'pcr_timeout_' . $ip_hash;
}

/**
 * Get timeout cached data
 */
function pcr_ac_get_timeout_cached($ip_hash) {
    return get_transient(pcr_ac_timeout_cache_key($ip_hash));
}

/**
 * Set timeout cache (for short-term retry avoidance)
 */
function pcr_ac_set_timeout_cache($ip_hash, $is_proxy, $reason) {
    set_transient(pcr_ac_timeout_cache_key($ip_hash), array(
        'is_proxy' => $is_proxy ? 1 : 0,
        'reason' => $reason,
    ), PCR_TIMEOUT_CACHE_EXPIRY);
}
