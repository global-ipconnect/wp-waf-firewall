<?php
/**
 * Database functions
 * Handles table creation and upgrades
 */

if (!defined('ABSPATH')) exit;

/**
 * Create IP cache table
 */
function pcr_ac_create_cache_table() {
    global $wpdb;
    $table_name = $wpdb->prefix . PCR_CACHE_TABLE;
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE IF NOT EXISTS $table_name (
        id bigint(20) NOT NULL AUTO_INCREMENT,
        ip_hash varchar(32) NOT NULL,
        ip_address varchar(45) NOT NULL,
        is_proxy tinyint(1) NOT NULL,
        last_checked datetime NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY ip_hash (ip_hash),
        KEY last_checked (last_checked)
    ) $charset_collate;";

    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);
}

/**
 * Create visitor log table
 */
function pcr_ac_create_visitor_log_table() {
    global $wpdb;
    $table_name = $wpdb->prefix . PCR_VISITOR_LOG_TABLE;
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE IF NOT EXISTS $table_name (
        id bigint(20) NOT NULL AUTO_INCREMENT,
        visit_time datetime NOT NULL,
        url_request varchar(2048) NOT NULL,
        ip_address varchar(45) NOT NULL,
        ip_hostname varchar(255) DEFAULT NULL,
        user_agent_raw text NOT NULL,
        user_agent_parsed varchar(255) DEFAULT NULL,
        http_code smallint(3) NOT NULL,
        username varchar(255) DEFAULT NULL,
        request_method varchar(10) DEFAULT NULL,
        is_suspicious tinyint(1) DEFAULT 0,
        threat_detected tinyint(1) DEFAULT 0,
        threat_type smallint(3) DEFAULT NULL,
        threat_name varchar(100) DEFAULT NULL,
        threat_data text DEFAULT NULL,
        threat_severity varchar(20) DEFAULT NULL,
        referrer text DEFAULT NULL,
        request_data mediumtext DEFAULT NULL,
        request_headers text DEFAULT NULL,
        PRIMARY KEY (id),
        KEY visit_time (visit_time),
        KEY ip_address (ip_address),
        KEY http_code (http_code),
        KEY username (username),
        KEY is_suspicious (is_suspicious),
        KEY threat_detected (threat_detected),
        KEY threat_type (threat_type),
        KEY request_method (request_method)
    ) $charset_collate;";

    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);
}

/**
 * Ensure tables exist, creating them if missing.
 * Uses an option flag so dbDelta only runs once per install.
 * Hooked to 'init' to handle MU-plugin deployments where
 * register_activation_hook never fires.
 */
function pcr_ac_ensure_tables() {
    if ( get_option( 'pcr_tables_created' ) ) {
        return;
    }
    pcr_ac_create_cache_table();
    pcr_ac_create_visitor_log_table();
    update_option( 'pcr_tables_created', '1', false );
}
add_action( 'init', 'pcr_ac_ensure_tables', 1 );

/**
 * Plugin activation handler
 */
function pcr_access_control_activate() {
    pcr_ac_create_cache_table();
    pcr_ac_create_visitor_log_table();
    update_option( 'pcr_tables_created', '1', false );
    add_option('pcr_activation_redirect', true);
    // Schedule daily cleanup of old visitor log entries
    if ( function_exists('wp_next_scheduled') && !wp_next_scheduled('pcr_ac_daily_cleanup') ) {
        wp_schedule_event( time(), 'daily', 'pcr_ac_daily_cleanup' );
    }
}

/**
 * Plugin uninstall handler
 */
function pcr_ac_plugin_uninstall() {
    global $wpdb;
    
    // Clear scheduled cleanup event
    if ( function_exists('wp_next_scheduled') ) {
        $ts = wp_next_scheduled('pcr_ac_daily_cleanup');
        if ($ts) wp_unschedule_event($ts, 'pcr_ac_daily_cleanup');
    }

    // Drop tables
    $cache_table = $wpdb->prefix . PCR_CACHE_TABLE;
    $log_table = $wpdb->prefix . PCR_VISITOR_LOG_TABLE;
    $wpdb->query("DROP TABLE IF EXISTS $cache_table");
    $wpdb->query("DROP TABLE IF EXISTS $log_table");
    
    // Delete options
    delete_option(PCR_OPTION_KEY);
    delete_option(PCR_SETUP_DONE);
    delete_option(PCR_SALT_OPTION);
    delete_option(PCR_SALT_ALERT_OPTION);
    delete_option('pcr_activation_redirect');
    delete_option('pcr_tables_created');
    
    // Clean up transients
    delete_transient('pcr_api_check');
    
    // Remove salt files
    if (file_exists(PCR_SALT_FILE)) {
        @unlink(PCR_SALT_FILE);
    }
    if (file_exists(PCR_SALT_FILE_LEGACY)) {
        @unlink(PCR_SALT_FILE_LEGACY);
    }
}

/**
 * Cleanup old visitor log entries based on retention setting
 */
function pcr_ac_cleanup_old_logs() {
    global $wpdb;

    // Get retention days from settings
    $settings = get_option('pcr_threat_settings', []);
    $days = isset($settings['visitor_log_retention_days']) ? absint($settings['visitor_log_retention_days']) : 30;

    if ($days <= 0) {
        // 0 means disabled
        return;
    }

    $cutoff = gmdate('Y-m-d H:i:s', strtotime("-{$days} days"));
    $table = $wpdb->prefix . PCR_VISITOR_LOG_TABLE;

    // Use prepare for the date parameter; table name is inserted directly
    $wpdb->query( $wpdb->prepare("DELETE FROM {$table} WHERE visit_time < %s", $cutoff) );
}

// Hook cleanup to scheduled action
add_action('pcr_ac_daily_cleanup', 'pcr_ac_cleanup_old_logs');
