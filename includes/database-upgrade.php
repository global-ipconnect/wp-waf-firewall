<?php
/**
 * Database upgrade handler for threat detection columns
 * Run this to add threat detection columns to existing installations
 */

if (!defined('ABSPATH')) exit;

/**
 * Upgrade visitor log table to support threat detection
 * Call this during plugin update/activation
 */
function pcr_ac_upgrade_visitor_log_table() {
    global $wpdb;
    $table_name = $wpdb->prefix . PCR_VISITOR_LOG_TABLE;
    
    // Check if threat_detected column exists
    $column_check = $wpdb->get_results("SHOW COLUMNS FROM `{$table_name}` LIKE 'threat_detected'");
    
    if (empty($column_check)) {
        // Add threat detection columns
        $wpdb->query("ALTER TABLE `{$table_name}` 
            ADD COLUMN `threat_detected` tinyint(1) DEFAULT 0 AFTER `is_suspicious`,
            ADD COLUMN `threat_type` smallint(3) DEFAULT NULL AFTER `threat_detected`,
            ADD COLUMN `threat_name` varchar(100) DEFAULT NULL AFTER `threat_type`,
            ADD COLUMN `threat_data` text DEFAULT NULL AFTER `threat_name`,
            ADD COLUMN `threat_severity` varchar(20) DEFAULT NULL AFTER `threat_data`,
            ADD INDEX `threat_detected` (`threat_detected`),
            ADD INDEX `threat_type` (`threat_type`)
        ");
        
        return true;
    }
    
    return false; // Already upgraded
}

// Run upgrade on plugin activation
add_action('admin_init', function() {
    $version_key = 'pcr_db_version';
    $current_version = get_option($version_key, '1.0');
    $new_version = '1.6'; // Threat detection update
    
    if (version_compare($current_version, $new_version, '<')) {
        // Ensure base tables exist before attempting column upgrades
        // (required for fresh MU-plugin installs where activation hook never ran)
        pcr_ac_create_cache_table();
        pcr_ac_create_visitor_log_table();
        update_option( 'pcr_tables_created', '1', false );
        pcr_ac_upgrade_visitor_log_table();
        update_option($version_key, $new_version);
    }
});
