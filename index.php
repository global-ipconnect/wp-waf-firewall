<?php
/*
Plugin Name: Global IPconnect Access Control
Plugin URI: https://global-ipconnect.com/
Description: Redirects anonymised visitors to a block page using proxycheck.io. Includes comprehensive visitor logging with suspicious request detection and advanced filtering. NOW WITH ADVANCED THREAT DETECTION SYSTEM inspired by WP Cerber.
Version: 2.0.1
Author: Global-IPconnect
Author URI: https://global-ipconnect.com/
Text Domain: global-ipconnect-access-control
Domain Path: /languages
Update URI: false
*/

if (!defined('ABSPATH')) exit;

if (defined('PCR_ACCESS_CONTROL_LOADED')) {
    return;
}
define('PCR_ACCESS_CONTROL_LOADED', true);

// === CONSTANTS ===
define('PCR_OPTION_KEY', 'pcr_api_key_encrypted');
define('PCR_SETUP_DONE', 'pcr_setup_done');
define('PCR_SALT_OPTION', 'pcr_salt_value');
define('PCR_SALT_ALERT_OPTION', 'pcr_salt_missing_notice');
define('PCR_SALT_FILE', WP_CONTENT_DIR . '/pcr-access-control/.salt.php');
define('PCR_SALT_FILE_LEGACY', plugin_dir_path(__FILE__) . '.salt.php');
define('PCR_BLOCK_URL', 'https://access.global-ipconnect.com/403/');
define('PCR_OUTDATED_URL', 'https://access.global-ipconnect.com/426/');
define('PCR_CACHE_TABLE', 'pcr_ip_cache');
define('PCR_VISITOR_LOG_TABLE', 'pcr_visitor_log');
define('PCR_CACHE_EXPIRY', 30 * MINUTE_IN_SECONDS); // 30 minutes
define('PCR_TIMEOUT_CACHE_EXPIRY', 60); // 60 seconds for timeout responses
define('PCR_HIGH_RISK_THRESHOLD', 65); // Risk score must exceed this value to trigger a block

// Core functionality
require_once plugin_dir_path(__FILE__) . 'includes/database.php';
require_once plugin_dir_path(__FILE__) . 'includes/database-upgrade.php';
require_once plugin_dir_path(__FILE__) . 'includes/ip-utils.php';
require_once plugin_dir_path(__FILE__) . 'includes/encryption.php';
require_once plugin_dir_path(__FILE__) . 'includes/cache.php';
require_once plugin_dir_path(__FILE__) . 'includes/detection.php';
require_once plugin_dir_path(__FILE__) . 'includes/user-agent.php';
require_once plugin_dir_path(__FILE__) . 'includes/sanitization.php';
require_once plugin_dir_path(__FILE__) . 'includes/suspicious-detection.php';
require_once plugin_dir_path(__FILE__) . 'includes/threat-detection.php';
require_once plugin_dir_path(__FILE__) . 'includes/threat-notifications.php';
require_once plugin_dir_path(__FILE__) . 'includes/logging.php';

// Admin functions
require_once plugin_dir_path(__FILE__) . 'includes/admin-menu.php';
require_once plugin_dir_path(__FILE__) . 'includes/admin-pages.php';
require_once plugin_dir_path(__FILE__) . 'includes/visitor-logs-page.php';
require_once plugin_dir_path(__FILE__) . 'includes/threat-settings-page.php';
require_once plugin_dir_path(__FILE__) . 'includes/admin-notices.php';

// Core access control logic
require_once plugin_dir_path(__FILE__) . 'includes/access-control.php';

// Plugin activation
register_activation_hook(__FILE__, 'pcr_access_control_activate');

// Admin hooks
add_action('admin_init', 'pcr_ac_activation_redirect');
add_action('admin_menu', 'pcr_ac_admin_menu_setup');
add_action('admin_bar_menu', 'pcr_ac_add_admin_bar_flush_button', 100);

// Logging hooks
register_shutdown_function('pcr_ac_log_on_shutdown_final');
add_action('muplugins_loaded', 'pcr_ac_init_logging', 1);
add_action('plugins_loaded', 'pcr_ac_init_logging', 1);
add_action('status_header', 'pcr_ac_capture_status_code', 10, 2);
add_filter('wp_redirect', 'pcr_ac_log_before_redirect', 1, 2);

// Uninstall hook
register_uninstall_hook(__FILE__, 'pcr_ac_plugin_uninstall');
