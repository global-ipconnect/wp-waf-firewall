<?php
/*
Plugin Name: Global IPconnect Access Control MU-Plugin Loader
Plugin URI: https://global-ipconnect.com/
Description: Loads the Global IPconnect Access Control plugin before all other plugins.
Version: 2.0.1
Author: Global-IPconnect
Author URI: https://global-ipconnect.com/
Text Domain: global-ipconnect-access-control
Domain Path: /languages
Update URI: false
*/

/**
 * Load Global IPconnect Access Control plugin early via mu-plugin
 * 
 * INSTALLATION:
 * 1. Copy this file to: wp-content/mu-plugins/load-access-control-early.php
 * 2. Create mu-plugins directory if it doesn't exist
 * 3. Ensure main plugin is installed in: wp-content/plugins/access-control/
 * 
 * WHY MU-PLUGIN:
 * - Loads before all regular plugins
 * - Ensures threat detection runs first
 * - Cannot be disabled from admin panel
 * - Critical for security-first architecture
 */

if (!defined('ABSPATH')) exit;

// Define the path to the main plugin
define('PCR_PLUGIN_PATH', WP_CONTENT_DIR . '/plugins/access-control/index.php');

// Check if the main plugin file exists
if (file_exists(PCR_PLUGIN_PATH)) {
    // Load the main plugin
    require_once PCR_PLUGIN_PATH;
    
    // Log that it was loaded via mu-plugin (only if debug is enabled)
    if (defined('WP_DEBUG') && WP_DEBUG) {
        error_log('PCR MU-PLUGIN: Global IPconnect Access Control loaded via mu-plugin');
    }
} else {
    // Plugin not found - log error
    if (defined('WP_DEBUG') && WP_DEBUG) {
        error_log('PCR MU-PLUGIN ERROR: Main plugin not found at ' . PCR_PLUGIN_PATH);
    }
    
    // Show admin notice
    add_action('admin_notices', function() {
        echo '<div class="notice notice-error"><p>';
        echo '<strong>Global IPconnect Access Control MU-Plugin Error:</strong> ';
        echo 'Main plugin not found. Please ensure the access-control plugin is installed in the correct directory.';
        echo '</p></div>';
    });
}
