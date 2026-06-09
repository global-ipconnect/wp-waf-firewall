<?php
/**
 * Admin notices
 */

if (!defined('ABSPATH')) exit;

/**
 * Show admin notice after flush
 */
add_action('admin_notices', function() {
    if (isset($_GET['pcr_flushed']) && $_GET['pcr_flushed'] === '1' && current_user_can('manage_options')) {
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('IP cache has been flushed successfully.', 'global-ipconnect-access-control') . '</p></div>';
    }
});

/**
 * Show notice when salt is missing
 */
add_action('admin_notices', function() {
    if (!current_user_can('manage_options')) return;
    $flag_time = (int) get_option(PCR_SALT_ALERT_OPTION);
    if (!$flag_time) return;

    // Show notice and clear flag so it only appears once per occurrence.
    delete_option(PCR_SALT_ALERT_OPTION);
    $settings_url = esc_url(admin_url('options-general.php?page=pcr_settings'));
    echo '<div class="notice notice-error is-dismissible"><p><strong>ProxyCheck Access Control:</strong> Salt value is missing. Please re-save your ProxyCheck.io API key on the <a href="' . $settings_url . '">settings page</a> to restore lookups.</p></div>';
});
