<?php
/**
 * Admin menu setup and handler functions
 */

if (!defined('ABSPATH')) exit;

/**
 * Admin activation redirect
 */
function pcr_ac_activation_redirect() {
    if (get_option('pcr_activation_redirect', false)) {
        delete_option('pcr_activation_redirect');
        if (!get_option(PCR_SETUP_DONE)) {
            wp_redirect(admin_url('admin.php?page=pcr_setup'));
            exit;
        }
    }
}

/**
 * Setup admin menu pages
 *
 * Registers a top-level "Global IPconnect" menu in the admin sidebar and
 * places all plugin pages as submenus beneath it.
 */
function pcr_ac_admin_menu_setup() {
    // ── Top-level menu entry ──────────────────────────────────────────────
    add_menu_page(
        'Global IPconnect Access Control', // Browser / page <title>
        'Global IPconnect',                // Sidebar label
        'manage_options',
        'pcr_settings',                    // Landing page slug
        'pcr_ac_settings_page',
        'dashicons-shield-alt',
        80
    );

    // Re-label the auto-created duplicate first submenu entry.
    add_submenu_page(
        'pcr_settings',
        'Access Control Settings',
        'Settings',
        'manage_options',
        'pcr_settings',
        'pcr_ac_settings_page'
    );

    // Visitor Logs
    add_submenu_page(
        'pcr_settings',
        'Visitor Logs',
        'Visitor Logs',
        'manage_options',
        'pcr_visitor_logs',
        'pcr_ac_visitor_logs_page'
    );

    // Threat Detection Settings
    add_submenu_page(
        'pcr_settings',
        'Threat Detection Settings',
        'Threat Detection',
        'manage_options',
        'pcr-threat-settings',
        'pcr_threat_settings_page'
    );

    // First-run setup wizard (only visible until setup is complete)
    if (!get_option(PCR_SETUP_DONE)) {
        add_submenu_page(
            'pcr_settings',
            'ProxyCheck Setup',
            'Setup',
            'manage_options',
            'pcr_setup',
            'pcr_ac_setup_page'
        );
    }

    // Hidden handler page for the flush-cache action (no sidebar entry)
    add_submenu_page(
        null,
        'Flush IP Cache',
        '',
        'manage_options',
        'pcr_flush_cache',
        'pcr_ac_flush_cache_handler'
    );
}

/**
 * Add flush button to admin bar
 */
function pcr_ac_add_admin_bar_flush_button($wp_admin_bar) {
    if (!current_user_can('manage_options') || !get_option(PCR_SETUP_DONE)) return;

    $wp_admin_bar->add_node(array(
        'id'    => 'pcr-flush-cache',
        'title' => 'Flush IP Cache',
        'href'  => wp_nonce_url(admin_url('admin.php?page=pcr_flush_cache'), 'pcr_flush_cache'),
        'meta'  => array('title' => 'Clear all cached IP addresses')
    ));
}

/**
 * Handle flush cache request
 */
function pcr_ac_flush_cache_handler() {
    if (!current_user_can('manage_options') || !check_admin_referer('pcr_flush_cache')) {
        wp_die('Sorry, you are not allowed to perform this action.');
    }

    pcr_ac_flush_ip_cache();
    
    // Redirect back with success message
    wp_redirect(add_query_arg('pcr_flushed', '1', admin_url()));
    exit;
}
