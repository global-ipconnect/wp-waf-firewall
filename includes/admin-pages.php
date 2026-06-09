<?php
/**
 * Admin page rendering functions  
 * Setup and Settings pages
 */

if (!defined('ABSPATH')) exit;

/**
 * Setup page (shown on first activation)
 */
function pcr_ac_setup_page() {
    if (isset($_POST['pcr_submit']) && !empty($_POST['pcr_api_key']) && check_admin_referer('pcr_setup_nonce')) {
        $api_key = sanitize_text_field($_POST['pcr_api_key']);
        
        // Validate API key format
        if (preg_match('/^[a-zA-Z0-9\-_]+$/', $api_key)) {
            $salt = bin2hex(random_bytes(16));
            pcr_ac_store_salt($salt);
            $encrypted = pcr_ac_encrypt($api_key, $salt);
            update_option(PCR_OPTION_KEY, array(
                'cipher' => $encrypted,
                'salt' => $salt,
            ));
            update_option(PCR_SETUP_DONE, true);

            wp_redirect(admin_url());
            exit;
        } else {
            echo '<div class="notice notice-error"><p>' . esc_html__('Invalid API key format.', 'global-ipconnect-access-control') . '</p></div>';
        }
    }

    if (get_option(PCR_SETUP_DONE)) {
        echo '<div class="notice notice-info"><p>' . esc_html__('Setup is complete. This page is now disabled.', 'global-ipconnect-access-control') . '</p></div>';
    } else {
        echo '<div class="wrap"><h1>' . esc_html__('ProxyCheck Setup', 'global-ipconnect-access-control') . '</h1><form method="post">';
        wp_nonce_field('pcr_setup_nonce');
        echo '<label for="pcr_api_key">' . esc_html__('Enter ProxyCheck.io API Key:', 'global-ipconnect-access-control') . '</label><br>';
        echo '<input type="password" name="pcr_api_key" id="pcr_api_key" required style="width:400px;" autocomplete="off" /><br><br>';
        echo '<input type="submit" name="pcr_submit" class="button button-primary" value="' . esc_attr__('Save API Key', 'global-ipconnect-access-control') . '" />';
        echo '</form></div>';
    }
}

/**
 * Settings page (update API key)
 */
function pcr_ac_settings_page() {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('Sorry, you are not allowed to perform this action.', 'global-ipconnect-access-control'));
    }

    if (isset($_POST['pcr_settings_submit']) && check_admin_referer('pcr_settings_nonce')) {
        $api_key = isset($_POST['pcr_api_key']) ? sanitize_text_field($_POST['pcr_api_key']) : '';
        
        // Validate API key format
        if (!empty($api_key) && preg_match('/^[a-zA-Z0-9\-_]+$/', $api_key)) {
            $salt = bin2hex(random_bytes(16));
            pcr_ac_store_salt($salt);
            $encrypted = pcr_ac_encrypt($api_key, $salt);
            update_option(PCR_OPTION_KEY, array(
                'cipher' => $encrypted,
                'salt' => $salt,
            ));
            update_option(PCR_SETUP_DONE, true);
            delete_option(PCR_SALT_ALERT_OPTION);
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('ProxyCheck API key saved.', 'global-ipconnect-access-control') . '</p></div>';
        } else {
            echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__('Please enter a valid API key.', 'global-ipconnect-access-control') . '</p></div>';
        }
    }

    echo '<div class="wrap">';
    echo '<h1>' . esc_html__('ProxyCheck Access Control', 'global-ipconnect-access-control') . '</h1>';
    echo '<p>' . esc_html__('Update your ProxyCheck.io API key. Saving will regenerate the salt if it is missing.', 'global-ipconnect-access-control') . '</p>';
    echo '<form method="post">';
    wp_nonce_field('pcr_settings_nonce');
    echo '<label for="pcr_api_key">' . esc_html__('ProxyCheck.io API Key:', 'global-ipconnect-access-control') . '</label><br>';
    echo '<input type="password" id="pcr_api_key" name="pcr_api_key" required style="width:400px;" autocomplete="off" /><br><br>';
    echo '<input type="submit" name="pcr_settings_submit" class="button button-primary" value="' . esc_attr__('Save API Key', 'global-ipconnect-access-control') . '" />';
    echo '</form>';
    echo '</div>';
}
