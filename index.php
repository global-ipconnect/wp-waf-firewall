<?php
/*
Plugin Name: Global IPconnect Access Control
Description: Redirects proxy visitors to a block page using proxycheck.io.
Version: 1.0.1
Author: Global-IPconnect
*/


if (!defined('ABSPATH')) exit;

// === CONSTANTS ===
define('PCR_OPTION_KEY', 'pcr_api_key_encrypted');
define('PCR_SETUP_DONE', 'pcr_setup_done');
define('PCR_SALT_FILE', plugin_dir_path(__FILE__) . '.salt.php');
define('PCR_TRANSIENT_PREFIX', 'pcr_ip_cache_');
define('PCR_BLOCK_URL', 'https://access.global-ipconnect.com/403/?from=');

// === SETUP MENU ===
add_action('admin_menu', function () {
    if (!get_option(PCR_SETUP_DONE)) {
        add_menu_page('ProxyCheck Setup', 'ProxyCheck Setup', 'manage_options', 'pcr_setup', 'pcr_setup_page');
    }
});

function pcr_setup_page() {
    if (isset($_POST['pcr_submit']) && !empty($_POST['pcr_api_key'])) {
        $salt = bin2hex(random_bytes(16));
        file_put_contents(PCR_SALT_FILE, '<?php return "' . $salt . '";');
        $encrypted = pcr_encrypt(sanitize_text_field($_POST['pcr_api_key']), $salt);
        update_option(PCR_OPTION_KEY, $encrypted);
        update_option(PCR_SETUP_DONE, true);

        // Redirect to admin dashboard after successful save
        wp_redirect(admin_url());
        exit;
    }

    if (get_option(PCR_SETUP_DONE)) {
        echo '<div class="notice notice-info"><p>Setup is complete. This page is now disabled.</p></div>';
    } else {
        echo '<div class="wrap"><h1>ProxyCheck Setup</h1><form method="post">';
        echo '<label for="pcr_api_key">Enter ProxyCheck.io API Key:</label><br>';
        echo '<input type="password" name="pcr_api_key" required style="width:400px;" /><br><br>';
        echo '<input type="submit" name="pcr_submit" class="button button-primary" value="Save API Key" />';
        echo '</form></div>';
    }
}

// === ENCRYPTION FUNCTIONS ===
function pcr_encrypt($data, $salt)
{
    $key = hash('sha256', $salt, true);
    $iv = openssl_random_pseudo_bytes(16);
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $encrypted);
}

function pcr_decrypt($data, $salt)
{
    $key = hash('sha256', $salt, true);
    $data = base64_decode($data);
    if (!$data || strlen($data) < 17) return null;
    $iv = substr($data, 0, 16);
    $encrypted = substr($data, 16);
    return openssl_decrypt($encrypted, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
}

// === REDIRECT LOGIC ===
add_action('template_redirect', function () {
    if (is_admin() || !get_option(PCR_SETUP_DONE)) return;

    if (!isset($_SERVER['REMOTE_ADDR']) || !filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP)) {
        error_log('PCR DEBUG: Invalid or missing REMOTE_ADDR.');
        return;
    }

    $ip = $_SERVER['REMOTE_ADDR'];
    error_log('PCR DEBUG: Visitor IP is ' . $ip);

    $transient_key = PCR_TRANSIENT_PREFIX . md5($ip);
    $cached = get_transient($transient_key);

    if ($cached === false) {
        if (!file_exists(PCR_SALT_FILE)) {
            error_log('PCR DEBUG: Salt file missing.');
            return;
        }

        $salt = include PCR_SALT_FILE;
        if (!$salt) {
            error_log('PCR DEBUG: Salt value not found.');
            return;
        }

        $encrypted_key = get_option(PCR_OPTION_KEY);
        $api_key = pcr_decrypt($encrypted_key, $salt);
        if (!$api_key) {
            error_log('PCR DEBUG: Decryption failed.');
            return;
        }

        error_log('PCR DEBUG: API key decrypted successfully');

        $tag = rawurlencode('Global IPconnect Access Control');
        $url = "https://proxycheck.io/v2/{$ip}?key={$api_key}&vpn=1&asn=1&node=1&tag={$tag}";
        $response = wp_remote_get($url, ['timeout' => 5]);

        if (is_wp_error($response)) {
            error_log('PCR DEBUG: Proxycheck API call failed: ' . $response->get_error_message());
            return;
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);
        error_log('PCR DEBUG: Proxycheck response: ' . print_r($body, true));

        $is_proxy = isset($body[$ip]['proxy']) && $body[$ip]['proxy'] === 'yes';
        set_transient($transient_key, $is_proxy ? '1' : '0', 30 * MINUTE_IN_SECONDS);
    } else {
        $is_proxy = $cached === '1';
        error_log('PCR DEBUG: Loaded cached proxy status: ' . ($is_proxy ? 'proxy' : 'clean'));
    }

    if ($is_proxy) {
        $current_url = (is_ssl() ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        error_log('PCR DEBUG: Redirecting to block page');
        wp_redirect(PCR_BLOCK_URL . urlencode($current_url));
        exit;
    } else {
        error_log('PCR DEBUG: Visitor is not a proxy');
    }
});

error_log('PCR DEBUG: API key decrypted successfully');
error_log('PCR DEBUG: Visitor IP is ' . $ip);
error_log('PCR DEBUG: Proxycheck response: ' . print_r($body, true));

// === UNINSTALL CLEANUP ===
register_uninstall_hook(__FILE__, 'pcr_plugin_uninstall');

function pcr_plugin_uninstall()
{
    delete_option(PCR_OPTION_KEY);
    delete_option(PCR_SETUP_DONE);

    global $wpdb;
    $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_" . PCR_TRANSIENT_PREFIX . "%'");

    if (file_exists(PCR_SALT_FILE)) {
        unlink(PCR_SALT_FILE);
    }
}
