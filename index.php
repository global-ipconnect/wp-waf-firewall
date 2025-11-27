<?php
/*
Plugin Name: Global IPconnect Access Control
Description: Redirects anonymised visitors to a block page using proxycheck.io.
Version: 1.1.1
Author: Global-IPconnect
*/

if (!defined('ABSPATH')) exit;

if (defined('PCR_ACCESS_CONTROL_LOADED')) {
    return;
}
define('PCR_ACCESS_CONTROL_LOADED', true);

// === CONSTANTS ===
define('PCR_OPTION_KEY', 'pcr_api_key_encrypted');
define('PCR_SETUP_DONE', 'pcr_setup_done');
define('PCR_SALT_FILE', plugin_dir_path(__FILE__) . '.salt.php');
define('PCR_BLOCK_URL', 'https://access.global-ipconnect.com/403/?from=');
define('PCR_CACHE_TABLE', 'pcr_ip_cache');
define('PCR_CACHE_EXPIRY', 30 * MINUTE_IN_SECONDS); // 30 minutes
define('PCR_HIGH_RISK_THRESHOLD', 65); // Risk score must exceed this value to trigger a block

// === PLUGIN ACTIVATION ===
register_activation_hook(__FILE__, 'pcr_access_control_activate');

function pcr_access_control_activate() {
    pcr_ac_create_cache_table();
    add_option('pcr_activation_redirect', true);
}

// === CREATE CACHE TABLE ===
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

// === GET REAL IP ADDRESS ===
function pcr_ac_get_real_ip() {
    $ip = '';
    
    if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
    }
    elseif (isset($_SERVER['HTTP_X_REAL_IP'])) {
        $ip = $_SERVER['HTTP_X_REAL_IP'];
    }
    elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $ip = trim($ips[0]);
    }
    else {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : $_SERVER['REMOTE_ADDR'];
}

// === ADMIN REDIRECT ===
add_action('admin_init', 'pcr_ac_activation_redirect');

function pcr_ac_activation_redirect() {
    if (get_option('pcr_activation_redirect', false)) {
        delete_option('pcr_activation_redirect');
        if (!get_option(PCR_SETUP_DONE)) {
            wp_redirect(admin_url('admin.php?page=pcr_setup'));
            exit;
        }
    }
}

// === ADMIN MENU ===
add_action('admin_bar_menu', 'pcr_ac_add_admin_bar_flush_button', 100);
add_action('admin_menu', 'pcr_ac_admin_menu_setup');

function pcr_ac_admin_menu_setup() {
    if (!get_option(PCR_SETUP_DONE)) {
        add_menu_page('ProxyCheck Setup', 'ProxyCheck Setup', 'manage_options', 'pcr_setup', 'pcr_ac_setup_page');
    }
    // Add hidden page for flush cache action
    add_submenu_page(
        null, // No parent menu
        'Flush IP Cache', // Page title
        '', // Menu title (not shown)
        'manage_options', // Capability
        'pcr_flush_cache', // Menu slug
        'pcr_ac_flush_cache_handler' // Function
    );
}

function pcr_ac_add_admin_bar_flush_button($wp_admin_bar) {
    if (!current_user_can('manage_options') || !get_option(PCR_SETUP_DONE)) return;

    $wp_admin_bar->add_node(array(
        'id'    => 'pcr-flush-cache',
        'title' => 'Flush IP Cache',
        'href'  => wp_nonce_url(admin_url('admin.php?page=pcr_flush_cache'), 'pcr_flush_cache'),
        'meta'  => array('title' => 'Clear all cached IP addresses')
    ));
}

function pcr_ac_flush_cache_handler() {
    if (!current_user_can('manage_options') || !check_admin_referer('pcr_flush_cache')) {
        wp_die('Sorry, you are not allowed to perform this action.');
    }

    pcr_ac_flush_ip_cache();
    
    // Redirect back with success message
    wp_redirect(add_query_arg('pcr_flushed', '1', admin_url()));
    exit;
}

function pcr_ac_flush_ip_cache() {
    global $wpdb;
    $table_name = $wpdb->prefix . PCR_CACHE_TABLE;
    $wpdb->query("TRUNCATE TABLE $table_name");
}

// Show admin notice after flush
add_action('admin_notices', function() {
    if (isset($_GET['pcr_flushed'])) {
        echo '<div class="notice notice-success is-dismissible"><p>IP cache has been flushed successfully.</p></div>';
    }
});

// === SETUP PAGE ===
function pcr_ac_setup_page() {
    if (isset($_POST['pcr_submit']) && !empty($_POST['pcr_api_key'])) {
        $salt = bin2hex(random_bytes(16));
        file_put_contents(PCR_SALT_FILE, '<?php return "' . $salt . '";');
        $encrypted = pcr_ac_encrypt(sanitize_text_field($_POST['pcr_api_key']), $salt);
        update_option(PCR_OPTION_KEY, $encrypted);
        update_option(PCR_SETUP_DONE, true);

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
function pcr_ac_encrypt($data, $salt) {
    $key = hash('sha256', $salt, true);
    $iv = openssl_random_pseudo_bytes(16);
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $encrypted);
}

function pcr_ac_decrypt($data, $salt) {
    $key = hash('sha256', $salt, true);
    $data = base64_decode($data);
    if (!$data || strlen($data) < 17) return null;
    $iv = substr($data, 0, 16);
    $encrypted = substr($data, 16);
    return openssl_decrypt($encrypted, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
}

// === CACHE MANAGEMENT ===
function pcr_ac_get_cached_ip($ip_hash) {
    global $wpdb;
    $table_name = $wpdb->prefix . PCR_CACHE_TABLE;
    
    return $wpdb->get_row($wpdb->prepare(
        "SELECT * FROM $table_name WHERE ip_hash = %s", $ip_hash
    ));
}

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

function pcr_ac_clean_expired_cache() {
    global $wpdb;
    $table_name = $wpdb->prefix . PCR_CACHE_TABLE;
    $expiry_time = date('Y-m-d H:i:s', time() - PCR_CACHE_EXPIRY);
    
    $wpdb->query($wpdb->prepare(
        "DELETE FROM $table_name WHERE last_checked < %s", $expiry_time
    ));
}

function pcr_ac_truthy_flag($value) {
    if (is_bool($value)) {
        return $value;
    }

    if (is_numeric($value)) {
        return (int) $value === 1;
    }

    if (is_string($value)) {
        $normalized = strtolower($value);
        return in_array($normalized, array('1', 'true', 'yes', 'on'), true);
    }

    return false;
}

function pcr_ac_is_whitelisted_result($ip_data) {
    if (!is_array($ip_data) || empty($ip_data['result'])) {
        return false;
    }

    $result = $ip_data['result'];

    foreach (array('whitelisted', 'whitelist') as $key) {
        if (array_key_exists($key, $result) && pcr_ac_truthy_flag($result[$key])) {
            return true;
        }
    }

    if (!empty($result['list']) && strtolower((string) $result['list']) === 'whitelist') {
        return true;
    }

    if (!empty($result['lists']) && is_array($result['lists'])) {
        $lists = $result['lists'];
        foreach (array('whitelist', 'white') as $list_key) {
            if (array_key_exists($list_key, $lists) && pcr_ac_truthy_flag($lists[$list_key])) {
                return true;
            }
        }
    }

    return false;
}

function pcr_ac_should_block_ip_data($ip_data) {
    if (!is_array($ip_data)) {
        return array(false, 'missing-data');
    }

    if (pcr_ac_is_whitelisted_result($ip_data)) {
        return array(false, 'whitelisted');
    }

    $detections = isset($ip_data['detections']) && is_array($ip_data['detections'])
        ? $ip_data['detections']
        : array();

    $blockable_keys = array('proxy', 'vpn', 'hosting', 'datacenter', 'vps', 'bot', 'tor', 'compromised', 'scraper', 'anonymous');
    foreach ($blockable_keys as $key) {
        if (array_key_exists($key, $detections) && pcr_ac_truthy_flag($detections[$key])) {
            return array(true, $key);
        }
    }

    $network_type_value = isset($ip_data['network']['type']) ? $ip_data['network']['type'] : '';
    $network_type = strtolower((string) $network_type_value);
    if ($network_type === 'hosting') {
        return array(true, 'hosting');
    }

    if (array_key_exists('risk', $detections) && is_numeric($detections['risk'])) {
        $risk_score = (int) $detections['risk'];
        if ($risk_score > PCR_HIGH_RISK_THRESHOLD) {
            return array(true, 'risk');
        }
    }

    return array(false, 'clean');
}

// === REDIRECT LOGIC ===
add_action('template_redirect', function () {
    if (is_admin() || !get_option(PCR_SETUP_DONE)) return;

    // Get the real IP address (handles Cloudflare and other proxies)
    $ip = pcr_ac_get_real_ip();
    if (!$ip) {
        error_log('PCR DEBUG: Could not determine valid IP address.');
        return;
    }

    $ip_hash = md5($ip);
    error_log('PCR DEBUG: Visitor IP is ' . $ip);

    // Clean expired cache entries periodically (1% chance)
    if (mt_rand(1, 100) === 1) {
        pcr_ac_clean_expired_cache();
    }

    $cached = pcr_ac_get_cached_ip($ip_hash);
    $is_proxy = false;
    $needs_check = true;

    if ($cached) {
        $last_checked = strtotime($cached->last_checked);
        $age = time() - $last_checked;
        
        if ($age < PCR_CACHE_EXPIRY) {
            $is_proxy = (bool)$cached->is_proxy;
            $needs_check = false;
            error_log('PCR DEBUG: Using cached proxy status: ' . ($is_proxy ? 'proxy' : 'clean') . " (age: {$age}s)");
        } else {
            error_log('PCR DEBUG: Cached entry expired (age: {$age}s), rechecking');
        }
    }

    $block_reason = '';

    if ($needs_check) {
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
        $api_key = pcr_ac_decrypt($encrypted_key, $salt);
        if (!$api_key) {
            error_log('PCR DEBUG: Decryption failed.');
            return;
        }

        error_log('PCR DEBUG: API key decrypted successfully');

        $tag = rawurlencode('Global IPconnect Access Control');
        $url = sprintf(
            'https://proxycheck.io/v3/%s?key=%s&tag=%s&node=1',
            $ip,
            rawurlencode($api_key),
            $tag
        );

        $response = wp_remote_get($url, array(
            'timeout' => 8,
            'headers' => array('Accept' => 'application/json'),
        ));

        if (is_wp_error($response)) {
            error_log('PCR DEBUG: Proxycheck API call failed: ' . $response->get_error_message());
            return;
        }

        $body_raw = wp_remote_retrieve_body($response);
        $body = json_decode($body_raw, true);
        error_log('PCR DEBUG: Proxycheck response: ' . print_r($body, true));

        if (!is_array($body)) {
            error_log('PCR DEBUG: Proxycheck response could not be decoded. Raw body: ' . $body_raw);
            return;
        }

        $status = isset($body['status']) ? $body['status'] : null;
        if (!in_array($status, array('ok', 'warning'), true)) {
            error_log('PCR DEBUG: Unexpected Proxycheck status: ' . print_r($status, true));
            return;
        }

        if (!isset($body[$ip]) || !is_array($body[$ip])) {
            error_log('PCR DEBUG: Proxycheck response missing IP payload.');
            return;
        }

        list($is_proxy, $block_reason) = pcr_ac_should_block_ip_data($body[$ip]);
        pcr_ac_update_ip_cache($ip, $ip_hash, $is_proxy);
    } else {
        if ($is_proxy) {
            $block_reason = 'cache';
        }
    }

    if ($is_proxy) {
        $current_url = (is_ssl() ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        $reason_message = $block_reason ? " ({$block_reason})" : '';
        error_log('PCR DEBUG: Redirecting to block page' . $reason_message);
        wp_redirect(PCR_BLOCK_URL . urlencode($current_url), 307);
        exit;
    } else {
        $allow_reason = ($block_reason === 'whitelisted') ? ' (whitelisted)' : '';
        error_log('PCR DEBUG: Visitor allowed' . $allow_reason);
    }
});

// === UNINSTALL CLEANUP ===
register_uninstall_hook(__FILE__, 'pcr_ac_plugin_uninstall');

function pcr_ac_plugin_uninstall() {
    delete_option(PCR_OPTION_KEY);
    delete_option(PCR_SETUP_DONE);
    delete_option('pcr_activation_redirect');

    global $wpdb;
    $table_name = $wpdb->prefix . PCR_CACHE_TABLE;
    $wpdb->query("DROP TABLE IF EXISTS $table_name");

    if (file_exists(PCR_SALT_FILE)) {
        unlink(PCR_SALT_FILE);
    }
}
