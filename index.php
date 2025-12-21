<?php
/*
Plugin Name: Global IPconnect Access Control
Description: Redirects anonymised visitors to a block page using proxycheck.io.
Version: 1.1.12
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
define('PCR_SALT_OPTION', 'pcr_salt_value');
define('PCR_SALT_ALERT_OPTION', 'pcr_salt_missing_notice');
define('PCR_SALT_FILE', plugin_dir_path(__FILE__) . '.salt.php');
define('PCR_BLOCK_URL', 'https://access.global-ipconnect.com/403/?from=');
define('PCR_OUTDATED_URL', 'https://access.global-ipconnect.com/426/?from=');
define('PCR_CACHE_TABLE', 'pcr_ip_cache');
define('PCR_CACHE_EXPIRY', 30 * MINUTE_IN_SECONDS); // 30 minutes
define('PCR_TIMEOUT_CACHE_EXPIRY', 60); // 60 seconds for timeout responses
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
    add_options_page(
        'ProxyCheck Access Control',
        'ProxyCheck Access Control',
        'manage_options',
        'pcr_settings',
        'pcr_ac_settings_page'
    );
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

add_action('admin_notices', function() {
    if (!current_user_can('manage_options')) return;
    $flag_time = (int) get_option(PCR_SALT_ALERT_OPTION);
    if (!$flag_time) return;

    // Show notice and clear flag so it only appears once per occurrence.
    delete_option(PCR_SALT_ALERT_OPTION);
    $settings_url = esc_url(admin_url('options-general.php?page=pcr_settings'));
    echo '<div class="notice notice-error is-dismissible"><p><strong>ProxyCheck Access Control:</strong> Salt value is missing. Please re-save your ProxyCheck.io API key on the <a href="' . $settings_url . '">settings page</a> to restore lookups.</p></div>';
});

// === SETUP PAGE ===
function pcr_ac_setup_page() {
    if (isset($_POST['pcr_submit']) && !empty($_POST['pcr_api_key'])) {
        $salt = bin2hex(random_bytes(16));
        pcr_ac_store_salt($salt);
        $encrypted = pcr_ac_encrypt(sanitize_text_field($_POST['pcr_api_key']), $salt);
        update_option(PCR_OPTION_KEY, array(
            'cipher' => $encrypted,
            'salt' => $salt,
        ));
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

function pcr_ac_settings_page() {
    if (!current_user_can('manage_options')) {
        wp_die('Sorry, you are not allowed to perform this action.');
    }

    if (isset($_POST['pcr_settings_submit']) && check_admin_referer('pcr_settings_nonce')) {
        $api_key = isset($_POST['pcr_api_key']) ? sanitize_text_field($_POST['pcr_api_key']) : '';
        if (!empty($api_key)) {
            $salt = bin2hex(random_bytes(16));
            pcr_ac_store_salt($salt);
            $encrypted = pcr_ac_encrypt($api_key, $salt);
            update_option(PCR_OPTION_KEY, array(
                'cipher' => $encrypted,
                'salt' => $salt,
            ));
            update_option(PCR_SETUP_DONE, true);
            delete_option(PCR_SALT_ALERT_OPTION);
            echo '<div class="notice notice-success is-dismissible"><p>ProxyCheck API key saved.</p></div>';
        } else {
            echo '<div class="notice notice-error is-dismissible"><p>Please enter an API key.</p></div>';
        }
    }

    echo '<div class="wrap">';
    echo '<h1>ProxyCheck Access Control</h1>';
    echo '<p>Update your ProxyCheck.io API key. Saving will regenerate the salt if it is missing.</p>';
    echo '<form method="post">';
    wp_nonce_field('pcr_settings_nonce');
    echo '<label for="pcr_api_key">ProxyCheck.io API Key:</label><br>';
    echo '<input type="password" id="pcr_api_key" name="pcr_api_key" required style="width:400px;" /><br><br>';
    echo '<input type="submit" name="pcr_settings_submit" class="button button-primary" value="Save API Key" />';
    echo '</form>';
    echo '</div>';
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

function pcr_ac_get_api_option_payload() {
    $value = get_option(PCR_OPTION_KEY);

    if (is_string($value)) {
        $decoded = json_decode($value, true);
        if (is_array($decoded) && (isset($decoded['cipher']) || isset($decoded['salt']))) {
            $value = $decoded;
        }
    }

    if (is_array($value)) {
        $cipher = isset($value['cipher']) ? $value['cipher'] : null;
        $salt = isset($value['salt']) ? $value['salt'] : null;
        return array('cipher' => $cipher, 'salt' => $salt);
    }

    return array('cipher' => $value, 'salt' => null);
}

function pcr_ac_store_salt($salt) {
    // Persist salt in both the file and as an option so we can recover if the file is deleted.
    update_option(PCR_SALT_OPTION, $salt);
    $bytes_written = @file_put_contents(PCR_SALT_FILE, '<?php return "' . $salt . '";');
    if ($bytes_written === false) {
        error_log('PCR DEBUG: Unable to write salt file at ' . PCR_SALT_FILE);
    }
}

function pcr_ac_get_salt($fallback = null) {
    if (file_exists(PCR_SALT_FILE)) {
        $salt = include PCR_SALT_FILE;
        if ($salt && !get_option(PCR_SALT_OPTION)) {
            update_option(PCR_SALT_OPTION, $salt);
        }
        return $salt;
    }

    $salt = get_option(PCR_SALT_OPTION);
    if ($salt) {
        // Recreate missing salt file from stored option for resilience.
        pcr_ac_store_salt($salt);
        return $salt;
    }

    if ($fallback) {
        pcr_ac_store_salt($fallback);
        return $fallback;
    }

    return null;
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

function pcr_ac_timeout_cache_key($ip_hash) {
    return 'pcr_timeout_' . $ip_hash;
}

function pcr_ac_get_timeout_cached($ip_hash) {
    return get_transient(pcr_ac_timeout_cache_key($ip_hash));
}

function pcr_ac_set_timeout_cache($ip_hash, $is_proxy, $reason) {
    set_transient(pcr_ac_timeout_cache_key($ip_hash), array(
        'is_proxy' => $is_proxy ? 1 : 0,
        'reason' => $reason,
    ), PCR_TIMEOUT_CACHE_EXPIRY);
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

function pcr_ac_is_search_bot_user_agent($user_agent) {
    if (!$user_agent) {
        return false;
    }

    $ua = strtolower($user_agent);
    $bots = array('googlebot', 'bingbot', 'duckduckbot', 'duckduckgo', 'bravesearchbot', 'bravebot');
    foreach ($bots as $bot) {
        if (strpos($ua, $bot) !== false) {
            return true;
        }
    }

    return false;
}

function pcr_ac_is_wordpress_user_agent($user_agent) {
    if (!$user_agent) {
        return false;
    }

    return stripos($user_agent, 'wordpress/') !== false;
}

function pcr_ac_is_outdated_browser($user_agent) {
    if (!$user_agent) {
        return false;
    }

    $ua = strtolower($user_agent);

    if (strpos($ua, 'msie') !== false || strpos($ua, 'trident/') !== false) {
        return true;
    }

    if (preg_match('/(chrome|crios|chromium)\/(\d+)/i', $user_agent, $matches)) {
        return (int)$matches[2] < 120;
    }

    if (preg_match('/(edg|edge)\/(\d+)/i', $user_agent, $matches)) {
        return (int)$matches[2] < 120;
    }

    if (preg_match('/opr\/(\d+)/i', $user_agent, $matches)) {
        return (int)$matches[1] < 104;
    }

    if (preg_match('/firefox\/(\d+)/i', $user_agent, $matches)) {
        return (int)$matches[1] < 120;
    }

    if (strpos($ua, 'safari/') !== false && strpos($ua, 'chrome/') === false && strpos($ua, 'crios/') === false && strpos($ua, 'fxios/') === false) {
        if (preg_match('/version\/(\d+)/i', $user_agent, $matches)) {
            return (int)$matches[1] < 14;
        }
    }

    if (preg_match('/fxios\/(\d+)/i', $user_agent, $matches)) {
        return (int)$matches[1] < 120;
    }

    return false;
}

function pcr_ac_get_detections_modified_by_flags($ip_data) {
    if (!is_array($ip_data)) {
        return array(false, false);
    }

    $sections = array($ip_data);
    if (isset($ip_data['detections']) && is_array($ip_data['detections'])) {
        $sections[] = $ip_data['detections'];
    }

    foreach ($sections as $section) {
        if (!is_array($section) || !isset($section['detections_modified_by']) || !is_array($section['detections_modified_by'])) {
            continue;
        }

        $modifiers = $section['detections_modified_by'];
        $whitelist = false;
        $blacklist = false;

        foreach (array('whitelist', 'whitelisted') as $whitelist_key) {
            if (array_key_exists($whitelist_key, $modifiers)) {
                $value = $modifiers[$whitelist_key];
                if ((is_array($value) && count($value) > 0) || pcr_ac_truthy_flag($value)) {
                    $whitelist = true;
                }
            }
        }

        foreach (array('blacklist', 'blacklisted') as $blacklist_key) {
            if (array_key_exists($blacklist_key, $modifiers)) {
                $value = $modifiers[$blacklist_key];
                if ((is_array($value) && count($value) > 0) || pcr_ac_truthy_flag($value)) {
                    $blacklist = true;
                }
            }
        }

        if ($whitelist || $blacklist) {
            return array($whitelist, $blacklist);
        }
    }

    return array(false, false);
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

    list($modified_whitelist, $modified_blacklist) = pcr_ac_get_detections_modified_by_flags($ip_data);
    if ($modified_whitelist) {
        return array(false, 'modified-whitelist');
    }

    if (pcr_ac_is_whitelisted_result($ip_data)) {
        return array(false, 'whitelisted');
    }

    if ($modified_blacklist) {
        return array(true, 'modified-blacklist');
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

    $risk_score = null;
    if (array_key_exists('risk', $detections) && is_numeric($detections['risk'])) {
        $risk_score = (int) $detections['risk'];
    }

    if ($risk_score !== null && in_array($network_type, array('residential', 'business'), true) && $risk_score >= 66) {
        return array(true, 'risk-network');
    }

    if ($risk_score !== null && $risk_score > PCR_HIGH_RISK_THRESHOLD) {
        return array(true, 'risk');
    }

    return array(false, 'clean');
}

// === REDIRECT LOGIC ===
add_action('template_redirect', function () {
    if (is_admin() || !get_option(PCR_SETUP_DONE)) return;

    $current_url = (is_ssl() ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
    if (!pcr_ac_is_search_bot_user_agent($user_agent)
        && !pcr_ac_is_wordpress_user_agent($user_agent)
        && pcr_ac_is_outdated_browser($user_agent)) {
        wp_redirect(PCR_OUTDATED_URL . urlencode($current_url), 307);
        exit;
    }

    // Get the real IP address (handles Cloudflare and other proxies)
    $ip = pcr_ac_get_real_ip();
    if (!$ip) {
        error_log('PCR DEBUG: Could not determine valid IP address.');
        return;
    }

    $ip_hash = md5($ip);
    error_log('PCR DEBUG: Visitor IP is ' . $ip);

    $is_proxy = null;
    $needs_check = null;
    $block_reason = '';

    // Clean expired cache entries periodically (1% chance)
    if (mt_rand(1, 100) === 1) {
        pcr_ac_clean_expired_cache();
    }

    $timeout_cached = pcr_ac_get_timeout_cached($ip_hash);
    if ($timeout_cached !== false) {
        $is_proxy = !empty($timeout_cached['is_proxy']);
        $block_reason = isset($timeout_cached['reason']) ? $timeout_cached['reason'] : 'timeout-cache';
        $needs_check = false;
        error_log('PCR DEBUG: Using timeout cache: ' . ($is_proxy ? 'proxy' : 'clean'));
    }

    $cached = pcr_ac_get_cached_ip($ip_hash);
    $is_proxy = $is_proxy ?? false;
    $needs_check = ($needs_check === null) ? true : $needs_check;

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

    if ($needs_check) {
        $api_option = pcr_ac_get_api_option_payload();
        $salt = pcr_ac_get_salt($api_option['salt']);
        if (!$salt) {
            update_option(PCR_SALT_ALERT_OPTION, time());
            error_log('PCR DEBUG: Salt value missing. Please re-save the ProxyCheck API key.');
            return;
        }

        $encrypted_key = $api_option['cipher'];
        $api_key = pcr_ac_decrypt($encrypted_key, $salt);
        if (!$api_key) {
            error_log('PCR DEBUG: Decryption failed.');
            return;
        }

        error_log('PCR DEBUG: API key decrypted successfully');

		$site_domain = parse_url(get_site_url(), PHP_URL_HOST);
        $tag = rawurlencode('Access Control - ' . $site_domain);
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
            $error_code = $response->get_error_code();
            $error_message = $response->get_error_message();
            $is_timeout = in_array($error_code, array('timeout', 'http_request_timeout'), true) || stripos($error_message, 'timed out') !== false;
            if ($is_timeout) {
                pcr_ac_set_timeout_cache($ip_hash, false, 'timeout');
                error_log('PCR DEBUG: Proxycheck API timeout; caching clean result for 60s');
            } else {
                error_log('PCR DEBUG: Proxycheck API call failed: ' . $error_message);
            }
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

        $ip_payload = null;
        if (isset($body[$ip]) && is_array($body[$ip])) {
            $ip_payload = $body[$ip];
        } elseif (isset($body['address']) && $body['address'] === $ip) {
            $ip_payload = $body;
        } elseif (isset($body['ip']) && is_array($body['ip'])) {
            $ip_payload = $body['ip'];
        }

        if (!$ip_payload || !is_array($ip_payload)) {
            error_log('PCR DEBUG: Proxycheck response missing IP payload.');
            return;
        }

        list($is_proxy, $block_reason) = pcr_ac_should_block_ip_data($ip_payload);
        pcr_ac_update_ip_cache($ip, $ip_hash, $is_proxy);
    } else {
        if ($is_proxy) {
            $block_reason = 'cache';
        }
    }

    if ($is_proxy) {
        $reason_message = $block_reason ? " ({$block_reason})" : '';
        error_log('PCR DEBUG: Redirecting to block page' . $reason_message);
        wp_redirect(PCR_BLOCK_URL . urlencode($current_url), 307);
        exit;
    } else {
        $allow_reason = in_array($block_reason, array('whitelisted', 'modified-whitelist'), true)
            ? " ({$block_reason})"
            : '';
        error_log('PCR DEBUG: Visitor allowed' . $allow_reason);
    }
});

// === UNINSTALL CLEANUP ===
register_uninstall_hook(__FILE__, 'pcr_ac_plugin_uninstall');

function pcr_ac_plugin_uninstall() {
    delete_option(PCR_OPTION_KEY);
    delete_option(PCR_SETUP_DONE);
    delete_option(PCR_SALT_OPTION);
    delete_option(PCR_SALT_ALERT_OPTION);
    delete_option('pcr_activation_redirect');

    global $wpdb;
    $table_name = $wpdb->prefix . PCR_CACHE_TABLE;
    $wpdb->query("DROP TABLE IF EXISTS $table_name");

    if (file_exists(PCR_SALT_FILE)) {
        unlink(PCR_SALT_FILE);
    }
}
