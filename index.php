<?php
/*
Plugin Name: Global IPconnect Access Control
Description: Redirects proxy visitors to a block page using proxycheck.io.
Version: 1.0.17
Author: Global-IPconnect
*/
if (!defined('ABSPATH')) exit;

// === CONSTANTS ===
define('PCR_OPTION_KEY', 'pcr_api_key_encrypted');
define('PCR_SETUP_DONE', 'pcr_setup_done');
define('PCR_SALT_FILE', plugin_dir_path(__FILE__) . '.salt.php');
define('PCR_BLOCK_URL', 'https://access.global-ipconnect.com/403/?from=');
define('PCR_CACHE_TABLE', 'pcr_ip_cache');
define('PCR_CACHE_EXPIRY', 30 * MINUTE_IN_SECONDS); // 30 minutes

// === PLUGIN ACTIVATION ===
register_activation_hook(__FILE__, 'pcr_plugin_activation');

function pcr_plugin_activation() {
    pcr_create_cache_table();
    add_option('pcr_activation_redirect', true);
}

// === CREATE CACHE TABLE ===
function pcr_create_cache_table() {
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
function pcr_get_real_ip() {
    $ip = '';
    
    // Cloudflare headers
    if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
    }
    // Other proxy headers (in order of reliability)
    elseif (isset($_SERVER['HTTP_X_REAL_IP'])) {
        $ip = $_SERVER['HTTP_X_REAL_IP'];
    }
    elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $ip = trim($ips[0]); // Gets the first IP in the chain
    }
    // Default remote address
    else {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    
    // Validate the IP
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : $_SERVER['REMOTE_ADDR'];
}

// === ADMIN REDIRECT ===
add_action('admin_init', 'pcr_activation_redirect');

function pcr_activation_redirect() {
    if (get_option('pcr_activation_redirect', false)) {
        delete_option('pcr_activation_redirect');
        if (!get_option(PCR_SETUP_DONE)) {
            wp_redirect(admin_url('admin.php?page=pcr_setup'));
            exit;
        }
    }
}

// === ADMIN MENU ===
add_action('admin_bar_menu', 'pcr_add_admin_bar_flush_button', 100);
add_action('admin_menu', 'pcr_admin_menu_setup');

function pcr_admin_menu_setup() {
    if (!get_option(PCR_SETUP_DONE)) {
        add_menu_page('ProxyCheck Setup', 'ProxyCheck Setup', 'manage_options', 'pcr_setup', 'pcr_setup_page');
    }
}

function pcr_add_admin_bar_flush_button($wp_admin_bar) {
    if (!current_user_can('manage_options') || !get_option(PCR_SETUP_DONE)) return;

    $wp_admin_bar->add_node(array(
        'id'    => 'pcr-flush-cache',
        'title' => 'Flush IP Cache',
        'href'  => wp_nonce_url(admin_url('admin.php?page=pcr_flush_cache&action=flush_cache'), 'pcr_flush_cache'),
        'meta'  => array('title' => 'Clear all cached IP addresses')
    ));
}

// Handle flush cache action
add_action('admin_init', function() {
    if (isset($_GET['page']) && $_GET['page'] === 'pcr_flush_cache' && 
        isset($_GET['action']) && $_GET['action'] === 'flush_cache' && 
        check_admin_referer('pcr_flush_cache')) {
        pcr_flush_ip_cache();
        
        add_action('admin_notices', function() {
            echo '<div class="notice notice-success is-dismissible"><p>IP cache has been flushed successfully.</p></div>';
        });
    }
});

function pcr_flush_ip_cache() {
    global $wpdb;
    $table_name = $wpdb->prefix . PCR_CACHE_TABLE;
    $wpdb->query("TRUNCATE TABLE $table_name");
}

// === SETUP PAGE ===
function pcr_setup_page() {
    if (isset($_POST['pcr_submit']) && !empty($_POST['pcr_api_key'])) {
        $salt = bin2hex(random_bytes(16));
        file_put_contents(PCR_SALT_FILE, '<?php return "' . $salt . '";');
        $encrypted = pcr_encrypt(sanitize_text_field($_POST['pcr_api_key']), $salt);
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
function pcr_encrypt($data, $salt) {
    $key = hash('sha256', $salt, true);
    $iv = openssl_random_pseudo_bytes(16);
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $encrypted);
}

function pcr_decrypt($data, $salt) {
    $key = hash('sha256', $salt, true);
    $data = base64_decode($data);
    if (!$data || strlen($data) < 17) return null;
    $iv = substr($data, 0, 16);
    $encrypted = substr($data, 16);
    return openssl_decrypt($encrypted, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
}

// === CACHE MANAGEMENT ===
function pcr_get_cached_ip($ip_hash) {
    global $wpdb;
    $table_name = $wpdb->prefix . PCR_CACHE_TABLE;
    
    return $wpdb->get_row($wpdb->prepare(
        "SELECT * FROM $table_name WHERE ip_hash = %s", $ip_hash
    ));
}

function pcr_update_ip_cache($ip, $ip_hash, $is_proxy) {
    global $wpdb;
    $table_name = $wpdb->prefix . PCR_CACHE_TABLE;
    
    $wpdb->replace($table_name, array(
        'ip_hash' => $ip_hash,
        'ip_address' => $ip,
        'is_proxy' => $is_proxy ? 1 : 0,
        'last_checked' => current_time('mysql', 1)
    ));
}

function pcr_clean_expired_cache() {
    global $wpdb;
    $table_name = $wpdb->prefix . PCR_CACHE_TABLE;
    $expiry_time = date('Y-m-d H:i:s', time() - PCR_CACHE_EXPIRY);
    
    $wpdb->query($wpdb->prepare(
        "DELETE FROM $table_name WHERE last_checked < %s", $expiry_time
    ));
}

// === REDIRECT LOGIC ===
add_action('template_redirect', function () {
    if (is_admin() || !get_option(PCR_SETUP_DONE)) return;

    // Get the real IP address (handles Cloudflare and other proxies)
    $ip = pcr_get_real_ip();
    if (!$ip) {
        error_log('PCR DEBUG: Could not determine valid IP address.');
        return;
    }

    $ip_hash = md5($ip);
    error_log('PCR DEBUG: Visitor IP is ' . $ip);

    // Clean expired cache entries periodically (1% chance)
    if (mt_rand(1, 100) === 1) {
        pcr_clean_expired_cache();
    }

    $cached = pcr_get_cached_ip($ip_hash);
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
        pcr_update_ip_cache($ip, $ip_hash, $is_proxy);
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

// === UNINSTALL CLEANUP ===
register_uninstall_hook(__FILE__, 'pcr_plugin_uninstall');

function pcr_plugin_uninstall() {
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
