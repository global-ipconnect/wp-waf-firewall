<?php
/*
Plugin Name: Global IPconnect Access Control
Description: Redirects proxy visitors to a block page using proxycheck.io.
Version: 1.0.22
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
    // Add hidden page for flush cache action
    add_submenu_page(
        null, // No parent menu
        'Flush IP Cache', // Page title
        '', // Menu title (not shown)
        'manage_options', // Capability
        'pcr_flush_cache', // Menu slug
        'pcr_flush_cache_handler' // Function
    );
}

function pcr_add_admin_bar_flush_button($wp_admin_bar) {
    if (!current_user_can('manage_options') || !get_option(PCR_SETUP_DONE)) return;

    $wp_admin_bar->add_node(array(
        'id'    => 'pcr-flush-cache',
        'title' => 'Flush IP Cache',
        'href'  => wp_nonce_url(admin_url('admin.php?page=pcr_flush_cache'), 'pcr_flush_cache'),
        'meta'  => array('title' => 'Clear all cached IP addresses')
    ));
}

function pcr_flush_cache_handler() {
    if (!current_user_can('manage_options') || !check_admin_referer('pcr_flush_cache')) {
        wp_die('Sorry, you are not allowed to perform this action.');
    }

    pcr_flush_ip_cache();
    
    // Redirect back with success message
    wp_redirect(add_query_arg('pcr_flushed', '1', admin_url()));
    exit;
}

function pcr_flush_ip_cache() {
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

// === CHECK IF IP SHOULD BE BLOCKED ===
function pcr_should_block_ip($ip_data) {
    // Handle both old and new API response formats
    $is_proxy = false;
    
    // Old format: direct 'proxy' field
    if (isset($ip_data['proxy']) && $ip_data['proxy'] === 'yes') {
        $is_proxy = true;
        error_log('PCR DEBUG: Old format proxy detection');
    }
    
    // New format: detections object
    if (isset($ip_data['detections']) && is_array($ip_data['detections'])) {
        $detections = $ip_data['detections'];
        
        // Check if any detection is true
        $detection_types = ['proxy', 'vpn', 'compromised', 'scraper', 'tor', 'hosting', 'anonymous'];
        
        foreach ($detection_types as $type) {
            if (isset($detections[$type]) && $detections[$type] === true) {
                $is_proxy = true;
                error_log("PCR DEBUG: New format detection found: $type");
                break;
            }
        }
        
        // Check if detections are modified by whitelist (only block if not whitelisted)
        if ($is_proxy && isset($detections['detections_modified_by']['whitelist'])) {
            error_log('PCR DEBUG: Detections modified by whitelist, allowing access');
            $is_proxy = false;
        }
    }
    
    return $is_proxy;
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
            error_log('PCR DEBUG: Cached entry expired (age: ' . $age . 's), rechecking');
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

        // Get the site domain for the tag
        $site_domain = parse_url(get_site_url(), PHP_URL_HOST);
        $tag = rawurlencode('Access Control - ' . $site_domain);
        
        $url = "https://proxycheck.io/v2/{$ip}?key={$api_key}&vpn=1&asn=1&node=1&tag={$tag}";
        $response = wp_remote_get($url, ['timeout' => 5]);

        if (is_wp_error($response)) {
            error_log('PCR DEBUG: Proxycheck API call failed: ' . $response->get_error_message());
            return;
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);
        error_log('PCR DEBUG: Proxycheck response: ' . print_r($body, true));

        // Check if IP data exists in response
        if (isset($body[$ip]) && is_array($body[$ip])) {
            $is_proxy = pcr_should_block_ip($body[$ip]);
            pcr_update_ip_cache($ip, $ip_hash, $is_proxy);
        } else {
            error_log('PCR DEBUG: No valid IP data in response');
            $is_proxy = false;
        }
    }

    if ($is_proxy) {
        $current_url = (is_ssl() ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        error_log('PCR DEBUG: Redirecting to block page');
        wp_redirect(PCR_BLOCK_URL . urlencode($current_url), 307);
        exit;
    } else {
        error_log('PCR DEBUG: Visitor is not a proxy or is whitelisted');
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
