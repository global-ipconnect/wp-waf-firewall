<?php
/**
 * Visitor logging functions
 * Handles comprehensive logging of all site visitors
 */

if (!defined('ABSPATH')) exit;

// Global variables for logging
global $pcr_visitor_logged, $pcr_http_status, $pcr_request_start_time;
$pcr_visitor_logged = false;
$pcr_http_status = 200;
$pcr_request_start_time = microtime(true);

/**
 * Log visitor information to database
 */
function pcr_ac_log_visitor($url, $ip, $user_agent, $http_code, $username = null, $request_method = 'GET') {
    global $wpdb;
    
    // Ensure WordPress database is available
    if (!isset($wpdb) || !is_object($wpdb)) {
        return false;
    }
    
    $table_name = $wpdb->prefix . PCR_VISITOR_LOG_TABLE;
    
    // Verify table exists before attempting insert
    $table_check = $wpdb->get_var("SHOW TABLES LIKE '$table_name'");
    if ($table_check !== $table_name) {
        return false; // Table doesn't exist
    }

    // Get hostname from cache (transient with 24-hour TTL)
    $hostname_key = 'pcr_hostname_' . md5($ip);
    $hostname = get_transient($hostname_key);
    
    if ($hostname === false) {
        $hostname = pcr_ac_get_ip_hostname($ip);
        // Cache for 24 hours
        set_transient($hostname_key, $hostname ? $hostname : '', 86400);
    }
    
    // Capture referrer
    $referrer = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : null;
    
    // Capture request data (POST and GET parameters)
    $request_data = array();
    if (!empty($_POST)) {
        // Sanitize sensitive data before logging (PII, passwords, payment info, etc.)
        $post_data = pcr_ac_sanitize_sensitive_data($_POST);
        $request_data['POST'] = $post_data;
    }
    if (!empty($_GET)) {
        // Sanitize GET parameters as well
        $get_data = pcr_ac_sanitize_sensitive_data($_GET);
        $request_data['GET'] = $get_data;
    }
    $request_data_json = !empty($request_data) ? json_encode($request_data) : null;
    
    // Capture important headers
    $headers = array();
    if (isset($_SERVER['HTTP_ACCEPT'])) $headers['Accept'] = $_SERVER['HTTP_ACCEPT'];
    if (isset($_SERVER['HTTP_ACCEPT_LANGUAGE'])) $headers['Accept-Language'] = $_SERVER['HTTP_ACCEPT_LANGUAGE'];
    if (isset($_SERVER['HTTP_ACCEPT_ENCODING'])) $headers['Accept-Encoding'] = $_SERVER['HTTP_ACCEPT_ENCODING'];
    if (isset($_SERVER['HTTP_CONNECTION'])) $headers['Connection'] = $_SERVER['HTTP_CONNECTION'];
    if (isset($_SERVER['HTTP_HOST'])) $headers['Host'] = $_SERVER['HTTP_HOST'];
    if (isset($_SERVER['HTTP_UPGRADE_INSECURE_REQUESTS'])) $headers['Upgrade-Insecure-Requests'] = $_SERVER['HTTP_UPGRADE_INSECURE_REQUESTS'];
    if (isset($_SERVER['HTTP_SEC_FETCH_DEST'])) $headers['Sec-Fetch-Dest'] = $_SERVER['HTTP_SEC_FETCH_DEST'];
    if (isset($_SERVER['HTTP_SEC_FETCH_MODE'])) $headers['Sec-Fetch-Mode'] = $_SERVER['HTTP_SEC_FETCH_MODE'];
    if (isset($_SERVER['HTTP_SEC_FETCH_SITE'])) $headers['Sec-Fetch-Site'] = $_SERVER['HTTP_SEC_FETCH_SITE'];
    $headers_json = !empty($headers) ? json_encode($headers) : null;
    
    // Detect if request is suspicious (pass username to check admin status)
    $is_suspicious = pcr_ac_is_suspicious_request($url, $user_agent, $http_code, $request_method, $username) ? 1 : 0;
    
    // Check for threat detection
    global $pcr_threat_detected;
    $threat_detected = 0;
    $threat_type = null;
    $threat_name = null;
    $threat_data = null;
    $threat_severity = null;
    
    if (!empty($pcr_threat_detected) && is_array($pcr_threat_detected)) {
        $threat_detected = 1;
        $threat_type = isset($pcr_threat_detected['threat_type']) ? (int)$pcr_threat_detected['threat_type'] : null;
        $threat_name = isset($pcr_threat_detected['threat_name']) ? substr($pcr_threat_detected['threat_name'], 0, 100) : null;
        $threat_data = isset($pcr_threat_detected['threat_data']) ? $pcr_threat_detected['threat_data'] : null;
        $threat_severity = isset($pcr_threat_detected['severity']) ? substr($pcr_threat_detected['severity'], 0, 20) : null;
    }

    // Insert the log entry
    $result = $wpdb->insert(
        $table_name,
        array(
            'visit_time' => current_time('mysql', 1),
            'url_request' => substr($url, 0, 2048), // Ensure we don't exceed column limit
            'ip_address' => $ip,
            'ip_hostname' => $hostname ? substr($hostname, 0, 255) : null,
            'user_agent_raw' => $user_agent,
            'user_agent_parsed' => pcr_ac_parse_user_agent($user_agent),
            'http_code' => (int)$http_code,
            'username' => $username ? substr($username, 0, 255) : null,
            'request_method' => substr($request_method, 0, 10),
            'is_suspicious' => $is_suspicious,
            'threat_detected' => $threat_detected,
            'threat_type' => $threat_type,
            'threat_name' => $threat_name,
            'threat_data' => $threat_data,
            'threat_severity' => $threat_severity,
            'referrer' => $referrer ? substr($referrer, 0, 2048) : null,
            'request_data' => $request_data_json,
            'request_headers' => $headers_json,
        ),
        array('%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%d', '%d', '%d', '%s', '%s', '%s', '%s', '%s', '%s')
    );
    
    // Suppress errors silently - we don't want logging to break the site
    if ($result === false && defined('WP_DEBUG') && WP_DEBUG) {
        error_log('PCR Visitor Log Error: ' . $wpdb->last_error);
    }
    
    return $result !== false;
}

/**
 * Capture HTTP status code as it's set
 */
function pcr_ac_capture_status_code($status_header, $code) {
    global $pcr_http_status;
    $pcr_http_status = $code;
    return $status_header;
}

/**
 * Initialize logging hooks early
 */
function pcr_ac_init_logging() {
    static $initialized = false;
    if ($initialized) {
        return;
    }
    $initialized = true;
    
    // Only skip WordPress admin dashboard pages
    if (is_admin() && !defined('DOING_AJAX')) {
        return;
    }
    
    // Hook into shutdown with high priority
    add_action('shutdown', 'pcr_ac_log_on_shutdown', 999);
}

/**
 * Main shutdown logging function
 */
function pcr_ac_log_on_shutdown() {
    pcr_ac_perform_logging();
}

/**
 * Fallback shutdown function (registered globally)
 */
function pcr_ac_log_on_shutdown_final() {
    pcr_ac_perform_logging();
}

/**
 * Central logging function - performs the actual logging
 */
function pcr_ac_perform_logging() {
    global $pcr_visitor_logged, $pcr_http_status;
    
    // Only log once per request
    if ($pcr_visitor_logged) {
        return;
    }
    
    // Only skip WordPress admin dashboard pages (but allow AJAX)
    if (defined('WP_ADMIN') && WP_ADMIN && !defined('DOING_AJAX')) {
        return;
    }

    $ip = pcr_ac_get_real_ip();
    if (!$ip) {
        return;
    }

    $current_url = (is_ssl() ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
    $request_method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';
    
    // Get username if logged in (first + last name, or email)
    $username = null;
    if (function_exists('is_user_logged_in') && is_user_logged_in()) {
        $current_user = wp_get_current_user();
        if ($current_user) {
            $username = pcr_ac_get_user_display_name($current_user);
        }
    }

    // Use captured status code, default to 200
    $http_code = $pcr_http_status;
    
    // Check for 404 if WordPress is fully loaded
    if (function_exists('is_404') && is_404()) {
        $http_code = 404;
    }

    pcr_ac_log_visitor($current_url, $ip, $user_agent, $http_code, $username, $request_method);
    $pcr_visitor_logged = true;
}

/**
 * Log before wp_redirect() is called (since it calls exit)
 */
function pcr_ac_log_before_redirect($location, $status) {
    global $pcr_visitor_logged;
    
    // Skip if already logged
    if ($pcr_visitor_logged) {
        return $location;
    }

    // Only skip WordPress admin dashboard pages (but allow AJAX)
    if (defined('WP_ADMIN') && WP_ADMIN && !defined('DOING_AJAX')) {
        return $location;
    }

    $ip = pcr_ac_get_real_ip();
    if (!$ip) {
        return $location;
    }

    $current_url = (is_ssl() ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
    $request_method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';
    
    $username = null;
    if (function_exists('is_user_logged_in') && is_user_logged_in()) {
        $current_user = wp_get_current_user();
        if ($current_user) {
            $username = pcr_ac_get_user_display_name($current_user);
        }
    }

    pcr_ac_log_visitor($current_url, $ip, $user_agent, $status, $username, $request_method);
    $pcr_visitor_logged = true;
    
    return $location;
}
