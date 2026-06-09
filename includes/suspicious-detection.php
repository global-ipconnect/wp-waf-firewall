<?php
/**
 * Suspicious request detection
 * Identifies potentially malicious or scanning activity
 */

if (!defined('ABSPATH')) exit;

/**
 * Detect if request is suspicious based on URL patterns, user agent, and HTTP code
 * Excludes admin users and WordPress internal requests from suspicious flagging
 */
function pcr_ac_is_suspicious_request($url, $user_agent, $http_code, $request_method, $username = null) {
    $suspicious = false;
    $url_lower = strtolower($url);
    $ua_lower = strtolower($user_agent);
    
    // WordPress internal requests are never suspicious
    if (strpos($url_lower, 'wp-cron.php') !== false) {
        return false; // WordPress cron system
    }
    
    // Admin-ajax.php is legitimate for logged-in users
    if (strpos($url_lower, 'admin-ajax.php') !== false) {
        // Heartbeat, autosave, and other admin-ajax actions from logged-in users are not suspicious
        if ($username) {
            return false;
        }
    }
    
    // If user is logged in as admin, don't flag wp-admin requests as suspicious
    $is_admin_user = false;
    if ($username) {
        // User is logged in - check if they're an admin
        $user = get_user_by('email', $username);
        if (!$user) {
            $user = get_user_by('login', $username);
        }
        if ($user && ($user->has_cap('administrator') || $user->has_cap('manage_options'))) {
            $is_admin_user = true;
        }
    }
    
    // Suspicious URL patterns (common attack vectors)
    // Note: wp-admin URLs are excluded if user is authenticated admin
    $suspicious_patterns = array(
        'wp-config.php',
        '.env',
        'phpinfo',
        '/admin',
        'xmlrpc.php',
        '.git/',
        '.svn/',
        '.sql',
        '.bak',
        '.backup',
        'eval(',
        'base64',
        'exec(',
        'passthru(',
        'shell_exec(',
        'system(',
        '../',
        '..\\',
        'union select',
        'concat(',
        "or '1'='1",
        "or 1=1",
        'drop table',
        'information_schema',
        '<script',
        'javascript:',
        'onerror=',
        'onload=',
        '/etc/passwd',
        '/proc/self',
        'cmd.exe',
        'powershell',
    );
    
    foreach ($suspicious_patterns as $pattern) {
        if (strpos($url_lower, $pattern) !== false) {
            $suspicious = true;
            break;
        }
    }
    
    // Check wp-admin and wp-login separately (only flag if not admin user)
    if (!$is_admin_user) {
        if (strpos($url_lower, 'wp-admin') !== false && strpos($url_lower, 'admin-ajax.php') === false) {
            // Only flag wp-admin access for non-admin users (excluding heartbeat/autosave)
            $suspicious = true;
        }
        if (strpos($url_lower, 'wp-login.php') !== false && in_array($http_code, array(401, 403))) {
            // Failed login attempts (non-admin users only)
            $suspicious = true;
        }
    }
    
    // XMLRPC requests are often used for attacks (always flag these)
    if (strpos($url_lower, 'xmlrpc.php') !== false) {
        $suspicious = true;
    }
    
    // Scanning user agents
    $scanner_ua = array(
        'nikto',
        'nmap',
        'masscan',
        'nessus',
        'sqlmap',
        'metasploit',
        'havij',
        'acunetix',
        'burp',
        'w3af',
        'webscarab',
        'appscan',
        'grabber',
        'libwww-perl',
        'python-requests',
        'python-urllib',
        'java/',
        'curl/',
        'wget',
        'scanner',
        'bot' // Generic bot pattern
    );
    
    foreach ($scanner_ua as $scanner) {
        if (strpos($ua_lower, $scanner) !== false) {
            // Whitelist legitimate bots
            if (!preg_match('/(googlebot|bingbot|duckduckbot|bravesearchbot|slackbot|telegrambot|whatsapp)/i', $user_agent)) {
                $suspicious = true;
                break;
            }
        }
    }
    
    // POST requests to non-standard endpoints (excluding wp-admin, wp-login, comments, cron)
    if ($request_method === 'POST' && strpos($url_lower, 'wp-admin') === false && strpos($url_lower, 'wp-login.php') === false && strpos($url_lower, 'wp-comments-post.php') === false && strpos($url_lower, 'admin-ajax.php') === false && strpos($url_lower, 'wp-cron.php') === false) {
        if (strpos($url_lower, '.php') !== false || strpos($url_lower, 'admin') !== false) {
            $suspicious = true;
        }
    }
    
    // Very long URLs (potential buffer overflow attempts)
    if (strlen($url) > 1000) {
        $suspicious = true;
    }
    
    // 403, 401 errors (unauthorized access attempts) - but not for admin users
    if (!$is_admin_user && in_array($http_code, array(401, 403))) {
        // Don't flag legitimate WordPress endpoints
        if (strpos($url_lower, 'admin-ajax.php') === false && strpos($url_lower, 'wp-cron.php') === false) {
            $suspicious = true;
        }
    }
    
    return $suspicious;
}
