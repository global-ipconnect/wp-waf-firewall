<?php
/**
 * Core access control logic
 * Handles IP checking, caching, and blocking decisions
 */

if (!defined('ABSPATH')) exit;

/**
 * Main redirect logic - checks IP against proxycheck.io and blocks if needed
 */
add_action('template_redirect', function () {
    if (is_admin() || !get_option(PCR_SETUP_DONE)) return;
    
    // === THREAT DETECTION CHECK (runs first) ===
    $threat_settings = pcr_threat_get_settings();
    if (!empty($threat_settings['enabled'])) {
        $threat_result = pcr_threat_detect_request();
        if ($threat_result && !empty($threat_settings['block_on_detect'])) {
            // Log the threat if logging is enabled
            if (!empty($threat_settings['log_threats'])) {
                global $pcr_threat_detected;
                $pcr_threat_detected = $threat_result;
            }
            
            // Send email notification for critical threats
            if (!empty($threat_settings['email_on_critical']) && 
                in_array($threat_result['severity'], ['critical', 'high'])) {
                pcr_threat_send_notification($threat_result);
            }
            
            // Check if redirect to access control is enabled
            if (!empty($threat_settings['redirect_to_access_control'])) {
                // Build current URL being accessed
                $current_url = (is_ssl() ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
                
                // Build redirect URL with correct parameters for access.global-ipconnect.com
                $block_url = 'https://access.global-ipconnect.com/403/';
                $params = sprintf(
                    'source=%s&from=%s&reason=%s',
                    urlencode('plugin'),
                    urlencode($current_url),
                    urlencode($threat_result['threat_name'])
                );
                $redirect_url = $block_url . '?' . $params;
                
                // Use 307 redirect and exit
                wp_redirect($redirect_url, 307);
                exit;
            }
            
            // Block the request directly
            $http_code = !empty($threat_settings['block_http_code']) ? $threat_settings['block_http_code'] : 403;
            status_header($http_code);
            nocache_headers();
            echo '<!DOCTYPE html><html><head><title>Request Blocked</title></head><body>';
            echo '<h1>Access Denied</h1>';
            echo '<p>Your request has been blocked for security reasons.</p>';
            echo '<p>Threat Type: ' . esc_html($threat_result['threat_name']) . '</p>';
            echo '<p>Reference ID: ' . esc_html(substr(md5(time() . $_SERVER['REMOTE_ADDR']), 0, 12)) . '</p>';
            echo '</body></html>';
            exit;
        }
    }

    $current_url = (is_ssl() ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
    
    // Check for outdated browsers
    if (!pcr_ac_is_search_bot_user_agent($user_agent)
        && !pcr_ac_is_wordpress_user_agent($user_agent)
        && pcr_ac_is_outdated_browser($user_agent)) {
        $redirect_url = PCR_OUTDATED_URL . '?source=plugin&reason=outdated_browser&from=' . urlencode($current_url);
        wp_redirect($redirect_url, 307);
        exit;
    }

    // Get the real IP address (handles Cloudflare and other proxies)
    $ip = pcr_ac_get_real_ip();
    if (!$ip) {
        return;
    }

    $ip_hash = md5($ip);

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
        } else {
            // Cache expired, needs recheck
        }
    }

    if ($needs_check) {
        $api_option = pcr_ac_get_api_option_payload();
        $salt = pcr_ac_get_salt($api_option['salt']);
        if (!$salt) {
            update_option(PCR_SALT_ALERT_OPTION, time());
            return;
        }

        $encrypted_key = $api_option['cipher'];
        $api_key = pcr_ac_decrypt($encrypted_key, $salt);
        if (!$api_key) {
            // Decryption failed - possible tampering
            return;
        }

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
            'sslverify' => true, // Enforce SSL verification
        ));

        if (is_wp_error($response)) {
            $error_code = $response->get_error_code();
            $error_message = $response->get_error_message();
            $is_timeout = in_array($error_code, array('timeout', 'http_request_timeout'), true) || stripos($error_message, 'timed out') !== false;
            if ($is_timeout) {
                pcr_ac_set_timeout_cache($ip_hash, false, 'timeout');
            }
            return;
        }

        $body_raw = wp_remote_retrieve_body($response);
        $body = json_decode($body_raw, true);

        if (!is_array($body)) {
            return;
        }

        $status = isset($body['status']) ? $body['status'] : null;
        if (!in_array($status, array('ok', 'warning'), true)) {
            return;
        }

        $ip_payload = null;
        if (isset($body[$ip]) && is_array($body[$ip])) {
            $ip_payload = $body[$ip];
        } else {
            // The API may normalise the IP (especially IPv6) to a different
            // representation than what was sent. Search response keys for a
            // valid IP entry that matches after normalisation.
            foreach ($body as $key => $value) {
                if (is_array($value) && filter_var($key, FILTER_VALIDATE_IP)) {
                    $ip_payload = $value;
                    break;
                }
            }
        }
        if (!$ip_payload) {
            if (isset($body['address']) && $body['address'] === $ip) {
                $ip_payload = $body;
            } elseif (isset($body['ip']) && is_array($body['ip'])) {
                $ip_payload = $body['ip'];
            }
        }

        if (!$ip_payload || !is_array($ip_payload)) {
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
        // Build proper redirect URL with source, reason, and from parameters
        $reason = $block_reason ? sanitize_text_field($block_reason) : 'proxy';
        $redirect_url = PCR_BLOCK_URL . '?source=plugin&reason=' . urlencode($reason) . '&from=' . urlencode($current_url);
        
        wp_redirect($redirect_url, 307);
        exit;
    }
});
