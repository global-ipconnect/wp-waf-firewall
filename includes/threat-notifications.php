<?php
/**
 * Threat notification helper functions
 */

if (!defined('ABSPATH')) exit;

/**
 * Send email notification about detected threat
 */
function pcr_threat_send_notification($threat_result) {
    $settings = pcr_threat_get_settings();
    $email = !empty($settings['notification_email']) ? $settings['notification_email'] : get_option('admin_email');
    
    if (empty($email)) {
        return;
    }
    
    $ip = pcr_ac_get_client_ip();
    $url = $_SERVER['REQUEST_URI'] ?? 'Unknown';
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    $timestamp = current_time('mysql');
    
    $subject = sprintf('[%s] Critical Threat Detected', get_bloginfo('name'));
    
    $message = "A critical security threat has been detected and blocked on your website.\n\n";
    $message .= "=== THREAT DETAILS ===\n";
    $message .= "Threat Type: {$threat_result['threat_name']}\n";
    $message .= "Severity: " . strtoupper($threat_result['severity']) . "\n";
    $message .= "Details: {$threat_result['threat_data']}\n\n";
    
    $message .= "=== REQUEST INFORMATION ===\n";
    $message .= "IP Address: {$ip}\n";
    $message .= "URL: {$url}\n";
    $message .= "User Agent: {$user_agent}\n";
    $message .= "Timestamp: {$timestamp}\n\n";
    
    $message .= "=== ACTIONS TAKEN ===\n";
    $message .= "✓ Request blocked\n";
    $message .= "✓ Logged to visitor logs\n\n";
    
    $message .= "Review the full details in your WordPress admin:\n";
    $message .= admin_url('tools.php?page=pcr_visitor_logs&filter_suspicious=1') . "\n\n";
    
    $message .= "---\n";
    $message .= "Global IPconnect Access Control Plugin\n";
    $message .= "Threat Detection System\n";
    
    $headers = ['Content-Type: text/plain; charset=UTF-8'];
    
    wp_mail($email, $subject, $message, $headers);
}
