<?php
/**
 * Advanced Threat Detection System
 * Inspired by WP Cerber's vulnerability scanning detection
 * 
 * Detection Types:
 * - PHP Code Injection (using tokenization)
 * - SQL Injection (pattern matching with scoring)
 * - Non-existent PHP file scanning
 * - Malicious file uploads
 * - Directory traversal
 * - Base64 obfuscation (recursive decoding)
 * - JavaScript injection
 */

if (!defined('ABSPATH')) exit;

// Threat reason codes
define('PCR_THREAT_PHP_INJECTION', 101);
define('PCR_THREAT_SQL_INJECTION', 102);
define('PCR_THREAT_PHP_SCAN', 103);
define('PCR_THREAT_FILE_UPLOAD', 104);
define('PCR_THREAT_XSS', 105);
define('PCR_THREAT_TRAVERSAL', 106);
define('PCR_THREAT_OBFUSCATION', 107);

/**
 * Main threat detection orchestrator
 * Checks all enabled detection methods
 * 
 * @return array|false Detection result or false if clean
 */
function pcr_threat_detect_request() {
    $settings = pcr_threat_get_settings();
    $result = false;
    
    // Check if IP is whitelisted
    if (pcr_threat_is_ip_whitelisted()) {
        return false;
    }
    
    // 1. Non-existent PHP script scanning detection
    if ($settings['detect_php_scan']) {
        if ($scan_result = pcr_threat_detect_php_scanning()) {
            $result = $scan_result;
        }
    }
    
    // 2. Request field inspection (GET/POST)
    if ($settings['detect_php_injection'] || $settings['detect_sql_injection'] || $settings['detect_xss']) {
        if ($field_result = pcr_threat_inspect_request_fields($settings)) {
            $result = $field_result;
        }
    }
    
    // 3. File upload inspection
    if ($settings['detect_file_upload'] && !empty($_FILES)) {
        if ($upload_result = pcr_threat_inspect_uploads($settings)) {
            $result = $upload_result;
        }
    }
    
    return $result;
}

/**
 * Check if current IP is whitelisted
 */
function pcr_threat_is_ip_whitelisted() {
    $settings = pcr_threat_get_settings();
    $whitelist = $settings['ip_whitelist'];
    
    if (empty($whitelist)) {
        return false;
    }
    
    $current_ip = pcr_ac_get_client_ip();
    $whitelist_array = array_map('trim', explode("\n", $whitelist));
    
    foreach ($whitelist_array as $whitelisted) {
        if (empty($whitelisted)) continue;
        
        // Exact match
        if ($whitelisted === $current_ip) {
            return true;
        }
        
        // CIDR notation support
        if (strpos($whitelisted, '/') !== false) {
            if (pcr_threat_ip_in_range($current_ip, $whitelisted)) {
                return true;
            }
        }
        
        // Wildcard support (e.g., 192.168.1.*)
        if (strpos($whitelisted, '*') !== false) {
            // Validate that the whitelisted value only contains IP-like characters
            if (!preg_match('/^[0-9.*]+$/', $whitelisted)) {
                continue; // Skip invalid entries
            }
            $pattern = str_replace(['.', '*'], ['\.', '.*'], $whitelisted);
            if (@preg_match("/^{$pattern}$/", $current_ip)) {
                return true;
            }
        }
    }
    
    return false;
}

/**
 * Check if IP is in CIDR range
 */
function pcr_threat_ip_in_range($ip, $cidr) {
    // Validate CIDR format
    if (strpos($cidr, '/') === false) {
        return false;
    }
    
    $parts = explode('/', $cidr);
    if (count($parts) !== 2) {
        return false;
    }
    
    list($subnet, $mask) = $parts;
    
    // Validate mask range
    $mask = (int)$mask;
    if ($mask < 0 || $mask > 32) {
        return false;
    }
    
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && 
        filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        $mask_long = -1 << (32 - $mask);
        return ($ip_long & $mask_long) === ($subnet_long & $mask_long);
    }
    
    return false;
}

/**
 * Detect scanning for non-existent PHP files
 * This catches vulnerability scanners probing for backdoors
 */
function pcr_threat_detect_php_scanning() {
    $uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    
    // Ignore legitimate WordPress scripts
    $wp_scripts = [
        '/wp-login.php',
        '/wp-signup.php',
        '/wp-activate.php',
        '/wp-cron.php',
        '/xmlrpc.php',
        '/wp-trackback.php',
        '/wp-comments-post.php',
        '/index.php'
    ];
    
    // Check if it's a PHP file request
    if (preg_match('/\.php$/i', $uri)) {
        // Normalize path
        $normalized = rtrim($uri, '/');
        
        // Check if it's not a known WP script
        $is_wp_script = false;
        foreach ($wp_scripts as $script) {
            if (strpos($normalized, $script) !== false) {
                $is_wp_script = true;
                break;
            }
        }
        
        // Check if file exists
        if (!$is_wp_script) {
            $file_path = ABSPATH . ltrim($uri, '/');
            $exists = file_exists($file_path);
            if (!$exists) {
                return [
                    'threat_type' => PCR_THREAT_PHP_SCAN,
                    'threat_name' => 'PHP Script Scanning',
                    'threat_data' => "Request for non-existent PHP file: {$uri}",
                    'severity' => 'high'
                ];
            }
        }

    }
    
    return false;
}

/**
 * Inspect GET and POST request fields for malicious code
 */
function pcr_threat_inspect_request_fields($settings) {
    $found = false;
    
    // Whitelist common WordPress fields
    $whitelist = ['s', 'search', 'comment', 'post_content'];
    
    // Inspect GET parameters (stricter)
    if (!empty($_GET)) {
        $found = pcr_threat_inspect_array($_GET, $whitelist, $settings, 'GET');
        if ($found) return $found;
    }
    
    // Inspect POST parameters (more lenient)
    if (!empty($_POST)) {
        $found = pcr_threat_inspect_array($_POST, $whitelist, $settings, 'POST');
        if ($found) return $found;
    }
    
    return false;
}

/**
 * Recursively inspect array for threats
 */
function pcr_threat_inspect_array($array, $whitelist, $settings, $context) {
    foreach ($array as $key => $value) {
        // Skip whitelisted fields
        if (in_array($key, $whitelist)) {
            continue;
        }
        
        if (is_array($value)) {
            $result = pcr_threat_inspect_array($value, $whitelist, $settings, $context);
            if ($result) return $result;
        } else {
            $result = pcr_threat_inspect_value($value, $settings, $context);
            if ($result) return $result;
        }
    }
    
    return false;
}

/**
 * Inspect individual value for threats
 * Supports recursive base64 decoding
 */
function pcr_threat_inspect_value($value, $settings, $context, $depth = 0) {
    // Prevent infinite recursion
    if ($depth > 30) {
        return [
            'threat_type' => PCR_THREAT_OBFUSCATION,
            'threat_name' => 'Deep Obfuscation',
            'threat_data' => 'Excessive base64 encoding depth detected',
            'severity' => 'high'
        ];
    }
    
    // Check for base64 encoding
    if (strlen($value) > 50 && pcr_threat_is_base64($value)) {
        $decoded = base64_decode($value, true);
        if ($decoded !== false) {
            return pcr_threat_inspect_value($decoded, $settings, $context, $depth + 1);
        }
    }
    
    // PHP code injection detection
    if ($settings['detect_php_injection']) {
        $php_result = pcr_threat_detect_php_code($value);
        if ($php_result) {
            return $php_result;
        }
    }
    
    // SQL injection detection
    if ($settings['detect_sql_injection']) {
        $sql_result = pcr_threat_detect_sql_injection($value, $context);
        if ($sql_result) {
            return $sql_result;
        }
    }
    
    // XSS detection
    if ($settings['detect_xss']) {
        $xss_result = pcr_threat_detect_xss($value);
        if ($xss_result) {
            return $xss_result;
        }
    }
    
    // Directory traversal
    $traversal_result = pcr_threat_detect_traversal($value);
    if ($traversal_result) {
        return $traversal_result;
    }
    
    return false;
}

/**
 * Detect if string is likely base64 encoded
 */
function pcr_threat_is_base64($str) {
    if (preg_match('/^[a-zA-Z0-9\/\r\n+]*={0,2}$/', $str)) {
        $decoded = base64_decode($str, true);
        if ($decoded !== false && base64_encode($decoded) === $str) {
            // Check if decoded content looks suspicious
            if (preg_match('/[^\x20-\x7E\t\r\n]/', $decoded) === 0) {
                return true;
            }
        }
    }
    return false;
}

/**
 * Detect PHP code injection using tokenization
 * More accurate than regex-only approaches
 */
function pcr_threat_detect_php_code($value) {
    // Unsafe PHP functions
    $unsafe_functions = [
        'eval' => 'Code Execution',
        'assert' => 'Code Execution',
        'create_function' => 'Code Execution',
        'system' => 'System Command',
        'exec' => 'System Command',
        'passthru' => 'System Command',
        'shell_exec' => 'System Command',
        'proc_open' => 'Process Control',
        'popen' => 'Process Control',
        'pcntl_exec' => 'Process Control',
        'include' => 'File Inclusion',
        'require' => 'File Inclusion',
        'include_once' => 'File Inclusion',
        'require_once' => 'File Inclusion',
        'file_get_contents' => 'File Access',
        'file_put_contents' => 'File Access',
        'fopen' => 'File Access',
        'readfile' => 'File Access',
        'gzinflate' => 'Obfuscation',
        'str_rot13' => 'Obfuscation',
        'base64_decode' => 'Obfuscation'
    ];
    
    // Remove comments
    $clean = preg_replace([
        '/\/\*.*?\*\//s',  // Multi-line comments
        '/\/\/.*$/m',       // Single-line comments
        '/#.*$/m'           // Shell-style comments
    ], '', $value);
    
    // Tokenize
    $tokens = @token_get_all('<?php ' . $clean);
    
    if (is_array($tokens)) {
        foreach ($tokens as $token) {
            if (is_array($token) && $token[0] === T_STRING) {
                $func_name = strtolower($token[1]);
                if (isset($unsafe_functions[$func_name])) {
                    // Check for function call pattern: func_name(args)
                    if (preg_match('/' . preg_quote($func_name, '/') . '\s*\((?!\s*\))/i', $clean)) {
                        return [
                            'threat_type' => PCR_THREAT_PHP_INJECTION,
                            'threat_name' => 'PHP Code Injection',
                            'threat_data' => "Dangerous function detected: {$func_name}() - {$unsafe_functions[$func_name]}",
                            'severity' => 'critical'
                        ];
                    }
                }
            }
        }
    }
    
    return false;
}

/**
 * Detect SQL injection with scoring system
 * Context-aware: GET params are stricter than POST
 */
function pcr_threat_detect_sql_injection($value, $context) {
    $score = 0;
    $str_upper = strtoupper($value);
    
    // Remove SQL comments
    $cleaned = preg_replace('/\/\*.*?\*\//s', '', $value);
    
    // SQL keywords
    if (preg_match('/\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE)\b/i', $cleaned)) {
        $score += 2;
        
        // UNION-based injection (immediate block for GET)
        if (preg_match('/\bUNION\b/i', $str_upper)) {
            $score += 3;
            if ($context === 'GET') {
                return [
                    'threat_type' => PCR_THREAT_SQL_INJECTION,
                    'threat_name' => 'SQL Injection',
                    'threat_data' => 'UNION-based SQL injection detected',
                    'severity' => 'critical'
                ];
            }
        }
        
        // Database enumeration
        if (preg_match('/\b(information_schema|wp_users|wp_usermeta|mysql\.user|sysobjects|syscolumns)\b/i', $value)) {
            return [
                'threat_type' => PCR_THREAT_SQL_INJECTION,
                'threat_name' => 'SQL Injection',
                'threat_data' => 'Database enumeration attempt detected',
                'severity' => 'critical'
            ];
        }
        
        // File operations
        if (preg_match('/\b(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE|xp_cmdshell)\b/i', $value)) {
            return [
                'threat_type' => PCR_THREAT_SQL_INJECTION,
                'threat_name' => 'SQL Injection',
                'threat_data' => 'SQL file operation detected',
                'severity' => 'critical'
            ];
        }
        
        // Obfuscation techniques
        if (preg_match('/\b(CHAR|CHR|CONCAT|CONCAT_WS|GROUP_CONCAT|name_const|unhex)\b/i', $value)) {
            $score += 2;
        }
        
        // Multiple CHAR() calls indicate obfuscation
        if (substr_count($str_upper, 'CHAR(') > 1) {
            return [
                'threat_type' => PCR_THREAT_SQL_INJECTION,
                'threat_name' => 'SQL Injection',
                'threat_data' => 'SQL obfuscation with CHAR() detected',
                'severity' => 'high'
            ];
        }
    }
    
    // Classic SQL injection patterns
    if (preg_match("/(OR|AND)\s*['\"]?\s*\d+\s*['\"]?\s*=\s*['\"]?\s*\d+/i", $value)) {
        $score += 3;
    }
    
    // Comment-based injection
    if (preg_match('/(--|\#|\/\*|\*\/)/', $value) && preg_match('/\b(SELECT|UNION|WHERE)\b/i', $value)) {
        $score += 2;
    }
    
    // Threshold
    if ($score >= 4) {
        return [
            'threat_type' => PCR_THREAT_SQL_INJECTION,
            'threat_name' => 'SQL Injection',
            'threat_data' => "SQL injection patterns detected (score: {$score})",
            'severity' => 'high'
        ];
    }
    
    return false;
}

/**
 * Detect XSS (Cross-Site Scripting)
 */
function pcr_threat_detect_xss($value) {
    // Script tags
    if (preg_match('/<script[^>]*>.*?<\/script>/is', $value)) {
        return [
            'threat_type' => PCR_THREAT_XSS,
            'threat_name' => 'Cross-Site Scripting',
            'threat_data' => 'Script tag detected',
            'severity' => 'high'
        ];
    }
    
    // Event handlers
    if (preg_match('/\bon(load|error|click|mouse|focus|blur|change|submit)\s*=/i', $value)) {
        return [
            'threat_type' => PCR_THREAT_XSS,
            'threat_name' => 'Cross-Site Scripting',
            'threat_data' => 'JavaScript event handler detected',
            'severity' => 'high'
        ];
    }
    
    // JavaScript protocol
    if (preg_match('/javascript\s*:/i', $value)) {
        return [
            'threat_type' => PCR_THREAT_XSS,
            'threat_name' => 'Cross-Site Scripting',
            'threat_data' => 'JavaScript protocol detected',
            'severity' => 'medium'
        ];
    }
    
    return false;
}

/**
 * Detect directory traversal attempts
 */
function pcr_threat_detect_traversal($value) {
    // Path traversal patterns
    if (preg_match('/\.\.[\/\\\\]/', $value)) {
        return [
            'threat_type' => PCR_THREAT_TRAVERSAL,
            'threat_name' => 'Directory Traversal',
            'threat_data' => 'Path traversal pattern detected',
            'severity' => 'high'
        ];
    }
    
    // Sensitive file access
    if (preg_match('/\/(etc\/passwd|etc\/shadow|windows\/system|proc\/self)/i', $value)) {
        return [
            'threat_type' => PCR_THREAT_TRAVERSAL,
            'threat_name' => 'Directory Traversal',
            'threat_data' => 'Sensitive file access attempt detected',
            'severity' => 'critical'
        ];
    }
    
    return false;
}

/**
 * Inspect uploaded files for malicious code
 */
function pcr_threat_inspect_uploads($settings) {
    if (empty($_FILES)) {
        return false;
    }
    
    foreach ($_FILES as $file_field) {
        if (is_array($file_field['tmp_name'])) {
            // Multiple files
            foreach ($file_field['tmp_name'] as $index => $tmp_name) {
                $result = pcr_threat_inspect_single_upload($tmp_name, $file_field['name'][$index], $settings);
                if ($result) return $result;
            }
        } else {
            // Single file
            $result = pcr_threat_inspect_single_upload($file_field['tmp_name'], $file_field['name'], $settings);
            if ($result) return $result;
        }
    }
    
    return false;
}

/**
 * Inspect a single uploaded file
 */
function pcr_threat_inspect_single_upload($tmp_name, $original_name, $settings) {
    if (!file_exists($tmp_name) || !is_readable($tmp_name)) {
        return false;
    }
    
    // Read first 100KB
    $handle = fopen($tmp_name, 'r');
    if (!$handle) return false;
    
    $content = fread($handle, 100000);
    fclose($handle);
    
    // Inspect content
    $result = pcr_threat_inspect_value($content, $settings, 'UPLOAD');
    
    if ($result) {
        // Auto-delete malicious file
        @unlink($tmp_name);
        
        $result['threat_data'] = "Malicious file upload: {$original_name}. " . $result['threat_data'];
        $result['threat_type'] = PCR_THREAT_FILE_UPLOAD;
        $result['threat_name'] = 'Malicious File Upload';
        
        return $result;
    }
    
    return false;
}

/**
 * Get threat detection settings
 */
function pcr_threat_get_settings() {
    $defaults = [
        'enabled' => false,
        'detect_php_injection' => true,
        'detect_sql_injection' => true,
        'detect_php_scan' => true,
        'detect_file_upload' => true,
        'detect_xss' => true,
        'detect_traversal' => true,
        'block_on_detect' => true,
        'log_threats' => true,
        'auto_block_ip' => false,
        'email_on_critical' => false,
        'recursive_base64' => true,
        'redirect_to_access_control' => false,
        'ip_whitelist' => '',
        'url_whitelist' => '',
        'field_whitelist' => '',
        'notification_email' => get_option('admin_email'),
        'block_http_code' => '403',
        'auto_block_threshold' => 3,
        'auto_block_period' => 10
        ,'visitor_log_retention_days' => 30
    ];
    
    $saved = get_option('pcr_threat_settings', []);
    return array_merge($defaults, $saved);
}

/**
 * Save threat detection settings
 */
function pcr_threat_save_settings($settings) {
    return update_option('pcr_threat_settings', $settings);
}
