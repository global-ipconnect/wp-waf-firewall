<?php
/**
 * Threat Detection Settings Admin Page
 * Full-featured settings interface with tabs and sections
 */

if (!defined('ABSPATH')) exit;

/**
 * Handle MU-plugin installation
 */
function pcr_threat_install_muplugin() {
    if (!current_user_can('manage_options')) {
        return ['success' => false, 'message' => 'Insufficient permissions'];
    }
    
    $source_file = plugin_dir_path(dirname(__FILE__)) . 'load-access-control-early.php';
    $mu_plugins_dir = WP_CONTENT_DIR . '/mu-plugins';
    $dest_file = $mu_plugins_dir . '/load-access-control-early.php';
    
    // Check if source file exists
    if (!file_exists($source_file)) {
        return ['success' => false, 'message' => 'Source MU-plugin file not found. Please reinstall the plugin.'];
    }
    
    // Create mu-plugins directory if it doesn't exist
    if (!file_exists($mu_plugins_dir)) {
        if (!wp_mkdir_p($mu_plugins_dir)) {
            return ['success' => false, 'message' => 'Failed to create mu-plugins directory. Check file permissions.'];
        }
    }
    
    // Check if directory is writable
    if (!is_writable($mu_plugins_dir)) {
        return ['success' => false, 'message' => 'The mu-plugins directory is not writable. Please check file permissions.'];
    }
    
    // Copy the file
    if (!copy($source_file, $dest_file)) {
        return ['success' => false, 'message' => 'Failed to copy MU-plugin file. Please check file permissions.'];
    }
    
    // Verify the copy was successful
    if (!file_exists($dest_file)) {
        return ['success' => false, 'message' => 'MU-plugin file copy verification failed.'];
    }
    
    return ['success' => true, 'message' => 'MU-plugin installed successfully! Your plugin now loads before all others.'];
}

/**
 * Handle MU-plugin uninstallation
 */
function pcr_threat_uninstall_muplugin() {
    if (!current_user_can('manage_options')) {
        return ['success' => false, 'message' => 'Insufficient permissions'];
    }
    
    $mu_plugin_file = WP_CONTENT_DIR . '/mu-plugins/load-access-control-early.php';
    
    if (!file_exists($mu_plugin_file)) {
        return ['success' => false, 'message' => 'MU-plugin file not found.'];
    }
    
    if (!unlink($mu_plugin_file)) {
        return ['success' => false, 'message' => 'Failed to remove MU-plugin file. Please check file permissions.'];
    }
    
    return ['success' => true, 'message' => 'MU-plugin uninstalled successfully. Plugin now loads with regular plugins.'];
}

/**
 * Check if MU-plugin is installed
 */
function pcr_threat_is_muplugin_installed() {
    $mu_plugin_file = WP_CONTENT_DIR . '/mu-plugins/load-access-control-early.php';
    return file_exists($mu_plugin_file);
}

/**
 * Render threat detection settings page
 */
function pcr_threat_settings_page() {
    if (!current_user_can('manage_options')) {
        wp_die(__('You do not have sufficient permissions to access this page.'));
    }
    
    // Handle MU-plugin installation FIRST
    if (isset($_POST['pcr_install_muplugin']) && check_admin_referer('pcr_muplugin_action')) {
        $result = pcr_threat_install_muplugin();
        $notice_class = $result['success'] ? 'notice-success' : 'notice-error';
        echo '<div class="notice ' . $notice_class . ' is-dismissible"><p>' . esc_html($result['message']) . '</p></div>';
    }
    
    // Handle MU-plugin uninstallation
    if (isset($_POST['pcr_uninstall_muplugin']) && check_admin_referer('pcr_muplugin_action')) {
        $result = pcr_threat_uninstall_muplugin();
        $notice_class = $result['success'] ? 'notice-success' : 'notice-error';
        echo '<div class="notice ' . $notice_class . ' is-dismissible"><p>' . esc_html($result['message']) . '</p></div>';
    }
    
    // Handle form submission BEFORE loading settings
    if (isset($_POST['pcr_threat_settings_submit'])) {
        $nonce_check = check_admin_referer('pcr_threat_settings_nonce');
        
        if ($nonce_check) {
            pcr_threat_handle_settings_save();
            // Success message is shown inside the save function
        } else {
            echo '<div class="notice notice-error is-dismissible"><p>Security check failed. Please try again.</p></div>';
        }
    }
    
    // Load settings AFTER saving (so we get the fresh values)
    $settings = pcr_threat_get_settings();
    $active_tab = isset($_GET['tab']) ? sanitize_key($_GET['tab']) : 'general';
    
    ?>
    <div class="wrap">
        <h1><?php echo esc_html__('Threat Detection Settings', 'global-ipconnect-access-control'); ?></h1>
        
        <?php
        // MU-Plugin management section (only shown on General tab, OUTSIDE main form to avoid nesting)
        if ($active_tab === 'general') {
            pcr_threat_render_muplugin_section();
        }
        ?>
        
        <h2 class="nav-tab-wrapper">
            <a href="?page=pcr-threat-settings&tab=general" class="nav-tab <?php echo $active_tab === 'general' ? 'nav-tab-active' : ''; ?>">
                <?php _e('General', 'global-ipconnect-access-control'); ?>
            </a>
            <a href="?page=pcr-threat-settings&tab=detection" class="nav-tab <?php echo $active_tab === 'detection' ? 'nav-tab-active' : ''; ?>">
                <?php _e('Detection Types', 'global-ipconnect-access-control'); ?>
            </a>
            <a href="?page=pcr-threat-settings&tab=whitelist" class="nav-tab <?php echo $active_tab === 'whitelist' ? 'nav-tab-active' : ''; ?>">
                <?php _e('Whitelist / Bypass', 'global-ipconnect-access-control'); ?>
            </a>
            <a href="?page=pcr-threat-settings&tab=actions" class="nav-tab <?php echo $active_tab === 'actions' ? 'nav-tab-active' : ''; ?>">
                <?php _e('Actions', 'global-ipconnect-access-control'); ?>
            </a>
        </h2>
        
        <form method="post" action="">
            <?php wp_nonce_field('pcr_threat_settings_nonce'); ?>
            
            <?php
            switch ($active_tab) {
                case 'general':
                    pcr_threat_render_general_tab($settings);
                    break;
                case 'detection':
                    pcr_threat_render_detection_tab($settings);
                    break;
                case 'whitelist':
                    pcr_threat_render_whitelist_tab($settings);
                    break;
                case 'actions':
                    pcr_threat_render_actions_tab($settings);
                    break;
            }
            ?>
            
            <p class="submit">
                <input type="submit" name="pcr_threat_settings_submit" class="button button-primary" 
                       value="<?php esc_attr_e('Save Settings', 'global-ipconnect-access-control'); ?>" />
            </p>
        </form>
    </div>
    
    <style>
        .pcr-settings-section {
            background: #fff;
            border: 1px solid #ccd0d4;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 1px 1px rgba(0,0,0,.04);
        }
        .pcr-settings-section h2 {
            margin-top: 0;
            border-bottom: 1px solid #ddd;
            padding-bottom: 10px;
        }
        .pcr-settings-row {
            margin: 15px 0;
            padding: 10px 0;
        }
        .pcr-settings-row label {
            display: inline-block;
            min-width: 200px;
            font-weight: 600;
        }
        .pcr-settings-row .description {
            display: block;
            margin: 5px 0 0 0;
            color: #666;
            font-style: italic;
        }
        .pcr-threat-critical { color: #dc3232; font-weight: bold; }
        .pcr-threat-high { color: #f56e28; font-weight: bold; }
        .pcr-threat-medium { color: #f0b849; font-weight: bold; }
        .pcr-threat-info { color: #00a0d2; }
        textarea.large-text {
            width: 100%;
            max-width: 600px;
            height: 150px;
            font-family: monospace;
        }
    </style>
    <?php
}

/**
 * Render MU-Plugin management section (separate from main form)
 */
function pcr_threat_render_muplugin_section() {
    $is_mu_installed = pcr_threat_is_muplugin_installed();
    $mu_plugins_dir = WP_CONTENT_DIR . '/mu-plugins';
    $mu_plugins_writable = is_writable(dirname($mu_plugins_dir)) || (file_exists($mu_plugins_dir) && is_writable($mu_plugins_dir));
    ?>
    
    <div class="pcr-settings-section" style="background: #fff; border: 1px solid #ccd0d4; padding: 20px; margin: 20px 0; box-shadow: 0 1px 1px rgba(0,0,0,.04);">
        <h2><?php _e('Must-Use Plugin (Load Early)', 'global-ipconnect-access-control'); ?></h2>
        <p><?php _e('Install as a Must-Use Plugin to ensure this security plugin loads <strong>before all other plugins</strong>. This is highly recommended for maximum security.', 'global-ipconnect-access-control'); ?></p>
        
        <div class="pcr-settings-row" style="background: <?php echo $is_mu_installed ? '#d4edda' : '#fff3cd'; ?>; padding: 15px; border-radius: 4px;">
            <table class="widefat" style="background: transparent; border: none;">
                <tr>
                    <td style="width: 200px;"><strong><?php _e('MU-Plugin Status:', 'global-ipconnect-access-control'); ?></strong></td>
                    <td>
                        <?php if ($is_mu_installed): ?>
                            <span style="color: green; font-weight: bold;">✓ Installed</span>
                            <span style="color: #666;"> - Plugin loads before all others</span>
                        <?php else: ?>
                            <span style="color: orange; font-weight: bold;">⚠ Not Installed</span>
                            <span style="color: #666;"> - Plugin loads with regular plugins</span>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <td><strong><?php _e('MU-Plugins Directory:', 'global-ipconnect-access-control'); ?></strong></td>
                    <td>
                        <code><?php echo esc_html($mu_plugins_dir); ?></code>
                        <?php if (!file_exists($mu_plugins_dir)): ?>
                            <span style="color: #666;"> (will be created)</span>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <td><strong><?php _e('Directory Writable:', 'global-ipconnect-access-control'); ?></strong></td>
                    <td>
                        <?php if ($mu_plugins_writable): ?>
                            <span style="color: green;">✓ Yes</span>
                        <?php else: ?>
                            <span style="color: red;">✗ No - Check file permissions</span>
                        <?php endif; ?>
                    </td>
                </tr>
            </table>
            
            <div style="margin-top: 15px;">
                <!-- Separate form for MU-plugin actions (not nested in settings form) -->
                <form method="post" action="" style="display: inline;">
                    <?php wp_nonce_field('pcr_muplugin_action'); ?>
                    <?php if ($is_mu_installed): ?>
                        <input type="submit" name="pcr_uninstall_muplugin" class="button" 
                               value="<?php esc_attr_e('Uninstall MU-Plugin', 'global-ipconnect-access-control'); ?>" 
                               onclick="return confirm('Are you sure you want to uninstall the MU-plugin? The plugin will still work but load with regular plugins.');" />
                        <span style="color: #666; margin-left: 10px;">
                            <em><?php _e('Plugin will continue to work but load with regular plugins', 'global-ipconnect-access-control'); ?></em>
                        </span>
                    <?php else: ?>
                        <input type="submit" name="pcr_install_muplugin" class="button button-primary" 
                               value="<?php esc_attr_e('Install as MU-Plugin (Recommended)', 'global-ipconnect-access-control'); ?>" 
                               <?php disabled(!$mu_plugins_writable); ?> />
                        <?php if (!$mu_plugins_writable): ?>
                            <p style="color: #dc3232; margin-top: 10px;">
                                <strong><?php _e('Installation not possible:', 'global-ipconnect-access-control'); ?></strong>
                                <?php _e('The wp-content directory is not writable. Please adjust file permissions or manually install the MU-plugin.', 'global-ipconnect-access-control'); ?>
                            </p>
                        <?php endif; ?>
                    <?php endif; ?>
                </form>
            </div>
        </div>
        
        <div style="margin-top: 15px; padding: 10px; background: #f0f0f1; border-left: 4px solid #2271b1;">
            <strong><?php _e('Why Install as MU-Plugin?', 'global-ipconnect-access-control'); ?></strong>
            <ul style="margin: 10px 0 0 20px;">
                <li><?php _e('Loads <strong>before all other plugins</strong> for maximum security', 'global-ipconnect-access-control'); ?></li>
                <li><?php _e('Threat detection runs earlier in the request lifecycle', 'global-ipconnect-access-control'); ?></li>
                <li><?php _e('Cannot be accidentally disabled from the Plugins menu', 'global-ipconnect-access-control'); ?></li>
                <li><?php _e('Protects against malicious plugin code execution', 'global-ipconnect-access-control'); ?></li>
            </ul>
        </div>
    </div>
    
    <?php
}

/**
 * Render General tab
 */
function pcr_threat_render_general_tab($settings) {
    ?>
    <!-- Hidden field to identify this tab -->
    <input type="hidden" name="pcr_threat[active_tab]" value="general" />
    
    <div class="pcr-settings-section">
        <h2><?php _e('Master Control', 'global-ipconnect-access-control'); ?></h2>
        
        <div class="pcr-settings-row">
            <label>
                <input type="checkbox" name="pcr_threat[enabled]" value="1" 
                       <?php checked($settings['enabled'], true); ?> />
                <?php _e('Enable Threat Detection System', 'global-ipconnect-access-control'); ?>
            </label>
            <p class="description">
                <?php _e('Master switch to enable/disable all threat detection features.', 'global-ipconnect-access-control'); ?>
            </p>
        </div>
    </div>
    
    <div class="pcr-settings-section">
        <h2><?php _e('Visitor Log Retention', 'global-ipconnect-access-control'); ?></h2>

        <div class="pcr-settings-row">
            <label for="pcr_visitor_log_retention">
                <?php _e('Keep visitor logs for (days):', 'global-ipconnect-access-control'); ?>
            </label>
            <input type="number" id="pcr_visitor_log_retention" name="pcr_threat[visitor_log_retention_days]" min="0" step="1" value="<?php echo esc_attr($settings['visitor_log_retention_days']); ?>" style="width:80px;" />
            <p class="description">
                <?php _e('Number of days to retain visitor log entries. Set to 0 to disable automatic deletion.', 'global-ipconnect-access-control'); ?>
            </p>
        </div>
    </div>
    
    <div class="pcr-settings-section">
        <h2><?php _e('System Information', 'global-ipconnect-access-control'); ?></h2>
        
        <table class="widefat">
            <tr>
                <td><strong><?php _e('Detection Engine', 'global-ipconnect-access-control'); ?></strong></td>
                <td><?php echo $settings['enabled'] ? '<span style="color: green;">Active</span>' : '<span style="color: red;">Inactive</span>'; ?></td>
            </tr>
            <tr>
                <td><strong><?php _e('PHP Tokenizer', 'global-ipconnect-access-control'); ?></strong></td>
                <td><?php echo function_exists('token_get_all') ? '<span style="color: green;">Available</span>' : '<span style="color: red;">Not Available</span>'; ?></td>
            </tr>
            <tr>
                <td><strong><?php _e('Active Detection Types', 'global-ipconnect-access-control'); ?></strong></td>
                <td>
                    <?php
                    $active_count = 0;
                    $detection_types = ['detect_php_injection', 'detect_sql_injection', 'detect_php_scan', 'detect_file_upload', 'detect_xss', 'detect_traversal'];
                    foreach ($detection_types as $type) {
                        if (!empty($settings[$type])) $active_count++;
                    }
                    echo $active_count . ' / ' . count($detection_types);
                    ?>
                </td>
            </tr>
        </table>
    </div>
    <?php
}

/**
 * Render Detection Types tab
 */
function pcr_threat_render_detection_tab($settings) {
    ?>
    <!-- Hidden field to identify this tab -->
    <input type="hidden" name="pcr_threat[active_tab]" value="detection" />
    
    <div class="pcr-settings-section">
        <h2><?php _e('Detection Methods', 'global-ipconnect-access-control'); ?></h2>
        <p><?php _e('Enable or disable specific threat detection methods. Each method can be independently controlled.', 'global-ipconnect-access-control'); ?></p>
        
        <!-- PHP Code Injection -->
        <div class="pcr-settings-row">
            <label>
                <input type="checkbox" name="pcr_threat[detect_php_injection]" value="1" 
                       <?php checked($settings['detect_php_injection'], true); ?> />
                <span class="pcr-threat-critical">⚠</span>
                <?php _e('PHP Code Injection Detection', 'global-ipconnect-access-control'); ?>
            </label>
            <p class="description">
                <?php _e('Detects dangerous PHP functions like eval(), system(), exec(), include() using PHP tokenization. Severity: CRITICAL', 'global-ipconnect-access-control'); ?><br>
                <em><?php _e('Examples: eval($_GET["cmd"]), system("rm -rf"), base64_decode(malicious_code)', 'global-ipconnect-access-control'); ?></em>
            </p>
        </div>
        
        <!-- SQL Injection -->
        <div class="pcr-settings-row">
            <label>
                <input type="checkbox" name="pcr_threat[detect_sql_injection]" value="1" 
                       <?php checked($settings['detect_sql_injection'], true); ?> />
                <span class="pcr-threat-critical">⚠</span>
                <?php _e('SQL Injection Detection', 'global-ipconnect-access-control'); ?>
            </label>
            <p class="description">
                <?php _e('Detects SQL injection attempts using pattern matching and scoring system. Context-aware (GET params are stricter). Severity: CRITICAL', 'global-ipconnect-access-control'); ?><br>
                <em><?php _e('Examples: UNION SELECT, information_schema, LOAD_FILE(), wp_users enumeration', 'global-ipconnect-access-control'); ?></em>
            </p>
        </div>
        
        <!-- PHP Script Scanning -->
        <div class="pcr-settings-row">
            <label>
                <input type="checkbox" name="pcr_threat[detect_php_scan]" value="1" 
                       <?php checked($settings['detect_php_scan'], true); ?> />
                <span class="pcr-threat-high">⚠</span>
                <?php _e('PHP Script Scanning Detection', 'global-ipconnect-access-control'); ?>
            </label>
            <p class="description">
                <?php _e('Detects requests for non-existent PHP files (common vulnerability scanner behavior). Severity: HIGH', 'global-ipconnect-access-control'); ?><br>
                <em><?php _e('Examples: /shell.php, /admin.php, /backup.php, /config.php', 'global-ipconnect-access-control'); ?></em>
            </p>
        </div>
        
        <!-- Malicious File Upload -->
        <div class="pcr-settings-row">
            <label>
                <input type="checkbox" name="pcr_threat[detect_file_upload]" value="1" 
                       <?php checked($settings['detect_file_upload'], true); ?> />
                <span class="pcr-threat-critical">⚠</span>
                <?php _e('Malicious File Upload Detection', 'global-ipconnect-access-control'); ?>
            </label>
            <p class="description">
                <?php _e('Scans uploaded files (first 100KB) for malicious code. Auto-deletes dangerous files. Severity: CRITICAL', 'global-ipconnect-access-control'); ?><br>
                <em><?php _e('Examples: Web shells, backdoors, trojans disguised as images or plugins', 'global-ipconnect-access-control'); ?></em>
            </p>
        </div>
        
        <!-- XSS Detection -->
        <div class="pcr-settings-row">
            <label>
                <input type="checkbox" name="pcr_threat[detect_xss]" value="1" 
                       <?php checked($settings['detect_xss'], true); ?> />
                <span class="pcr-threat-high">⚠</span>
                <?php _e('Cross-Site Scripting (XSS) Detection', 'global-ipconnect-access-control'); ?>
            </label>
            <p class="description">
                <?php _e('Detects JavaScript injection attempts in request parameters. Severity: HIGH', 'global-ipconnect-access-control'); ?><br>
                <em><?php _e('Examples: &lt;script&gt;alert()&lt;/script&gt;, onerror="javascript:...", javascript: protocol', 'global-ipconnect-access-control'); ?></em>
            </p>
        </div>
        
        <!-- Directory Traversal -->
        <div class="pcr-settings-row">
            <label>
                <input type="checkbox" name="pcr_threat[detect_traversal]" value="1" 
                       <?php checked($settings['detect_traversal'], true); ?> />
                <span class="pcr-threat-high">⚠</span>
                <?php _e('Directory Traversal Detection', 'global-ipconnect-access-control'); ?>
            </label>
            <p class="description">
                <?php _e('Detects path traversal attempts to access sensitive files. Severity: HIGH', 'global-ipconnect-access-control'); ?><br>
                <em><?php _e('Examples: ../../etc/passwd, ../../../windows/system32', 'global-ipconnect-access-control'); ?></em>
            </p>
        </div>
    </div>
    
    <div class="pcr-settings-section">
        <h2><?php _e('Advanced Detection Options', 'global-ipconnect-access-control'); ?></h2>
        
        <div class="pcr-settings-row">
            <label>
                <input type="checkbox" name="pcr_threat[recursive_base64]" value="1" 
                       <?php checked(!empty($settings['recursive_base64']), true); ?> />
                <?php _e('Recursive Base64 Decoding', 'global-ipconnect-access-control'); ?>
            </label>
            <p class="description">
                <?php _e('Automatically decode base64-encoded payloads up to 30 levels deep. Detects obfuscated attacks.', 'global-ipconnect-access-control'); ?>
            </p>
        </div>
    </div>
    <?php
}

/**
 * Render Whitelist/Bypass tab
 */
function pcr_threat_render_whitelist_tab($settings) {
    ?>
    <!-- Hidden field to identify this tab -->
    <input type="hidden" name="pcr_threat[active_tab]" value="whitelist" />
    
    <div class="pcr-settings-section">
        <h2><?php _e('IP Whitelist', 'global-ipconnect-access-control'); ?></h2>
        <p><?php _e('Whitelisted IPs bypass all threat detection. One IP per line. Supports CIDR notation and wildcards.', 'global-ipconnect-access-control'); ?></p>
        
        <div class="pcr-settings-row">
            <textarea name="pcr_threat[ip_whitelist]" class="large-text" rows="10" 
                      placeholder="192.168.1.1&#10;10.0.0.0/8&#10;172.16.*.*"><?php 
                echo esc_textarea($settings['ip_whitelist']); 
            ?></textarea>
            <p class="description">
                <strong><?php _e('Supported formats:', 'global-ipconnect-access-control'); ?></strong><br>
                • <?php _e('Single IP: 192.168.1.1', 'global-ipconnect-access-control'); ?><br>
                • <?php _e('CIDR notation: 10.0.0.0/8', 'global-ipconnect-access-control'); ?><br>
                • <?php _e('Wildcards: 172.16.*.*', 'global-ipconnect-access-control'); ?>
            </p>
        </div>
    </div>
    
    <div class="pcr-settings-section">
        <h2><?php _e('URL Whitelist', 'global-ipconnect-access-control'); ?></h2>
        <p><?php _e('URLs matching these patterns bypass threat detection. One pattern per line. Supports wildcards and regex.', 'global-ipconnect-access-control'); ?></p>
        
        <div class="pcr-settings-row">
            <textarea name="pcr_threat[url_whitelist]" class="large-text" rows="10" 
                      placeholder="/wp-admin/admin-ajax.php&#10;/my-api/*&#10;regex:/\/api\/v[0-9]+\/.+/"><?php 
                echo esc_textarea($settings['url_whitelist']); 
            ?></textarea>
            <p class="description">
                <strong><?php _e('Supported formats:', 'global-ipconnect-access-control'); ?></strong><br>
                • <?php _e('Exact match: /wp-admin/admin-ajax.php', 'global-ipconnect-access-control'); ?><br>
                • <?php _e('Wildcard: /api/* (matches anything under /api/)', 'global-ipconnect-access-control'); ?><br>
                • <?php _e('Regex: regex:/\/api\/v[0-9]+\/.*/ (prefix with "regex:")', 'global-ipconnect-access-control'); ?>
            </p>
        </div>
    </div>
    
    <div class="pcr-settings-section">
        <h2><?php _e('Whitelisted Form Fields', 'global-ipconnect-access-control'); ?></h2>
        <p><?php _e('These form fields will not be inspected for threats (e.g., comment fields, search queries).', 'global-ipconnect-access-control'); ?></p>
        
        <div class="pcr-settings-row">
            <input type="text" name="pcr_threat[field_whitelist]" class="large-text" 
                   value="<?php echo esc_attr($settings['field_whitelist'] ?? 's,search,comment,post_content'); ?>" 
                   placeholder="s,search,comment,post_content" />
            <p class="description">
                <?php _e('Comma-separated field names. Default: s, search, comment, post_content', 'global-ipconnect-access-control'); ?>
            </p>
        </div>
    </div>
    <?php
}

/**
 * Render Actions tab
 */
function pcr_threat_render_actions_tab($settings) {
    ?>
    <!-- Hidden field to identify this tab -->
    <input type="hidden" name="pcr_threat[active_tab]" value="actions" />
    
    <div class="pcr-settings-section">
        <h2><?php _e('Response Actions', 'global-ipconnect-access-control'); ?></h2>
        <p><?php _e('Configure what happens when a threat is detected.', 'global-ipconnect-access-control'); ?></p>
        
        <div class="pcr-settings-row">
            <label>
                <input type="checkbox" name="pcr_threat[block_on_detect]" value="1" 
                       <?php checked($settings['block_on_detect'], true); ?> />
                <?php _e('Block Request on Threat Detection', 'global-ipconnect-access-control'); ?>
            </label>
            <p class="description">
                <?php _e('If enabled, requests with detected threats will be blocked immediately. If disabled, threats are only logged.', 'global-ipconnect-access-control'); ?>
            </p>
        </div>
        
        <div class="pcr-settings-row">
            <label>
                <input type="checkbox" name="pcr_threat[log_threats]" value="1" 
                       <?php checked($settings['log_threats'], true); ?> />
                <?php _e('Log Threat Detections', 'global-ipconnect-access-control'); ?>
            </label>
            <p class="description">
                <?php _e('Log all detected threats to the visitor log for review and analysis.', 'global-ipconnect-access-control'); ?>
            </p>
        </div>
        
        <div class="pcr-settings-row">
            <label>
                <input type="checkbox" name="pcr_threat[auto_block_ip]" value="1" 
                       <?php checked(!empty($settings['auto_block_ip']), true); ?> />
                <?php _e('Automatically Block Attacking IPs', 'global-ipconnect-access-control'); ?>
            </label>
            <p class="description">
                <?php _e('Add IPs with detected threats to the blocklist after threshold is reached.', 'global-ipconnect-access-control'); ?>
            </p>
        </div>
        
        <div class="pcr-settings-row">
            <label>
                <?php _e('Auto-Block Threshold:', 'global-ipconnect-access-control'); ?>
                <input type="number" name="pcr_threat[auto_block_threshold]" 
                       value="<?php echo esc_attr($settings['auto_block_threshold'] ?? '3'); ?>" 
                       min="1" max="100" style="width: 80px;" />
                <?php _e('threats within', 'global-ipconnect-access-control'); ?>
                <input type="number" name="pcr_threat[auto_block_period]" 
                       value="<?php echo esc_attr($settings['auto_block_period'] ?? '10'); ?>" 
                       min="1" max="1440" style="width: 80px;" />
                <?php _e('minutes', 'global-ipconnect-access-control'); ?>
            </label>
            <p class="description">
                <?php _e('Block IP after X detected threats within Y minutes. Default: 3 threats in 10 minutes.', 'global-ipconnect-access-control'); ?>
            </p>
        </div>
    </div>
    
    <div class="pcr-settings-section">
        <h2><?php _e('Block Response', 'global-ipconnect-access-control'); ?></h2>
        
        <div class="pcr-settings-row">
            <label>
                <input type="checkbox" name="pcr_threat[redirect_to_access_control]" value="1" 
                       <?php checked(!empty($settings['redirect_to_access_control']), true); ?> />
                <?php _e('Redirect to Access Control Block Page (307)', 'global-ipconnect-access-control'); ?>
            </label>
            <p class="description">
                <?php _e('Redirect threats to https://access.global-ipconnect.com/403 with reason included. This logs blocks in the access control site with error code 403. Uses 307 (Temporary Redirect).', 'global-ipconnect-access-control'); ?>
            </p>
        </div>
        
        <div class="pcr-settings-row">
            <label>
                <?php _e('HTTP Response Code (Direct Block):', 'global-ipconnect-access-control'); ?>
                <select name="pcr_threat[block_http_code]">
                    <option value="403" <?php selected($settings['block_http_code'] ?? '403', '403'); ?>>403 Forbidden</option>
                    <option value="404" <?php selected($settings['block_http_code'] ?? '403', '404'); ?>>404 Not Found</option>
                    <option value="406" <?php selected($settings['block_http_code'] ?? '403', '406'); ?>>406 Not Acceptable</option>
                </select>
            </label>
            <p class="description">
                <?php _e('HTTP status code when blocking directly (not using redirect). 403 is recommended for security, 404 can help hide the site.', 'global-ipconnect-access-control'); ?>
            </p>
        </div>
    </div>
    
    <div class="pcr-settings-section">
        <h2><?php _e('Email Notifications', 'global-ipconnect-access-control'); ?></h2>
        
        <div class="pcr-settings-row">
            <label>
                <input type="checkbox" name="pcr_threat[email_on_critical]" value="1" 
                       <?php checked(!empty($settings['email_on_critical']), true); ?> />
                <?php _e('Send Email on Critical Threats', 'global-ipconnect-access-control'); ?>
            </label>
            <p class="description">
                <?php _e('Send email notification when critical threats (PHP injection, SQL injection, file uploads) are detected.', 'global-ipconnect-access-control'); ?>
            </p>
        </div>
        
        <div class="pcr-settings-row">
            <label>
                <?php _e('Notification Email:', 'global-ipconnect-access-control'); ?>
                <input type="email" name="pcr_threat[notification_email]" class="regular-text" 
                       value="<?php echo esc_attr($settings['notification_email'] ?? get_option('admin_email')); ?>" />
            </label>
            <p class="description">
                <?php _e('Email address for threat notifications. Default: site admin email.', 'global-ipconnect-access-control'); ?>
            </p>
        </div>
    </div>
    <?php
}

/**
 * Handle settings save
 */
function pcr_threat_handle_settings_save() {
    // Load existing settings first - IMPORTANT: only update what's submitted
    $settings = pcr_threat_get_settings();
    
    // Determine which tab was submitted using the hidden field
    $active_tab = isset($_POST['pcr_threat']['active_tab']) ? sanitize_key($_POST['pcr_threat']['active_tab']) : '';
    
    // FALLBACK 1: Use the URL tab parameter if hidden field is missing
    if (empty($active_tab) && isset($_GET['tab'])) {
        $active_tab = sanitize_key($_GET['tab']);
    }
    
    // FALLBACK 2: If still no tab, try to detect based on submitted fields
    if (empty($active_tab)) {
        // Check for unique fields from each tab
        if (array_key_exists('detect_php_injection', $_POST['pcr_threat'] ?? [])) {
            $active_tab = 'detection';
        } elseif (isset($_POST['pcr_threat']['ip_whitelist'])) {
            $active_tab = 'whitelist';
        } elseif (isset($_POST['pcr_threat']['block_http_code']) || isset($_POST['pcr_threat']['notification_email'])) {
            $active_tab = 'actions';
        } else {
            // Default to general if we can't detect anything else
            $active_tab = 'general';
        }
    }
    
    // General tab
    if ($active_tab === 'general') {
        // IMPORTANT: For checkboxes, we need to explicitly set false if unchecked
        $settings['enabled'] = isset($_POST['pcr_threat']['enabled']) && $_POST['pcr_threat']['enabled'] == '1';
        if (isset($_POST['pcr_threat']['visitor_log_retention_days'])) {
            $settings['visitor_log_retention_days'] = absint($_POST['pcr_threat']['visitor_log_retention_days']);
        }
    }
    
    // Detection Types tab
    elseif ($active_tab === 'detection') {
        $detection_checkboxes = [
            'detect_php_injection', 'detect_sql_injection', 'detect_php_scan',
            'detect_file_upload', 'detect_xss', 'detect_traversal', 'recursive_base64'
        ];
        foreach ($detection_checkboxes as $key) {
            $settings[$key] = !empty($_POST['pcr_threat'][$key]);
        }
    }
    
    // Whitelist tab
    elseif ($active_tab === 'whitelist') {
        $whitelist_fields = ['ip_whitelist', 'url_whitelist', 'field_whitelist'];
        foreach ($whitelist_fields as $key) {
            if (isset($_POST['pcr_threat'][$key])) {
                $settings[$key] = sanitize_textarea_field($_POST['pcr_threat'][$key]);
            }
        }
    }
    
    // Actions tab
    elseif ($active_tab === 'actions') {
        $action_checkboxes = [
            'block_on_detect', 'log_threats', 'auto_block_ip', 
            'email_on_critical', 'redirect_to_access_control'
        ];
        foreach ($action_checkboxes as $key) {
            $settings[$key] = !empty($_POST['pcr_threat'][$key]);
        }
        
        // Actions tab text/numeric fields
        if (isset($_POST['pcr_threat']['block_http_code'])) {
            $settings['block_http_code'] = sanitize_text_field($_POST['pcr_threat']['block_http_code']);
        }
        if (isset($_POST['pcr_threat']['notification_email'])) {
            $settings['notification_email'] = sanitize_email($_POST['pcr_threat']['notification_email']);
        }
        if (isset($_POST['pcr_threat']['auto_block_threshold'])) {
            $settings['auto_block_threshold'] = absint($_POST['pcr_threat']['auto_block_threshold']);
        }
        if (isset($_POST['pcr_threat']['auto_block_period'])) {
            $settings['auto_block_period'] = absint($_POST['pcr_threat']['auto_block_period']);
        }
    }
    
    // FAILSAFE: If still no matching tab, show error
    else {
        echo '<div class="notice notice-error is-dismissible"><p><strong>Error:</strong> Could not determine which tab was submitted. Please try again.</p></div>';
        return;
    }
    
    // Save settings to database
    $save_result = pcr_threat_save_settings($settings);
    
    // Check if save actually worked
    if ($save_result === false) {
        echo '<div class="notice notice-error is-dismissible"><p><strong>Database Error:</strong> Failed to save settings to database. Check file permissions and database connection.</p></div>';
        return;
    }
    
    // Build detailed success message
    $success_details = [];
    if ($active_tab === 'general') {
        $success_details[] = "'enabled' = " . ($settings['enabled'] ? 'TRUE' : 'FALSE');
    } elseif ($active_tab === 'detection') {
        $enabled_count = 0;
        foreach (['detect_php_injection', 'detect_sql_injection', 'detect_php_scan', 'detect_file_upload', 'detect_xss', 'detect_traversal', 'recursive_base64'] as $key) {
            if (!empty($settings[$key])) $enabled_count++;
        }
        $success_details[] = "$enabled_count detection methods enabled";
    } elseif ($active_tab === 'actions') {
        $success_details[] = "redirect_to_access_control = " . ($settings['redirect_to_access_control'] ? 'TRUE' : 'FALSE');
    }
    
    echo '<div class="notice notice-success is-dismissible" style="border-left: 4px solid #46b450; padding: 15px; font-size: 14px;"><p>' . 
         '<strong>✓ SUCCESS:</strong> ' . esc_html__('Threat detection settings saved successfully.', 'global-ipconnect-access-control') . 
         '<br><strong>Active Tab:</strong> ' . esc_html($active_tab) . 
         (!empty($success_details) ? '<br><strong>Saved:</strong> ' . implode(', ', $success_details) : '') .
         '</p></div>';
}
