<?php
/**
 * Visitor Logs Admin Page
 * Complete page rendering for visitor logs with filtering
 */

if (!defined('ABSPATH')) exit;

function pcr_ac_visitor_logs_page() {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('Sorry, you are not allowed to perform this action.', 'global-ipconnect-access-control'));
    }

    global $wpdb;
    $table_name = $wpdb->prefix . PCR_VISITOR_LOG_TABLE;

    // Handle manual table creation
    if (isset($_POST['pcr_create_log_table']) && check_admin_referer('pcr_create_log_table_nonce')) {
        pcr_ac_create_visitor_log_table();
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Visitor log table has been created.', 'global-ipconnect-access-control') . '</p></div>';
    }
    
    // Handle username column upgrade
    if (isset($_POST['pcr_upgrade_username_column']) && check_admin_referer('pcr_upgrade_username_column_nonce')) {
        $wpdb->query("ALTER TABLE $table_name MODIFY COLUMN username varchar(255) DEFAULT NULL");
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Username column has been upgraded to support email addresses.', 'global-ipconnect-access-control') . '</p></div>';
    }
    
    // Handle table upgrade for new columns
    if (isset($_POST['pcr_upgrade_table_columns']) && check_admin_referer('pcr_upgrade_table_columns_nonce')) {
        $wpdb->query("ALTER TABLE $table_name 
            ADD COLUMN IF NOT EXISTS request_method varchar(10) DEFAULT NULL,
            ADD COLUMN IF NOT EXISTS is_suspicious tinyint(1) DEFAULT 0,
            ADD INDEX IF NOT EXISTS request_method (request_method),
            ADD INDEX IF NOT EXISTS is_suspicious (is_suspicious)");
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Visitor log table has been upgraded with new columns.', 'global-ipconnect-access-control') . '</p></div>';
    }
    
    // Handle table upgrade for detailed request columns
    if (isset($_POST['pcr_upgrade_request_details']) && check_admin_referer('pcr_upgrade_request_details_nonce')) {
        $wpdb->query("ALTER TABLE $table_name 
            ADD COLUMN IF NOT EXISTS referrer text DEFAULT NULL,
            ADD COLUMN IF NOT EXISTS request_data mediumtext DEFAULT NULL,
            ADD COLUMN IF NOT EXISTS request_headers text DEFAULT NULL");
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Visitor log table has been upgraded with detailed request tracking columns.', 'global-ipconnect-access-control') . '</p></div>';
    }

    // Check if table exists
    $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$table_name'") === $table_name;
    
    if (!$table_exists) {
        echo '<div class="wrap"><h1>' . esc_html__('Visitor Logs', 'global-ipconnect-access-control') . '</h1>';
        echo '<div class="notice notice-error"><p><strong>' . esc_html__('Error:', 'global-ipconnect-access-control') . '</strong> ' . esc_html__('Visitor log table does not exist.', 'global-ipconnect-access-control') . '</p></div>';
        echo '<p>' . esc_html__('You can create the table now by clicking the button below, or deactivate and reactivate the plugin.', 'global-ipconnect-access-control') . '</p>';
        echo '<form method="post">';
        wp_nonce_field('pcr_create_log_table_nonce');
        echo '<input type="submit" name="pcr_create_log_table" class="button button-primary" value="' . esc_attr__('Create Visitor Log Table', 'global-ipconnect-access-control') . '" />';
        echo '</form></div>';
        return;
    }
    
    // Check if username column needs upgrading
    $column_info = $wpdb->get_row("SHOW COLUMNS FROM $table_name LIKE 'username'");
    $needs_username_upgrade = false;
    if ($column_info && strpos($column_info->Type, 'varchar(60)') !== false) {
        $needs_username_upgrade = true;
        echo '<div class="notice notice-warning is-dismissible">';
        echo '<p><strong>' . esc_html__('Database Update Available:', 'global-ipconnect-access-control') . '</strong> ';
        echo esc_html__('The username column can be upgraded to support email addresses (current limit: 60 chars, new: 255 chars).', 'global-ipconnect-access-control') . '</p>';
        echo '<form method="post" style="margin-top: 10px;">';
        wp_nonce_field('pcr_upgrade_username_column_nonce');
        echo '<input type="submit" name="pcr_upgrade_username_column" class="button button-secondary" value="' . esc_attr__('Upgrade Username Column', 'global-ipconnect-access-control') . '" />';
        echo '</form></div>';
    }
    
    // Check if new columns need to be added
    $request_method_exists = $wpdb->get_row("SHOW COLUMNS FROM $table_name LIKE 'request_method'");
    $is_suspicious_exists = $wpdb->get_row("SHOW COLUMNS FROM $table_name LIKE 'is_suspicious'");
    
    if (!$request_method_exists || !$is_suspicious_exists) {
        echo '<div class="notice notice-warning is-dismissible">';
        echo '<p><strong>' . esc_html__('New Features Available:', 'global-ipconnect-access-control') . '</strong> ';
        echo esc_html__('Upgrade your visitor log table to enable request method tracking and suspicious request detection.', 'global-ipconnect-access-control') . '</p>';
        echo '<form method="post" style="margin-top: 10px;">';
        wp_nonce_field('pcr_upgrade_table_columns_nonce');
        echo '<input type="submit" name="pcr_upgrade_table_columns" class="button button-primary" value="' . esc_attr__('Upgrade Table (Add New Columns)', 'global-ipconnect-access-control') . '" />';
        echo '</form></div>';
    }
    
    // Check if detailed request columns need to be added
    $referrer_exists = $wpdb->get_row("SHOW COLUMNS FROM $table_name LIKE 'referrer'");
    $request_data_exists = $wpdb->get_row("SHOW COLUMNS FROM $table_name LIKE 'request_data'");
    $request_headers_exists = $wpdb->get_row("SHOW COLUMNS FROM $table_name LIKE 'request_headers'");
    
    if (!$referrer_exists || !$request_data_exists || !$request_headers_exists) {
        echo '<div class="notice notice-warning is-dismissible">';
        echo '<p><strong>' . esc_html__('Enhanced Request Tracking Available:', 'global-ipconnect-access-control') . '</strong> ';
        echo esc_html__('Upgrade your visitor log table to enable detailed request tracking (referrer, POST/GET data, headers). This allows you to click on log entries to view full request details.', 'global-ipconnect-access-control') . '</p>';
        echo '<form method="post" style="margin-top: 10px;">';
        wp_nonce_field('pcr_upgrade_request_details_nonce');
        echo '<input type="submit" name="pcr_upgrade_request_details" class="button button-primary" value="' . esc_attr__('Upgrade Table (Add Request Details)', 'global-ipconnect-access-control') . '" />';
        echo '</form></div>';
    }

    // Handle log clearing
    if (isset($_POST['pcr_clear_logs']) && check_admin_referer('pcr_clear_logs_nonce')) {
        $wpdb->query("TRUNCATE TABLE $table_name");
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Visitor logs have been cleared.', 'global-ipconnect-access-control') . '</p></div>';
    }

    // Get filter parameters
    $filter_preset = isset($_GET['preset']) ? sanitize_text_field($_GET['preset']) : '';
    $search_ip = isset($_GET['search_ip']) ? sanitize_text_field($_GET['search_ip']) : '';
    $search_url = isset($_GET['search_url']) ? sanitize_text_field($_GET['search_url']) : '';
    $url_contains = isset($_GET['url_contains']) ? sanitize_text_field($_GET['url_contains']) : '';
    $search_username = isset($_GET['search_username']) ? sanitize_text_field($_GET['search_username']) : '';
    $filter_http_code = isset($_GET['filter_http_code']) ? intval($_GET['filter_http_code']) : 0;
    $filter_method = isset($_GET['filter_method']) ? sanitize_text_field($_GET['filter_method']) : '';
    $filter_days = isset($_GET['filter_days']) ? intval($_GET['filter_days']) : 7;
    $date_from = isset($_GET['date_from']) ? sanitize_text_field($_GET['date_from']) : '';
    $date_to = isset($_GET['date_to']) ? sanitize_text_field($_GET['date_to']) : '';
    $show_advanced = isset($_GET['advanced']) ? true : false;
    
    // Initialize filter variables with defaults
    $filter_suspicious = isset($_GET['filter_suspicious']) ? intval($_GET['filter_suspicious']) : -1;
    $filter_errors = isset($_GET['filter_errors']) ? true : false;
    
    // Apply preset filters (override defaults)
    switch ($filter_preset) {
        case 'suspicious':
            $filter_suspicious = 1;
            break;
        case 'errors':
            $filter_errors = true;
            break;
        case 'forms':
            $filter_method = 'POST';
            break;
        case '404':
            $filter_http_code = 404;
            break;
        case 'rest':
            $url_contains = '/wp-json/';
            break;
        case 'xmlrpc':
            $url_contains = 'xmlrpc.php';
            break;
    }

    // Build query
    $where_clauses = array();
    $where_values = array();

    if (!empty($search_ip)) {
        $where_clauses[] = 'ip_address LIKE %s';
        $where_values[] = '%' . $wpdb->esc_like($search_ip) . '%';
    }

    if (!empty($search_url)) {
        $where_clauses[] = 'url_request LIKE %s';
        $where_values[] = '%' . $wpdb->esc_like($search_url) . '%';
    }
    
    if (!empty($url_contains)) {
        $where_clauses[] = 'url_request LIKE %s';
        $where_values[] = '%' . $wpdb->esc_like($url_contains) . '%';
    }

    if (!empty($search_username)) {
        $where_clauses[] = 'username LIKE %s';
        $where_values[] = '%' . $wpdb->esc_like($search_username) . '%';
    }

    if ($filter_http_code > 0) {
        $where_clauses[] = 'http_code = %d';
        $where_values[] = $filter_http_code;
    }
    
    if (!empty($filter_method)) {
        $where_clauses[] = 'request_method = %s';
        $where_values[] = $filter_method;
    }
    
    if (isset($filter_suspicious) && $filter_suspicious >= 0) {
        $where_clauses[] = 'is_suspicious = %d';
        $where_values[] = $filter_suspicious;
    }
    
    if ($filter_errors) {
        $where_clauses[] = 'http_code >= 400';
    }

    if ($filter_days > 0) {
        $where_clauses[] = 'visit_time >= DATE_SUB(NOW(), INTERVAL %d DAY)';
        $where_values[] = $filter_days;
    }
    
    if (!empty($date_from)) {
        $where_clauses[] = 'visit_time >= %s';
        $where_values[] = $date_from . ' 00:00:00';
    }
    
    if (!empty($date_to)) {
        $where_clauses[] = 'visit_time <= %s';
        $where_values[] = $date_to . ' 23:59:59';
    }

    $where_sql = '';
    if (!empty($where_clauses)) {
        $where_sql = 'WHERE ' . implode(' AND ', $where_clauses);
    }

    // Pagination
    $per_page = 50;
    $page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
    $offset = ($page - 1) * $per_page;

    // Get total count
    if (!empty($where_values)) {
        $count_query = $wpdb->prepare("SELECT COUNT(*) FROM $table_name $where_sql", $where_values);
    } else {
        $count_query = "SELECT COUNT(*) FROM $table_name";
    }
    $total_items = $wpdb->get_var($count_query);
    $total_pages = ceil($total_items / $per_page);

    // Get logs
    if (!empty($where_values)) {
        $query = $wpdb->prepare(
            "SELECT * FROM $table_name $where_sql ORDER BY visit_time DESC LIMIT %d OFFSET %d",
            array_merge($where_values, array($per_page, $offset))
        );
    } else {
        $query = $wpdb->prepare(
            "SELECT * FROM $table_name ORDER BY visit_time DESC LIMIT %d OFFSET %d",
            $per_page,
            $offset
        );
    }
    $logs = $wpdb->get_results($query);

    // Display page
    echo '<div class="wrap">';
    echo '<h1>' . esc_html__('Visitor Logs', 'global-ipconnect-access-control') . '</h1>';
    
    // Quick filter buttons
    $base_url = admin_url('admin.php?page=pcr_visitor_logs');
    echo '<div style="background: #f9f9f9; padding: 15px; margin: 15px 0; border: 1px solid #ddd;">';
    echo '<h3 style="margin: 0 0 10px 0;">' . esc_html__('Quick Filters', 'global-ipconnect-access-control') . '</h3>';
    echo '<div style="display: flex; gap: 8px; flex-wrap: wrap;">';
    
    $filters = array(
        '' => 'View All',
        'suspicious' => 'Suspicious Requests',
        'errors' => 'Errors (4xx/5xx)',
        'forms' => 'Form Submissions',
        '404' => 'Page Not Found',
        'rest' => 'REST API',
        'xmlrpc' => 'XML-RPC',
    );
    
    foreach ($filters as $preset => $label) {
        $url = $preset ? add_query_arg('preset', $preset, $base_url) : $base_url;
        $active = ($filter_preset === $preset && !$show_advanced) || ($preset === '' && empty($filter_preset) && !$show_advanced);
        $style = $active ? 'background: #2271b1; color: #fff; border-color: #2271b1;' : 'background: #fff; color: #2271b1;';
        echo '<a href="' . esc_url($url) . '" class="button" style="' . $style . '">' . esc_html($label) . '</a>';
    }
    
    $advanced_style = 'background: #fff; color: #2271b1;';
    echo '<a href="#" id="pcr-open-advanced-modal" class="button" style="' . $advanced_style . '">' . esc_html__('Advanced Filtering', 'global-ipconnect-access-control') . '</a>';
    
    if (!empty($filter_preset) || !empty($search_ip) || !empty($url_contains) || $filter_http_code > 0 || !empty($filter_method) || $show_advanced) {
        echo '<a href="' . esc_url($base_url) . '" class="button" style="background: #dc3232; color: #fff; border-color: #dc3232;">' . esc_html__('Reset/Clear', 'global-ipconnect-access-control') . '</a>';
    }
    
    echo '</div></div>';

    // Advanced filter modal
    echo '<div id="pcr-advanced-modal" style="display: none; position: fixed; z-index: 100000; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.5);">';
    echo '<div style="background-color: #fefefe; margin: 5% auto; padding: 20px; border: 1px solid #888; width: 90%; max-width: 800px; border-radius: 5px; position: relative;">';
    echo '<span id="pcr-close-modal" style="color: #aaa; float: right; font-size: 28px; font-weight: bold; cursor: pointer; line-height: 20px;">&times;</span>';
    echo '<h2>' . esc_html__('Advanced Filtering', 'global-ipconnect-access-control') . '</h2>';
    echo '<form method="get" style="margin-top: 20px;">';
    echo '<input type="hidden" name="page" value="pcr_visitor_logs" />';
    echo '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px;">';
        
        echo '<div><label for="search_ip">' . esc_html__('IP Address', 'global-ipconnect-access-control') . '</label><br>';
        echo '<input type="text" name="search_ip" id="search_ip" value="' . esc_attr($search_ip) . '" placeholder="e.g., 192.168.1.1" style="width: 100%;" /></div>';
        
        echo '<div><label for="url_contains">' . esc_html__('URL Contains', 'global-ipconnect-access-control') . '</label><br>';
        echo '<input type="text" name="url_contains" id="url_contains" value="' . esc_attr($url_contains) . '" placeholder="e.g., wp-login, xmlrpc" style="width: 100%;" /></div>';
        
        echo '<div><label for="search_username">' . esc_html__('Username', 'global-ipconnect-access-control') . '</label><br>';
        echo '<input type="text" name="search_username" id="search_username" value="' . esc_attr($search_username) . '" placeholder="Search user" style="width: 100%;" /></div>';
        
        echo '<div><label for="filter_method">' . esc_html__('Request Method', 'global-ipconnect-access-control') . '</label><br>';
        echo '<select name="filter_method" id="filter_method" style="width: 100%;">';
        echo '<option value=""' . selected($filter_method, '', false) . '>All Methods</option>';
        echo '<option value="GET"' . selected($filter_method, 'GET', false) . '>GET</option>';
        echo '<option value="POST"' . selected($filter_method, 'POST', false) . '>POST</option>';
        echo '<option value="PUT"' . selected($filter_method, 'PUT', false) . '>PUT</option>';
        echo '<option value="DELETE"' . selected($filter_method, 'DELETE', false) . '>DELETE</option>';
        echo '<option value="PATCH"' . selected($filter_method, 'PATCH', false) . '>PATCH</option>';
        echo '<option value="HEAD"' . selected($filter_method, 'HEAD', false) . '>HEAD</option>';
        echo '</select></div>';
        
        echo '<div><label for="filter_http_code">' . esc_html__('HTTP Code', 'global-ipconnect-access-control') . '</label><br>';
        echo '<select name="filter_http_code" id="filter_http_code" style="width: 100%;">';
        echo '<option value="0"' . selected($filter_http_code, 0, false) . '>All Codes</option>';
    echo '<option value="200"' . selected($filter_http_code, 200, false) . '>200 OK</option>';
    echo '<option value="301"' . selected($filter_http_code, 301, false) . '>301 Moved</option>';
    echo '<option value="302"' . selected($filter_http_code, 302, false) . '>302 Found</option>';
    echo '<option value="307"' . selected($filter_http_code, 307, false) . '>307 Temp</option>';
    echo '<option value="403"' . selected($filter_http_code, 403, false) . '>403 Forbidden</option>';
    echo '<option value="404"' . selected($filter_http_code, 404, false) . '>404 Not Found</option>';
    echo '<option value="500"' . selected($filter_http_code, 500, false) . '>500 Error</option>';
        echo '<option value="503"' . selected($filter_http_code, 503, false) . '>503 Unavailable</option>';
        echo '</select></div>';
        
        echo '<div><label for="date_from">' . esc_html__('Date From', 'global-ipconnect-access-control') . '</label><br>';
        echo '<input type="date" name="date_from" id="date_from" value="' . esc_attr($date_from) . '" style="width: 100%;" /></div>';
        
        echo '<div><label for="date_to">' . esc_html__('Date To', 'global-ipconnect-access-control') . '</label><br>';
        echo '<input type="date" name="date_to" id="date_to" value="' . esc_attr($date_to) . '" style="width: 100%;" /></div>';
        
        echo '<div><label for="filter_suspicious">' . esc_html__('Suspicious Status', 'global-ipconnect-access-control') . '</label><br>';
        echo '<select name="filter_suspicious" id="filter_suspicious" style="width: 100%;">';
        echo '<option value="-1"' . selected(isset($filter_suspicious) ? $filter_suspicious : -1, -1, false) . '>All Requests</option>';
        echo '<option value="1"' . selected(isset($filter_suspicious) ? $filter_suspicious : -1, 1, false) . '>⚠️ Suspicious Only</option>';
        echo '<option value="0"' . selected(isset($filter_suspicious) ? $filter_suspicious : -1, 0, false) . '>✅ Clean Only</option>';
        echo '</select></div>';
        
        echo '</div>';
        
        echo '<div style="display: flex; gap: 10px; justify-content: flex-end;">';
        echo '<input type="submit" class="button button-primary" value="' . esc_attr__('Apply Filters', 'global-ipconnect-access-control') . '" />';
        echo '<a href="' . esc_url($base_url) . '" class="button">' . esc_html__('Reset All', 'global-ipconnect-access-control') . '</a>';
        echo '</div>';
        
        echo '</form></div></div>';
    
        // Simple filter row (always show)
        echo '<form method="get" style="margin-bottom: 15px;">';
        echo '<input type="hidden" name="page" value="pcr_visitor_logs" />';
        echo '<div style="display: flex; gap: 10px; flex-wrap: wrap; align-items: end;">';
        
        echo '<div><label for="filter_days">' . esc_html__('Time Range:', 'global-ipconnect-access-control') . '</label><br>';
    echo '<select name="filter_days" id="filter_days" style="width: 120px;">';
    echo '<option value="1"' . selected($filter_days, 1, false) . '>Last 24 hours</option>';
    echo '<option value="7"' . selected($filter_days, 7, false) . '>Last 7 days</option>';
    echo '<option value="30"' . selected($filter_days, 30, false) . '>Last 30 days</option>';
    echo '<option value="90"' . selected($filter_days, 90, false) . '>Last 90 days</option>';
        echo '<option value="0"' . selected($filter_days, 0, false) . '>All time</option>';
        echo '</select></div>';
        
        echo '<div><input type="submit" class="button" value="' . esc_attr__('Filter', 'global-ipconnect-access-control') . '" /></div>';
        echo '</div></form>';

    // Statistics
    echo '<div style="background: #fff; padding: 15px; border: 1px solid #ccc; margin-bottom: 20px;">';
    echo '<strong>' . esc_html__('Total Results:', 'global-ipconnect-access-control') . '</strong> ' . number_format($total_items);
    echo '</div>';

    // Logs table
    echo '<div style="position: relative; z-index: 1; background: #fff;">';
    echo '<table class="wp-list-table widefat fixed striped" style="table-layout: auto;">';
    echo '<thead><tr>';
    echo '<th style="width: 140px;">' . esc_html__('Date/Time', 'global-ipconnect-access-control') . '</th>';
    echo '<th style="width: 110px;">' . esc_html__('IP', 'global-ipconnect-access-control') . '</th>';
    echo '<th style="width: 160px;">' . esc_html__('Hostname', 'global-ipconnect-access-control') . '</th>';
    echo '<th>' . esc_html__('URL', 'global-ipconnect-access-control') . '</th>';
    echo '<th style="width: 180px;">' . esc_html__('User Agent', 'global-ipconnect-access-control') . '</th>';
    echo '<th style="width: 50px; text-align: center;">' . esc_html__('HTTP', 'global-ipconnect-access-control') . '</th>';
    echo '<th style="width: 130px;">' . esc_html__('User', 'global-ipconnect-access-control') . '</th>';
    echo '</tr></thead><tbody>';

    if (!empty($logs)) {
        foreach ($logs as $log) {
            $http_code_class = '';
            if ($log->http_code >= 400) {
                $http_code_class = 'color: #dc3232;';
            } elseif ($log->http_code >= 300) {
                $http_code_class = 'color: #ffb900;';
            } else {
                $http_code_class = 'color: #46b450;';
            }

            // Build filter URLs
            $filter_by_ip_url = add_query_arg(array(
                'page' => 'pcr_visitor_logs',
                'search_ip' => $log->ip_address,
                'advanced' => '1'
            ), admin_url('admin.php'));
            
            $filter_by_http_url = add_query_arg(array(
                'page' => 'pcr_visitor_logs',
                'filter_http_code' => $log->http_code,
                'advanced' => '1'
            ), admin_url('admin.php'));
            
            $filter_by_user_url = '';
            if ($log->username) {
                $filter_by_user_url = add_query_arg(array(
                    'page' => 'pcr_visitor_logs',
                    'search_username' => $log->username,
                    'advanced' => '1'
                ), admin_url('admin.php'));
            }
            
            $filter_by_method_url = '';
            if (isset($log->request_method) && $log->request_method) {
                $filter_by_method_url = add_query_arg(array(
                    'page' => 'pcr_visitor_logs',
                    'filter_method' => $log->request_method,
                    'advanced' => '1'
                ), admin_url('admin.php'));
            }
            
            $is_suspicious = isset($log->is_suspicious) && $log->is_suspicious == 1;
            $row_style = $is_suspicious ? 'background-color: #ffe6e6;' : '';
            $row_title = $is_suspicious ? 'title="Suspicious request detected"' : '';

            echo '<tr class="pcr-log-row" data-log-id="' . esc_attr($log->id) . '" style="' . $row_style . ' cursor: pointer;" ' . $row_title . ' onclick="pcrToggleLogDetails(' . esc_attr($log->id) . ')">';
            echo '<td>' . esc_html(get_date_from_gmt($log->visit_time, 'Y-m-d H:i:s')) . '</td>';
            echo '<td><a href="' . esc_url($filter_by_ip_url) . '" style="text-decoration: none; color: #2271b1;" title="Filter by this IP" onclick="event.stopPropagation();">' . esc_html($log->ip_address) . '</a></td>';
            echo '<td style="word-break: break-all; font-size: 11px;">' . esc_html($log->ip_hostname ? $log->ip_hostname : '-') . '</td>';
            echo '<td style="word-break: break-all;"><a href="' . esc_url($log->url_request) . '" target="_blank" onclick="event.stopPropagation();">' . esc_html($log->url_request) . '</a></td>';
            $simple_ua = pcr_ac_parse_user_agent_simple($log->user_agent_raw);
            echo '<td title="' . esc_attr($log->user_agent_raw) . '" style="font-size: 11px;">' . esc_html($simple_ua) . '</td>';
            echo '<td style="text-align: center; font-weight: bold;"><a href="' . esc_url($filter_by_http_url) . '" style="text-decoration: none; ' . $http_code_class . '" title="Filter by HTTP ' . esc_attr($log->http_code) . '" onclick="event.stopPropagation();">' . esc_html($log->http_code) . '</a></td>';
            if ($log->username) {
                echo '<td><a href="' . esc_url($filter_by_user_url) . '" style="text-decoration: none; color: #2271b1; font-size: 11px;" title="Filter by this user" onclick="event.stopPropagation();">' . esc_html($log->username) . '</a></td>';
            } else {
                echo '<td>-</td>';
            }
            echo '</tr>';
            
            // Expanded details row (hidden by default)
            echo '<tr id="pcr-details-' . esc_attr($log->id) . '" class="pcr-details-row" style="display: none;">';
            echo '<td colspan="7" style="background: #f9f9f9; padding: 20px; border-left: 3px solid #2271b1;">';
            
            // Referrer
            echo '<div style="margin-bottom: 15px;">';
            echo '<strong style="display: block; margin-bottom: 5px;">Referrer:</strong>';
            $referrer = isset($log->referrer) && $log->referrer ? $log->referrer : 'None';
            echo '<div style="background: #fff; padding: 10px; border: 1px solid #ddd; border-radius: 3px; font-family: monospace; font-size: 12px;">' . esc_html($referrer) . '</div>';
            echo '</div>';
            
            // User Agent (full)
            echo '<div style="margin-bottom: 15px;">';
            echo '<strong style="display: block; margin-bottom: 5px;">User Agent:</strong>';
            echo '<div style="background: #fff; padding: 10px; border: 1px solid #ddd; border-radius: 3px; font-family: monospace; font-size: 12px; word-break: break-all;">' . esc_html($log->user_agent_raw) . '</div>';
            echo '</div>';
            
            // Request Data
            if (isset($log->request_data) && $log->request_data) {
                $request_data = json_decode($log->request_data, true);
                if ($request_data) {
                    echo '<div style="margin-bottom: 15px;">';
                    echo '<strong style="display: block; margin-bottom: 5px;">Request Data:</strong>';
                    echo '<div style="background: #fff; padding: 10px; border: 1px solid #ddd; border-radius: 3px;">';
                    
                    if (isset($request_data['POST']) && !empty($request_data['POST'])) {
                        echo '<div style="margin-bottom: 10px;"><strong style="color: #d63638;">POST Data:</strong></div>';
                        echo '<table style="width: 100%; border-collapse: collapse; font-size: 12px; margin-bottom: 15px;">';
                        echo '<thead><tr style="background: #f0f0f0;"><th style="padding: 5px; text-align: left; border: 1px solid #ddd;">Parameter</th><th style="padding: 5px; text-align: left; border: 1px solid #ddd;">Value</th></tr></thead><tbody>';
                        foreach ($request_data['POST'] as $key => $value) {
                            echo '<tr><td style="padding: 5px; border: 1px solid #ddd; font-family: monospace;">' . esc_html($key) . '</td><td style="padding: 5px; border: 1px solid #ddd; font-family: monospace; word-break: break-all;">' . esc_html(is_array($value) ? json_encode($value) : $value) . '</td></tr>';
                        }
                        echo '</tbody></table>';
                    }
                    
                    if (isset($request_data['GET']) && !empty($request_data['GET'])) {
                        echo '<div style="margin-bottom: 10px;"><strong style="color: #00a32a;">GET Parameters:</strong></div>';
                        echo '<table style="width: 100%; border-collapse: collapse; font-size: 12px;">';
                        echo '<thead><tr style="background: #f0f0f0;"><th style="padding: 5px; text-align: left; border: 1px solid #ddd;">Parameter</th><th style="padding: 5px; text-align: left; border: 1px solid #ddd;">Value</th></tr></thead><tbody>';
                        foreach ($request_data['GET'] as $key => $value) {
                            echo '<tr><td style="padding: 5px; border: 1px solid #ddd; font-family: monospace;">' . esc_html($key) . '</td><td style="padding: 5px; border: 1px solid #ddd; font-family: monospace; word-break: break-all;">' . esc_html(is_array($value) ? json_encode($value) : $value) . '</td></tr>';
                        }
                        echo '</tbody></table>';
                    }
                    
                    echo '</div>';
                    echo '</div>';
                } else {
                    echo '<div style="margin-bottom: 15px;">';
                    echo '<strong style="display: block; margin-bottom: 5px;">Request Data:</strong>';
                    echo '<div style="background: #fff; padding: 10px; border: 1px solid #ddd; border-radius: 3px; color: #666; font-style: italic;">No data sent with this request</div>';
                    echo '</div>';
                }
            } else {
                echo '<div style="margin-bottom: 15px;">';
                echo '<strong style="display: block; margin-bottom: 5px;">Request Data:</strong>';
                echo '<div style="background: #fff; padding: 10px; border: 1px solid #ddd; border-radius: 3px; color: #666; font-style: italic;">No data sent with this request</div>';
                echo '</div>';
            }
            
            // Request Headers
            if (isset($log->request_headers) && $log->request_headers) {
                $headers = json_decode($log->request_headers, true);
                if ($headers) {
                    echo '<div style="margin-bottom: 15px;">';
                    echo '<strong style="display: block; margin-bottom: 5px;">Request Headers:</strong>';
                    echo '<div style="background: #fff; padding: 10px; border: 1px solid #ddd; border-radius: 3px;">';
                    echo '<table style="width: 100%; border-collapse: collapse; font-size: 12px;">';
                    echo '<thead><tr style="background: #f0f0f0;"><th style="padding: 5px; text-align: left; border: 1px solid #ddd;">Header</th><th style="padding: 5px; text-align: left; border: 1px solid #ddd;">Value</th></tr></thead><tbody>';
                    foreach ($headers as $key => $value) {
                        echo '<tr><td style="padding: 5px; border: 1px solid #ddd; font-family: monospace;">' . esc_html($key) . '</td><td style="padding: 5px; border: 1px solid #ddd; font-family: monospace; word-break: break-all;">' . esc_html($value) . '</td></tr>';
                    }
                    echo '</tbody></table></div></div>';
                }
            }
            
            echo '</td></tr>';
        }
    } else {
        echo '<tr><td colspan="7" style="text-align: center; padding: 20px;">' . esc_html__('No logs found.', 'global-ipconnect-access-control') . '</td></tr>';
    }

    echo '</tbody></table></div>';

    // Pagination
    if ($total_pages > 1) {
        echo '<div class="tablenav bottom" style="padding: 10px 0;">';
        echo '<div class="tablenav-pages">';
        echo '<span class="displaying-num">' . sprintf(_n('%s item', '%s items', $total_items), number_format_i18n($total_items)) . '</span>';
        
        $page_links = paginate_links(array(
            'base' => add_query_arg('paged', '%#%'),
            'format' => '',
            'prev_text' => '&laquo;',
            'next_text' => '&raquo;',
            'total' => $total_pages,
            'current' => $page,
        ));
        
        if ($page_links) {
            echo '<span class="pagination-links">' . $page_links . '</span>';
        }
        echo '</div></div>';
    }

    // Clear logs button
    echo '<form method="post" style="margin-top: 20px;" onsubmit="return confirm(' . esc_js(__('Are you sure you want to clear all visitor logs? This action cannot be undone.', 'global-ipconnect-access-control')) . ');">';
    wp_nonce_field('pcr_clear_logs_nonce');
    echo '<input type="submit" name="pcr_clear_logs" class="button button-secondary" value="' . esc_attr__('Clear All Logs', 'global-ipconnect-access-control') . '" />';
    echo '</form>';
    
    // Copyright
    echo '<div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666; font-size: 12px;">';
    echo 'Global IP Connect Access Control Plugin &copy; ' . date('Y') . ' <a href="https://pacificatoll.com" target="_blank" style="color: #2271b1; text-decoration: none;">Pacific Atoll System</a>. All rights reserved.';
    echo '</div>';
    
    // Modal and Row Expansion JavaScript
    echo '<script>
    function pcrToggleLogDetails(logId) {
        var detailsRow = document.getElementById("pcr-details-" + logId);
        if (detailsRow) {
            if (detailsRow.style.display === "none" || detailsRow.style.display === "") {
                detailsRow.style.display = "table-row";
            } else {
                detailsRow.style.display = "none";
            }
        }
    }
    
    document.addEventListener("DOMContentLoaded", function() {
        var modal = document.getElementById("pcr-advanced-modal");
        var btn = document.getElementById("pcr-open-advanced-modal");
        var span = document.getElementById("pcr-close-modal");
        
        if (btn) {
            btn.onclick = function(e) {
                e.preventDefault();
                modal.style.display = "block";
            };
        }
        
        if (span) {
            span.onclick = function() {
                modal.style.display = "none";
            };
        }
        
        window.onclick = function(event) {
            if (event.target == modal) {
                modal.style.display = "none";
            }
        };
    });
    </script>';

    echo '</div>';
}
