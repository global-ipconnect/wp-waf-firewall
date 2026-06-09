<?php
/**
 * Detection functions
 * Bot detection, browser detection, blocking logic
 */

if (!defined('ABSPATH')) exit;

/**
 * Convert value to boolean flag
 */
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

/**
 * Check if user agent is a search bot
 */
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

/**
 * Check if user agent is WordPress updater
 */
function pcr_ac_is_wordpress_user_agent($user_agent) {
    if (!$user_agent) {
        return false;
    }

    return stripos($user_agent, 'wordpress/') !== false;
}

/**
 * Check if browser is outdated
 */
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

/**
 * Get detections modified by whitelist/blacklist flags
 */
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

/**
 * Check if result is whitelisted
 */
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

/**
 * Determine if IP should be blocked based on detection data
 */
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
