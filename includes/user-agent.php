<?php
/**
 * User agent parsing functions
 * Converts user agent strings to human-readable formats
 */

if (!defined('ABSPATH')) exit;

/**
 * Parse user agent into detailed format (browser version + OS version)
 * Example: "Chrome 120.0 on Windows 10/11"
 */
function pcr_ac_parse_user_agent($user_agent) {
    if (empty($user_agent)) {
        return 'Unknown';
    }

    $ua = $user_agent;
    $browser = 'Unknown Browser';
    $os = 'Unknown OS';

    // Detect browser
    if (preg_match('/Edg\/(\d+\.\d+)/', $ua, $matches)) {
        $browser = 'Edge ' . $matches[1];
    } elseif (preg_match('/OPR\/(\d+\.\d+)/', $ua, $matches)) {
        $browser = 'Opera ' . $matches[1];
    } elseif (preg_match('/Chrome\/(\d+\.\d+)/', $ua, $matches)) {
        $browser = 'Chrome ' . $matches[1];
    } elseif (preg_match('/Firefox\/(\d+\.\d+)/', $ua, $matches)) {
        $browser = 'Firefox ' . $matches[1];
    } elseif (preg_match('/Safari\/(\d+\.\d+)/', $ua, $matches) && !preg_match('/Chrome/', $ua)) {
        if (preg_match('/Version\/(\d+\.\d+)/', $ua, $version)) {
            $browser = 'Safari ' . $version[1];
        } else {
            $browser = 'Safari ' . $matches[1];
        }
    } elseif (preg_match('/MSIE (\d+\.\d+)/', $ua, $matches)) {
        $browser = 'IE ' . $matches[1];
    } elseif (preg_match('/Trident\/.*rv:(\d+\.\d+)/', $ua, $matches)) {
        $browser = 'IE ' . $matches[1];
    } elseif (preg_match('/Brave/', $ua)) {
        $browser = 'Brave';
    }

    // Detect OS
    if (preg_match('/Windows NT (\d+\.\d+)/', $ua, $matches)) {
        $nt_version = $matches[1];
        $win_versions = array(
            '10.0' => 'Windows 10/11',
            '6.3' => 'Windows 8.1',
            '6.2' => 'Windows 8',
            '6.1' => 'Windows 7',
            '6.0' => 'Windows Vista',
            '5.1' => 'Windows XP',
        );
        $os = isset($win_versions[$nt_version]) ? $win_versions[$nt_version] : 'Windows';
    } elseif (preg_match('/Mac OS X ([\d_]+)/', $ua, $matches)) {
        $version = str_replace('_', '.', $matches[1]);
        $os = 'macOS ' . $version;
    } elseif (preg_match('/Linux/', $ua)) {
        if (preg_match('/Ubuntu/', $ua)) {
            $os = 'Ubuntu Linux';
        } elseif (preg_match('/Fedora/', $ua)) {
            $os = 'Fedora Linux';
        } elseif (preg_match('/Android/', $ua)) {
            $os = 'Android';
        } else {
            $os = 'Linux';
        }
    } elseif (preg_match('/iPhone/', $ua)) {
        $os = 'iOS (iPhone)';
    } elseif (preg_match('/iPad/', $ua)) {
        $os = 'iOS (iPad)';
    } elseif (preg_match('/Android/', $ua)) {
        $os = 'Android';
    }

    return $browser . ' on ' . $os;
}

/**
 * Parse user agent to simple format (no versions)
 * Example: "Chrome for Windows"
 */
function pcr_ac_parse_user_agent_simple($user_agent) {
    if (empty($user_agent)) {
        return 'Unknown';
    }

    $ua = $user_agent;
    $browser = 'Unknown Browser';
    $os = 'Unknown OS';

    // Detect browser (no version)
    if (preg_match('/Edg\//i', $ua)) {
        $browser = 'Edge';
    } elseif (preg_match('/OPR\//i', $ua)) {
        $browser = 'Opera';
    } elseif (preg_match('/Chrome\//i', $ua)) {
        $browser = 'Chrome';
    } elseif (preg_match('/Firefox\//i', $ua)) {
        $browser = 'Firefox';
    } elseif (preg_match('/Safari\//i', $ua) && !preg_match('/Chrome/i', $ua)) {
        $browser = 'Safari';
    } elseif (preg_match('/MSIE|Trident/i', $ua)) {
        $browser = 'Internet Explorer';
    } elseif (preg_match('/Brave/i', $ua)) {
        $browser = 'Brave';
    }

    // Detect OS (simplified)
    if (preg_match('/Windows/i', $ua)) {
        $os = 'Windows';
    } elseif (preg_match('/Mac OS X/i', $ua)) {
        $os = 'macOS';
    } elseif (preg_match('/iPhone/i', $ua)) {
        $os = 'iOS';
    } elseif (preg_match('/iPad/i', $ua)) {
        $os = 'iOS';
    } elseif (preg_match('/Android/i', $ua)) {
        $os = 'Android';
    } elseif (preg_match('/Linux/i', $ua)) {
        $os = 'Linux';
    }

    return $browser . ' for ' . $os;
}
