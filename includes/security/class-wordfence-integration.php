<?php
namespace QuxSync\Security;

class WordfenceIntegration {
    
    public static function is_active() {
        return class_exists('wordfence') || class_exists('wfConfig');
    }
    
    public static function is_ip_blocked($ip = null) {
        if (!self::is_active()) {
            return false;
        }
        
        if ($ip === null) {
            $ip = self::get_client_ip();
        }
        
        if (class_exists('wordfence') && method_exists('wordfence', 'isIPBlocked')) {
            return \wordfence::isIPBlocked($ip);
        }
        
        if (class_exists('wfBlock')) {
            $block = new \wfBlock();
            return $block->isIPBlocked($ip);
        }
        
        return false;
    }
    
    public static function get_client_ip() {
        if (self::is_active() && class_exists('wfUtils') && method_exists('wfUtils', 'getIP')) {
            return \wfUtils::getIP();
        }
        
        $ip_keys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'];
        foreach ($ip_keys as $key) {
            if (!empty($_SERVER[$key])) {
                $ip = $_SERVER[$key];
                if (strpos($ip, ',') !== false) {
                    $ips = explode(',', $ip);
                    $ip = trim($ips[0]);
                }
                return $ip;
            }
        }
        return '';
    }
    
    public static function log($message, $level = 'info', $category = 'API') {
        if (!self::is_active()) {
            return;
        }
        
        if (in_array($level, ['critical', 'error']) && class_exists('wfLog')) {
            try {
                \wfLog::log($message, $level);
            } catch (\Exception $e) {
                // Silently fail
            }
        }
    }
}
