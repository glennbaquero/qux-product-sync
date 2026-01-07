<?php
namespace QuxSync\Security;

class Authentication {
    
    public static function generate_initial_key() {
        if (empty(get_option('wc_sync_api_auth_key', ''))) {
            $key = self::generate_secure_key(64);
            update_option('wc_sync_api_auth_key', $key);
            update_option('wc_sync_last_key_generation', current_time('Y-m-d H:i:s'));
        }
    }
    
    public static function generate_secure_key($length = 64) {
        if (function_exists('wp_generate_password')) {
            return wp_generate_password($length, true, true);
        }
        
        if (function_exists('random_bytes')) {
            return bin2hex(random_bytes($length / 2));
        }
        
        return bin2hex(openssl_random_pseudo_bytes($length / 2));
    }
    
    public static function validate_auth_key($provided_key) {
        $stored_key = get_option('wc_sync_api_auth_key', '');
        return !empty($stored_key) && hash_equals($stored_key, $provided_key);
    }
    
    public static function validate_signature($body, $timestamp, $signature) {
        if (abs(time() - intval($timestamp)) > 300) {
            return false;
        }
        
        $auth_key = get_option('wc_sync_api_auth_key', '');
        $expected = hash_hmac('sha256', $body . $timestamp, $auth_key);
        
        return hash_equals($expected, $signature);
    }
}
