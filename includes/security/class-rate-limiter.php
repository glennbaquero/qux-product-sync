<?php
namespace QuxSync\Security;

class RateLimiter {
    
    public static function check($identifier) {
        $option_key = 'wc_sync_rate_limit_' . md5($identifier);
        $data = get_transient($option_key);
        
        $max_requests = get_option('wc_sync_rate_limit_max', 60);
        $time_window = get_option('wc_sync_rate_limit_window', 3600);
        
        if ($data === false) {
            set_transient($option_key, ['count' => 1, 'start' => time()], $time_window);
            return true;
        }
        
        if ($data['count'] >= $max_requests) {
            return false;
        }
        
        $data['count']++;
        set_transient($option_key, $data, $time_window);
        return true;
    }
}
