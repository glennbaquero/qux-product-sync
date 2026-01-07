<?php
namespace QuxSync\Updates;

use QuxSync\Helpers\Logger;

class UpdateChecker {
    
    private $update_url;
    private $logger;
    
    public function __construct() {
        $this->update_url = get_option('qux_product_sync_update_server_url', 'https://qa.api.quxtech.tv/wp/qux-product-sync');
        $this->logger = new Logger();
    }
    
    public function get_remote_version() {
        $cached = get_transient('qux_product_sync_remote_version');
        
        if ($cached !== false && !isset($_GET['force-check'])) {
            return $cached;
        }
        
        $request = wp_remote_get($this->update_url, [
            'timeout' => 15,
            'headers' => [
                'Accept' => 'application/json',
                'User-Agent' => 'WordPress/' . get_bloginfo('version') . '; ' . home_url()
            ]
        ]);
        
        if (is_wp_error($request)) {
            $this->logger->log('Error checking updates: ' . $request->get_error_message(), 'error');
            return false;
        }
        
        $status_code = wp_remote_retrieve_response_code($request);
        if ($status_code !== 200) {
            $this->logger->log('Update check failed: HTTP ' . $status_code, 'error');
            return false;
        }
        
        $body = wp_remote_retrieve_body($request);
        $data = json_decode($body);
        
        if (!$data || !isset($data->version)) {
            $this->logger->log('Invalid update data received', 'error');
            return false;
        }
        
        set_transient('qux_product_sync_remote_version', $data, 12 * HOUR_IN_SECONDS);
        
        return $data;
    }
}
