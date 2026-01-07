<?php
namespace QuxSync\API;

use QuxSync\Helpers\Logger;

class APIClient {
    
    private $api_url;
    private $api_key;
    private $secret_key;
    private $logger;
    
    public function __construct() {
        $this->api_url = 'https://qa.api.quxtech.tv/wp/sync-products';
        $this->api_key = get_option('wc_sync_api_key', '');
        $this->secret_key = get_option('wc_sync_secret_key', '');
        $this->logger = new Logger();
    }
    
    public function test_connection() {
        if (empty($this->api_url)) {
            return new \WP_Error('no_api_url', 'API URL not configured', ['status' => 400]);
        }
        
        $response = wp_remote_get($this->api_url, [
            'headers' => [
                'Api-Key' => $this->api_key,
                'Secret-Key' => $this->secret_key,
                'Content-Type' => 'application/json'
            ],
            'timeout' => 30
        ]);
        
        if (is_wp_error($response)) {
            $this->logger->log('API connection test failed: ' . $response->get_error_message(), 'error');
            return new \WP_Error('connection_failed', $response->get_error_message(), ['status' => 500]);
        }
        
        $status_code = wp_remote_retrieve_response_code($response);
        $success = ($status_code >= 200 && $status_code < 300);
        
        $this->logger->log('API connection test: ' . ($success ? 'success' : "failed ({$status_code})"), $success ? 'info' : 'error');
        
        return rest_ensure_response([
            'success' => $success,
            'data' => [
                'status_code' => $status_code,
                'timestamp' => current_time('Y-m-d H:i:s')
            ]
        ]);
    }
    
    public function send_product($product_data) {
        if (empty($this->api_url)) {
            return false;
        }
        
        $response = wp_remote_post($this->api_url, [
            'body' => wp_json_encode($product_data),
            'headers' => [
                'Api-Key' => $this->api_key,
                'Secret-Key' => $this->secret_key,
                'Content-Type' => 'application/json'
            ],
            'timeout' => 30
        ]);
        
        if (is_wp_error($response)) {
            $this->logger->log('Error sending product: ' . $response->get_error_message(), 'error');
            return false;
        }
        
        $status_code = wp_remote_retrieve_response_code($response);
        return ($status_code >= 200 && $status_code < 300);
    }
    
    public function delete_product($product_id) {
        if (empty($this->api_url)) {
            return false;
        }
        
        $response = wp_remote_request($this->api_url . '/' . $product_id, [
            'method' => 'DELETE',
            'headers' => [
                'Api-Key' => $this->api_key,
                'Secret-Key' => $this->secret_key,
                'Content-Type' => 'application/json'
            ],
            'timeout' => 30
        ]);
        
        return !is_wp_error($response);
    }
}
