<?php
namespace QuxSync\API;

use QuxSync\Security\Authentication;
use QuxSync\Security\RateLimiter;
use QuxSync\Security\WordfenceIntegration;
use QuxSync\Helpers\Logger;

class RestAPI {
    
    private $logger;
    
    public function __construct() {
        $this->logger = new Logger();
        add_action('rest_api_init', [$this, 'register_routes']);
    }
    
    public function register_routes() {
        $routes = [
            '/sync/all' => ['POST', 'sync_all_products'],
            '/sync/product/(?P<id>\d+)' => ['POST', 'sync_single_product'],
            '/sync/products' => ['POST', 'sync_multiple_products'],
            '/status' => ['GET', 'get_sync_status'],
            '/test' => ['POST', 'test_connection'],
            '/settings' => ['GET', 'get_settings'],
            '/settings' => ['POST', 'update_settings'],
            '/logs' => ['GET', 'get_logs'],
            '/update/product/(?P<id>\d+)' => ['PUT', 'update_product'],
            '/update/products' => ['PUT', 'bulk_update_products'],
            '/auth/generate' => ['POST', 'generate_auth_key'],
            '/auth/info' => ['GET', 'get_auth_info'],
            '/security/status' => ['GET', 'get_security_status'],
        ];
        
        foreach ($routes as $route => $config) {
            list($method, $callback) = $config;
            
            $args = [
                'methods' => $method,
                'callback' => [$this, $callback],
                'permission_callback' => [$this, 'check_permissions'],
            ];
            
            if (strpos($route, '(?P<id>\d+)') !== false) {
                $args['args'] = [
                    'id' => [
                        'required' => true,
                        'validate_callback' => function($param) {
                            return is_numeric($param);
                        }
                    ]
                ];
            }
            
            register_rest_route('wc-sync/v1', $route, $args);
        }
    }
    
    public function check_permissions($request) {
        $client_ip = WordfenceIntegration::get_client_ip();
        
        // Check WordFence IP blocking
        if (WordfenceIntegration::is_ip_blocked($client_ip)) {
            WordfenceIntegration::log("Blocked IP attempted API access: {$client_ip}", 'critical', 'Security');
            $this->logger->log("Blocked IP attempted API access: {$client_ip}", 'error');
            return new \WP_Error('ip_blocked', 'Access denied', ['status' => 403]);
        }
        
        // Check IP whitelist
        $ip_whitelist = get_option('wc_sync_ip_whitelist', '');
        if (!empty($ip_whitelist)) {
            $allowed_ips = array_map('trim', explode(',', $ip_whitelist));
            if (!in_array($client_ip, $allowed_ips)) {
                WordfenceIntegration::log("Unauthorized IP: {$client_ip}", 'warning', 'Security');
                return new \WP_Error('ip_not_whitelisted', 'IP not authorized', ['status' => 403]);
            }
        }
        
        // Rate limiting
        if (!RateLimiter::check($client_ip)) {
            WordfenceIntegration::log("Rate limit exceeded: {$client_ip}", 'warning', 'Security');
            return new \WP_Error('rate_limit_exceeded', 'Too many requests', ['status' => 429]);
        }
        
        // Authentication
        $auth_key = get_option('wc_sync_api_auth_key', '');
        if (empty($auth_key)) {
            return new \WP_Error('no_auth_key', 'API authentication key not configured', ['status' => 401]);
        }
        
        $provided_key = $request->get_header('X-WC-Sync-Auth') ?: $request->get_param('auth_key');
        
        if (!Authentication::validate_auth_key($provided_key)) {
            WordfenceIntegration::log("Invalid auth attempt: {$client_ip}", 'warning', 'Security');
            return new \WP_Error('invalid_auth_key', 'Invalid authentication key', ['status' => 401]);
        }
        
        // Signature validation for POST/PUT
        if (get_option('wc_sync_enable_signature', 1) && in_array($request->get_method(), ['POST', 'PUT'])) {
            $signature = $request->get_header('X-WC-Sync-Signature');
            $timestamp = $request->get_header('X-WC-Sync-Timestamp');
            $body = $request->get_body();
            
            if (!Authentication::validate_signature($body, $timestamp, $signature)) {
                WordfenceIntegration::log("Invalid signature: {$client_ip}", 'warning', 'Security');
                return new \WP_Error('invalid_signature', 'Invalid request signature', ['status' => 401]);
            }
        }
        
        WordfenceIntegration::log("Successful API auth: {$client_ip}", 'info', 'API');
        return true;
    }
    
    public function sync_all_products($request) {
        require_once QUX_SYNC_PLUGIN_DIR . 'includes/sync/class-bulk-sync.php';
        $bulk_sync = new \QuxSync\Sync\BulkSync();
        return $bulk_sync->sync_all();
    }
    
    public function sync_single_product($request) {
        require_once QUX_SYNC_PLUGIN_DIR . 'includes/sync/class-product-sync.php';
        $product_sync = new \QuxSync\Sync\ProductSync();
        return $product_sync->sync_single($request->get_param('id'));
    }
    
    public function sync_multiple_products($request) {
        require_once QUX_SYNC_PLUGIN_DIR . 'includes/sync/class-bulk-sync.php';
        $bulk_sync = new \QuxSync\Sync\BulkSync();
        $product_ids = $request->get_param('product_ids');
        return $bulk_sync->sync_multiple($product_ids);
    }
    
    public function get_sync_status($request) {
        return rest_ensure_response([
            'success' => true,
            'data' => [
                'total_products' => wp_count_posts('product')->publish,
                'last_full_sync' => get_option('wc_sync_last_full_sync', 'Never'),
                'products_synced' => get_option('wc_sync_count', 0),
                'auto_sync_enabled' => (bool) get_option('wc_sync_auto_sync', 1),
                'debug_mode_enabled' => (bool) get_option('wc_sync_debug_mode', 0),
                'wordfence_active' => WordfenceIntegration::is_active(),
                'timestamp' => current_time('Y-m-d H:i:s')
            ]
        ]);
    }
    
    public function test_connection($request) {
        require_once QUX_SYNC_PLUGIN_DIR . 'includes/api/class-api-client.php';
        $client = new APIClient();
        return $client->test_connection();
    }
    
    public function get_settings($request) {
        return rest_ensure_response([
            'success' => true,
            'data' => [
                'api_url' => get_option('wc_sync_api_url', ''),
                'auto_sync' => get_option('wc_sync_auto_sync', 1),
                'debug_mode' => get_option('wc_sync_debug_mode', 0),
                'wordfence_active' => WordfenceIntegration::is_active()
            ]
        ]);
    }
    
    public function update_settings($request) {
        $settings = $request->get_json_params();
        $updated = [];
        
        if (isset($settings['api_url'])) {
            update_option('wc_sync_api_url', sanitize_url($settings['api_url']));
            $updated[] = 'api_url';
        }
        
        WordfenceIntegration::log("Settings updated: " . implode(', ', $updated), 'info', 'Settings');
        return rest_ensure_response([
            'success' => true,
            'data' => [
                'updated_settings' => $updated,
                'timestamp' => current_time('Y-m-d H:i:s')
            ]
        ]);
    }
    
    public function get_logs($request) {
        $lines = $request->get_param('lines') ?: 100;
        $logs = $this->logger->get_logs($lines);
        
        return rest_ensure_response([
            'success' => true,
            'data' => [
                'logs' => $logs,
                'showing_lines' => count($logs)
            ]
        ]);
    }
    
    public function update_product($request) {
        require_once QUX_SYNC_PLUGIN_DIR . 'includes/sync/class-product-sync.php';
        $product_sync = new \QuxSync\Sync\ProductSync();
        return $product_sync->update_from_external($request->get_param('id'), $request->get_json_params());
    }
    
    public function bulk_update_products($request) {
        require_once QUX_SYNC_PLUGIN_DIR . 'includes/sync/class-bulk-sync.php';
        $bulk_sync = new \QuxSync\Sync\BulkSync();
        return $bulk_sync->update_from_external($request->get_param('products'));
    }
    
    public function generate_auth_key($request) {
        $new_key = Authentication::generate_secure_key(64);
        update_option('wc_sync_api_auth_key', $new_key);
        update_option('wc_sync_last_key_generation', current_time('Y-m-d H:i:s'));
        
        WordfenceIntegration::log('New API auth key generated', 'info', 'Security');
        
        return rest_ensure_response([
            'success' => true,
            'data' => [
                'new_key' => $new_key,
                'message' => 'New authentication key generated',
                'timestamp' => current_time('Y-m-d H:i:s')
            ]
        ]);
    }
    
    public function get_auth_info($request) {
        $auth_key = get_option('wc_sync_api_auth_key', '');
        
        return rest_ensure_response([
            'success' => true,
            'data' => [
                'key_configured' => !empty($auth_key),
                'key_length' => strlen($auth_key),
                'key_preview' => !empty($auth_key) ? substr($auth_key, 0, 8) . '...' : '',
                'timestamp' => current_time('Y-m-d H:i:s')
            ]
        ]);
    }
    
    public function get_security_status($request) {
        $client_ip = WordfenceIntegration::get_client_ip();
        
        return rest_ensure_response([
            'success' => true,
            'data' => [
                'wordfence_active' => WordfenceIntegration::is_active(),
                'client_ip' => $client_ip,
                'ip_blocked' => WordfenceIntegration::is_ip_blocked($client_ip),
                'rate_limit_max' => get_option('wc_sync_rate_limit_max', 60),
                'rate_limit_window' => get_option('wc_sync_rate_limit_window', 3600),
                'signature_validation' => (bool) get_option('wc_sync_enable_signature', 1),
                'ip_whitelist_enabled' => !empty(get_option('wc_sync_ip_whitelist', '')),
                'timestamp' => current_time('Y-m-d H:i:s')
            ]
        ]);
    }
}
