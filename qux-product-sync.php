<?php
/*
    Plugin Name: QUX Pay® Product Sync
    Description: Sync your WooCommerce products to QUX®Marketplace. Recommended with QUX Pay® Payment integration. Compatible with WordFence.
    Version: 1.1.3
    Author: Qux
    Requires PHP: 7.4
    Requires at least: 6.7
    Tested up to: 6.8.2
    WC requires at least: 10.1.2
    WC tested up to: 10.1.2
    Requires Plugins: woocommerce, wordfence
    Author URI: https://qux.tv
    Plugin URI: https://qux.tv/
    Update URI: https://qa.api.quxtech.tv/qux-product-sync
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class QuxProductSync {
    
    private $api_url;
    private $api_key;
    private $secret_key;
    private $log_file;
    private $wordfence_enabled = false;
    
    // Auto-update properties
    private $plugin_slug = 'qux-product-sync';
    private $plugin_file = __FILE__;
    private $update_url = 'https://qa.api.quxtech.tv/wp/qux-product-sync';
    
    public function __construct() {
        $this->api_url = 'https://qa.api.quxtech.tv/wp/sync-products';
        $this->api_key = get_option('wc_sync_api_key', '');
        $this->secret_key = get_option('wc_sync_secret_key', '');
        $this->log_file = WP_CONTENT_DIR . '/wc-product-sync.log';
        $this->wordfence_enabled = $this->is_wordfence_active();
        
        // HPOS compatibility
        add_action('before_woocommerce_init', function() {
            if (class_exists(\Automattic\WooCommerce\Utilities\FeaturesUtil::class)) {
                \Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility(
                    'custom_order_tables',
                    __FILE__,
                    true
                );
            }
        });
        
        add_action('init', array($this, 'init'));
        add_action('admin_menu', array($this, 'admin_menu'));
        add_action('wp_ajax_sync_all_products', array($this, 'ajax_sync_all_products'));
        add_action('wp_ajax_test_api_connection', array($this, 'ajax_test_api_connection'));
        add_action('wp_ajax_generate_auth_key', array($this, 'ajax_generate_auth_key'));
        
        // Hook into product save/update events
        add_action('woocommerce_new_product', array($this, 'sync_single_product'), 10, 1);
        add_action('woocommerce_update_product', array($this, 'sync_single_product'), 10, 1);
        add_action('woocommerce_delete_product', array($this, 'delete_product_from_api'), 10, 1);
        
        // Add bulk action
        add_filter('bulk_actions-edit-product', array($this, 'add_bulk_sync_action'));
        add_filter('handle_bulk_actions-edit-product', array($this, 'handle_bulk_sync_action'), 10, 3);
        
        // Register REST API endpoints
        add_action('rest_api_init', array($this, 'register_api_endpoints'));
        
        // Plugin activation/deactivation hooks
        register_activation_hook(__FILE__, array($this, 'plugin_activation'));
        register_deactivation_hook(__FILE__, array($this, 'plugin_deactivation'));
        
        // Auto-update hooks
        add_filter('pre_set_site_transient_update_plugins', array($this, 'check_for_updates'));
        add_filter('plugins_api', array($this, 'plugin_info'), 10, 3);
        add_filter('plugin_row_meta', array($this, 'plugin_row_meta'), 10, 2);
        add_action('in_plugin_update_message-' . plugin_basename(__FILE__), array($this, 'update_message'), 10, 2);
        
        // Cron hook for periodic update checks
        add_action('qux_product_sync_check_updates', array($this, 'cron_check_updates'));
        
        // Settings for auto-updates
        add_action('wp_ajax_toggle_auto_updates', array($this, 'ajax_toggle_auto_updates'));
        add_action('wp_ajax_check_updates_now', array($this, 'ajax_check_updates_now'));
        
        // Add JavaScript for plugins page
        add_action('admin_footer-plugins.php', array($this, 'add_plugins_page_script'));
    }
    
    /**
     * Check for plugin updates
     */
    public function check_for_updates($transient) {
        if (empty($transient->checked)) {
            return $transient;
        }
        
        // Check if auto-updates are enabled
        if (!get_option('qux_product_sync_auto_updates_enabled', 1)) {
            return $transient;
        }
        
        $plugin_slug = plugin_basename($this->plugin_file);
        
        // Get remote version info
        $remote_version = $this->get_remote_version();
        
        if ($remote_version && version_compare($this->get_plugin_version(), $remote_version->version, '<')) {
            $obj = new stdClass();
            $obj->slug = $this->plugin_slug;
            $obj->plugin = $plugin_slug;
            $obj->new_version = $remote_version->version;
            $obj->url = $remote_version->homepage ?? '';
            $obj->package = $remote_version->download_url ?? '';
            $obj->tested = $remote_version->tested ?? '';
            $obj->requires = $remote_version->requires ?? '';
            $obj->requires_php = $remote_version->requires_php ?? '';
            
            // Add icons if available
            if (isset($remote_version->icons)) {
                $obj->icons = (array) $remote_version->icons;
            }
            
            $transient->response[$plugin_slug] = $obj;
        }
        
        return $transient;
    }
    
    /**
     * Get plugin information for details popup
     */
    public function plugin_info($false, $action, $response) {
        if ($action !== 'plugin_information') {
            return $false;
        }
        
        if ($response->slug !== $this->plugin_slug) {
            return $false;
        }
        
        $remote_version = $this->get_remote_version();
        
        if (!$remote_version) {
            return $false;
        }
        
        $info = new stdClass();
        $info->name = $remote_version->name ?? 'QUX Pay® Product Sync';
        $info->slug = $this->plugin_slug;
        $info->version = $remote_version->version;
        $info->author = $remote_version->author ?? 'Qux';
        $info->homepage = $remote_version->homepage ?? 'https://qux.tv';
        $info->requires = $remote_version->requires ?? '6.7';
        $info->tested = $remote_version->tested ?? '6.8.2';
        $info->requires_php = $remote_version->requires_php ?? '7.4';
        $info->download_link = $remote_version->download_url ?? '';
        $info->sections = array(
            'description' => $remote_version->sections->description ?? 'Syncs WooCommerce products to Qux with WordFence security integration.',
            'changelog' => $remote_version->sections->changelog ?? ''
        );
        
        if (isset($remote_version->banners)) {
            $info->banners = (array) $remote_version->banners;
        }
        
        return $info;
    }
    
    /**
     * Add custom links to plugin row
     */
    public function plugin_row_meta($links, $file) {
        if ($file === plugin_basename($this->plugin_file)) {
            $auto_updates_enabled = get_option('qux_product_sync_auto_updates_enabled', 1);
            $status = $auto_updates_enabled ? 'enabled' : 'disabled';
            $links[] = '<a href="#" class="qux-toggle-auto-updates" data-nonce="' . wp_create_nonce('qux_product_sync_nonce') . '" data-enabled="' . $auto_updates_enabled . '">Auto-updates <span class="auto-update-status">' . $status . '</span></a>';
            $links[] = '<a href="' . admin_url('admin.php?page=wc-product-sync&tab=updates') . '">Update Settings</a>';
        }
        return $links;
    }
    
    /**
     * Show update message
     */
    public function update_message($plugin_data, $response) {
        echo '<br><strong>Important:</strong> Please backup your site before updating.';
    }
    
    /**
     * Get remote version information
     */
    private function get_remote_version() {
        $cached = get_transient('qux_product_sync_remote_version');
        
        if ($cached !== false && !isset($_GET['force-check'])) {
            return $cached;
        }
        
        $request = wp_remote_get($this->update_url, array(
            'timeout' => 15,
            'headers' => array(
                'Accept' => 'application/json',
                'User-Agent' => 'WordPress/' . get_bloginfo('version') . '; ' . home_url()
            )
        ));
        
        if (is_wp_error($request)) {
            $this->log('Error checking for updates: ' . $request->get_error_message());
            return false;
        }
        
        $status_code = wp_remote_retrieve_response_code($request);
        if ($status_code !== 200) {
            $this->log('Update check failed with status code: ' . $status_code);
            return false;
        }
        
        $body = wp_remote_retrieve_body($request);
        $data = json_decode($body);
        
        if (!$data || !isset($data->version)) {
            $this->log('Invalid update data received from server');
            return false;
        }
        
        // Cache for 12 hours
        set_transient('qux_product_sync_remote_version', $data, 12 * HOUR_IN_SECONDS);
        
        return $data;
    }
    
    /**
     * Get current plugin version
     */
    private function get_plugin_version() {
        $plugin_data = get_file_data($this->plugin_file, array('Version' => 'Version'));
        return $plugin_data['Version'];
    }
    
    /**
     * Schedule update checks
     */
    public function schedule_update_checks() {
        if (!wp_next_scheduled('qux_product_sync_check_updates')) {
            wp_schedule_event(time(), 'twicedaily', 'qux_product_sync_check_updates');
            $this->log('Update check cron scheduled');
        }
    }
    
    /**
     * Remove scheduled update checks
     */
    public function unschedule_update_checks() {
        $timestamp = wp_next_scheduled('qux_product_sync_check_updates');
        if ($timestamp) {
            wp_unschedule_event($timestamp, 'qux_product_sync_check_updates');
            $this->log('Update check cron unscheduled');
        }
    }
    
    /**
     * Cron callback to check for updates
     */
    public function cron_check_updates() {
        if (!get_option('qux_product_sync_auto_updates_enabled', 1)) {
            return;
        }
        
        // Clear cache to force fresh check
        delete_transient('qux_product_sync_remote_version');
        delete_site_transient('update_plugins');
        
        $this->log('Automated update check triggered by cron');
    }
    
    /**
     * AJAX: Toggle auto-updates
     */
    public function ajax_toggle_auto_updates() {
        check_ajax_referer('qux_product_sync_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die(json_encode(array('success' => false, 'message' => 'Insufficient permissions')));
        }
        
        $current = get_option('qux_product_sync_auto_updates_enabled', 1);
        $new_value = !$current;
        
        update_option('qux_product_sync_auto_updates_enabled', $new_value);
        
        $this->log('Auto-updates ' . ($new_value ? 'enabled' : 'disabled'));
        $this->log_to_wordfence('Auto-updates ' . ($new_value ? 'enabled' : 'disabled'), 'info', 'Settings');
        
        wp_die(json_encode(array(
            'success' => true,
            'enabled' => $new_value,
            'message' => 'Auto-updates ' . ($new_value ? 'enabled' : 'disabled')
        )));
    }
    
    /**
     * AJAX: Check for updates now
     */
    public function ajax_check_updates_now() {
        check_ajax_referer('qux_product_sync_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die(json_encode(array('success' => false, 'message' => 'Insufficient permissions')));
        }
        
        // Force check by clearing cache
        delete_transient('qux_product_sync_remote_version');
        delete_site_transient('update_plugins');
        
        $remote_version = $this->get_remote_version();
        $current_version = $this->get_plugin_version();
        
        if (!$remote_version) {
            wp_die(json_encode(array(
                'success' => false,
                'message' => 'Could not connect to update server. Please check your update server URL: ' . $this->update_url
            )));
        }
        
        $update_available = version_compare($current_version, $remote_version->version, '<');
        
        // Log the check
        $this->log('Manual update check - Current: ' . $current_version . ', Remote: ' . $remote_version->version);
        
        wp_die(json_encode(array(
            'success' => true,
            'current_version' => $current_version,
            'remote_version' => $remote_version->version,
            'update_available' => $update_available,
            'message' => $update_available 
                ? 'Update available: ' . $remote_version->version 
                : 'You are using the latest version'
        )));
    }
    
    /**
     * Add JavaScript to plugins page for toggle functionality
     */
    public function add_plugins_page_script() {
        ?>
        <script type="text/javascript">
        jQuery(document).ready(function($) {
            $(document).on('click', '.qux-toggle-auto-updates', function(e) {
                e.preventDefault();
                
                var link = $(this);
                var statusSpan = link.find('.auto-update-status');
                var nonce = link.data('nonce');
                var originalText = statusSpan.text();
                statusSpan.text('updating...');
                
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'toggle_auto_updates',
                        nonce: nonce
                    },
                    success: function(response) {
                        var data = JSON.parse(response);
                        if (data.success) {
                            var newStatus = data.enabled ? 'enabled' : 'disabled';
                            statusSpan.text(newStatus);
                            link.data('enabled', data.enabled ? 1 : 0);
                            
                            var message = $('<div class="notice notice-success is-dismissible"><p>' + data.message + '</p></div>');
                            $('.wrap').prepend(message);
                            
                            setTimeout(function() {
                                message.fadeOut(function() {
                                    $(this).remove();
                                });
                            }, 3000);
                        } else {
                            statusSpan.text(originalText);
                            alert('Error: ' + data.message);
                        }
                    },
                    error: function() {
                        statusSpan.text(originalText);
                        alert('Failed to toggle auto-updates. Please try again.');
                    }
                });
            });
        });
        </script>
        <?php
    }
    
    /**
     * Check if WordFence is active
     */
    private function is_wordfence_active() {
        return class_exists('wordfence') || class_exists('wfConfig');
    }
    
    /**
     * Check if IP is blocked by WordFence
     */
    private function is_ip_blocked($ip = null) {
        if (!$this->wordfence_enabled) {
            return false;
        }
        
        if ($ip === null) {
            $ip = $this->get_client_ip();
        }
        
        if (class_exists('wordfence') && method_exists('wordfence', 'isIPBlocked')) {
            return wordfence::isIPBlocked($ip);
        }
        
        if (class_exists('wfBlock')) {
            $block = new wfBlock();
            return $block->isIPBlocked($ip);
        }
        
        return false;
    }
    
    /**
     * Get client IP address
     */
    private function get_client_ip() {
        if ($this->wordfence_enabled && class_exists('wfUtils') && method_exists('wfUtils', 'getIP')) {
            return wfUtils::getIP();
        }
        
        $ip_keys = array('HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR');
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
    
    /**
     * Log to WordFence if available
     */
    private function log_to_wordfence($message, $level = 'info', $category = 'API') {
        if (!$this->wordfence_enabled) {
            return;
        }
        
        if (class_exists('wfActivityReport')) {
            try {
                // wfActivityReport::logActivity($category, $message, $level);
            } catch (Exception $e) {
                // Silently fail
            }
        }
        
        if ($level === 'critical' || $level === 'error') {
            if (class_exists('wfLog')) {
                try {
                    wfLog::log($message, $level);
                } catch (Exception $e) {
                    // Silently fail
                }
            }
        }
    }
    
    /**
     * Check rate limiting for API requests
     */
    private function check_rate_limit($identifier) {
        $option_key = 'wc_sync_rate_limit_' . md5($identifier);
        $rate_limit_data = get_transient($option_key);
        
        $max_requests = get_option('wc_sync_rate_limit_max', 60);
        $time_window = get_option('wc_sync_rate_limit_window', 3600);
        
        if ($rate_limit_data === false) {
            set_transient($option_key, array('count' => 1, 'start' => time()), $time_window);
            return true;
        }
        
        if ($rate_limit_data['count'] >= $max_requests) {
            $this->log_to_wordfence("Rate limit exceeded for: {$identifier}", 'warning', 'Security');
            $this->log("Rate limit exceeded for: {$identifier}");
            return false;
        }
        
        $rate_limit_data['count']++;
        set_transient($option_key, $rate_limit_data, $time_window);
        return true;
    }
    
    /**
     * Validate request signature
     */
    private function validate_request_signature($request) {
        $signature = $request->get_header('X-WC-Sync-Signature');
        if (empty($signature)) {
            return false;
        }
        
        $body = $request->get_body();
        $timestamp = $request->get_header('X-WC-Sync-Timestamp');
        
        if (abs(time() - intval($timestamp)) > 300) {
            $this->log_to_wordfence("Request timestamp expired", 'warning', 'Security');
            return false;
        }
        
        $auth_key = get_option('wc_sync_api_auth_key', '');
        $expected_signature = hash_hmac('sha256', $body . $timestamp, $auth_key);
        
        return hash_equals($expected_signature, $signature);
    }
    
    /**
     * Plugin activation
     */
    public function plugin_activation() {
        if (empty(get_option('wc_sync_api_auth_key', ''))) {
            $this->generate_new_auth_key();
        }
        
        if (empty(get_option('wc_sync_rate_limit_max'))) {
            update_option('wc_sync_rate_limit_max', 60);
        }
        if (empty(get_option('wc_sync_rate_limit_window'))) {
            update_option('wc_sync_rate_limit_window', 3600);
        }
        if (empty(get_option('wc_sync_enable_signature'))) {
            update_option('wc_sync_enable_signature', 1);
        }
        if (empty(get_option('qux_product_sync_auto_updates_enabled'))) {
            update_option('qux_product_sync_auto_updates_enabled', 1);
        }
        if (empty(get_option('qux_product_sync_update_server_url'))) {
            update_option('qux_product_sync_update_server_url', $this->update_url);
        }
        
        // Schedule update checks
        $this->schedule_update_checks();
        
        $this->log_to_wordfence("QUX Pay® Product Sync plugin activated", 'info', 'Plugin');
    }
    
    /**
     * Plugin deactivation
     */
    public function plugin_deactivation() {
        $this->unschedule_update_checks();
        $this->log_to_wordfence("QUX Pay® Product Sync plugin deactivated", 'info', 'Plugin');
    }
    
    public function init() {
        register_setting('wc_sync_settings', 'wc_sync_api_url');
        register_setting('wc_sync_settings', 'wc_sync_api_key');
        register_setting('wc_sync_settings', 'wc_sync_secret_key');
        register_setting('wc_sync_settings', 'wc_sync_auto_sync');
        register_setting('wc_sync_settings', 'wc_sync_debug_mode');
        register_setting('wc_sync_settings', 'wc_sync_api_auth_key');
        register_setting('wc_sync_settings', 'wc_sync_rate_limit_max');
        register_setting('wc_sync_settings', 'wc_sync_rate_limit_window');
        register_setting('wc_sync_settings', 'wc_sync_enable_signature');
        register_setting('wc_sync_settings', 'wc_sync_ip_whitelist');
        register_setting('wc_sync_settings', 'qux_product_sync_update_server_url');
        // NOTE: qux_product_sync_auto_updates_enabled is NOT registered here - it uses custom form handling
    }
    
    public function register_api_endpoints() {
        $endpoints = array(
            array('route' => '/sync/all', 'methods' => 'POST', 'callback' => 'api_sync_all_products'),
            array('route' => '/sync/product/(?P<id>\d+)', 'methods' => 'POST', 'callback' => 'api_sync_single_product'),
            array('route' => '/sync/products', 'methods' => 'POST', 'callback' => 'api_sync_multiple_products'),
            array('route' => '/status', 'methods' => 'GET', 'callback' => 'api_get_sync_status'),
            array('route' => '/test', 'methods' => 'POST', 'callback' => 'api_test_connection'),
            array('route' => '/settings', 'methods' => 'GET', 'callback' => 'api_get_settings'),
            array('route' => '/settings', 'methods' => 'POST', 'callback' => 'api_update_settings'),
            array('route' => '/logs', 'methods' => 'GET', 'callback' => 'api_get_logs'),
            array('route' => '/update/product/(?P<id>\d+)', 'methods' => 'PUT', 'callback' => 'api_update_product_from_external'),
            array('route' => '/update/products', 'methods' => 'PUT', 'callback' => 'api_bulk_update_products_from_external'),
            array('route' => '/auth/generate', 'methods' => 'POST', 'callback' => 'api_generate_auth_key'),
            array('route' => '/auth/info', 'methods' => 'GET', 'callback' => 'api_get_auth_info'),
            array('route' => '/security/status', 'methods' => 'GET', 'callback' => 'api_get_security_status'),
        );
        
        foreach ($endpoints as $endpoint) {
            $args = array(
                'methods' => $endpoint['methods'],
                'callback' => array($this, $endpoint['callback']),
                'permission_callback' => array($this, 'api_permission_check'),
            );
            
            if (strpos($endpoint['route'], '(?P<id>\d+)') !== false) {
                $args['args'] = array(
                    'id' => array(
                        'required' => true,
                        'validate_callback' => function($param) { return is_numeric($param); }
                    ),
                );
            }
            
            register_rest_route('wc-sync/v1', $endpoint['route'], $args);
        }
    }
    
    private function generate_new_auth_key() {
        $key = $this->generate_secure_key(64);
        update_option('wc_sync_api_auth_key', $key);
        update_option('wc_sync_last_key_generation', current_time('Y-m-d H:i:s'));
        $this->log('New API authentication key generated');
        $this->log_to_wordfence('New API authentication key generated', 'info', 'Security');
        return $key;
    }
    
    private function generate_secure_key($length = 64) {
        if (function_exists('wp_generate_password')) {
            return wp_generate_password($length, true, true);
        }
        
        if (function_exists('random_bytes')) {
            return bin2hex(random_bytes($length / 2));
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            return bin2hex(openssl_random_pseudo_bytes($length / 2));
        }
        
        $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
        $key = '';
        $max = strlen($characters) - 1;
        
        for ($i = 0; $i < $length; $i++) {
            $key .= $characters[mt_rand(0, $max)];
        }
        
        return $key;
    }
    
    public function ajax_generate_auth_key() {
        check_ajax_referer('wc_sync_nonce', 'nonce');
        
        if (!current_user_can('manage_woocommerce')) {
            wp_die(json_encode(array('success' => false, 'data' => 'Insufficient permissions')));
        }
        
        try {
            $new_key = $this->generate_new_auth_key();
            
            wp_die(json_encode(array(
                'success' => true,
                'data' => array(
                    'new_key' => $new_key,
                    'message' => 'New authentication key generated successfully',
                    'timestamp' => current_time('Y-m-d H:i:s')
                )
            )));
            
        } catch (Exception $e) {
            $this->log('Error generating auth key: ' . $e->getMessage());
            wp_die(json_encode(array('success' => false, 'data' => $e->getMessage())));
        }
    }
    
    public function api_generate_auth_key($request) {
        try {
            $new_key = $this->generate_new_auth_key();
            
            return rest_ensure_response(array(
                'success' => true,
                'data' => array(
                    'new_key' => $new_key,
                    'message' => 'New authentication key generated successfully',
                    'key_length' => strlen($new_key),
                    'timestamp' => current_time('Y-m-d H:i:s')
                )
            ));
            
        } catch (Exception $e) {
            return new WP_Error('generation_failed', $e->getMessage(), array('status' => 500));
        }
    }
    
    public function api_get_auth_info($request) {
        $auth_key = get_option('wc_sync_api_auth_key', '');
        
        return rest_ensure_response(array(
            'success' => true,
            'data' => array(
                'key_configured' => !empty($auth_key),
                'key_length' => strlen($auth_key),
                'key_preview' => !empty($auth_key) ? substr($auth_key, 0, 8) . '...' . substr($auth_key, -8) : '',
                'timestamp' => current_time('Y-m-d H:i:s')
            )
        ));
    }
    
    public function api_permission_check($request) {
        $client_ip = $this->get_client_ip();
        
        if ($this->is_ip_blocked($client_ip)) {
            $this->log_to_wordfence("Blocked IP attempted API access: {$client_ip}", 'critical', 'Security');
            $this->log("Blocked IP attempted API access: {$client_ip}");
            return new WP_Error('ip_blocked', 'Access denied', array('status' => 403));
        }
        
        $ip_whitelist = get_option('wc_sync_ip_whitelist', '');
        if (!empty($ip_whitelist)) {
            $allowed_ips = array_map('trim', explode(',', $ip_whitelist));
            if (!in_array($client_ip, $allowed_ips)) {
                $this->log_to_wordfence("Unauthorized IP attempted API access: {$client_ip}", 'warning', 'Security');
                $this->log("Unauthorized IP attempted API access: {$client_ip}");
                return new WP_Error('ip_not_whitelisted', 'IP not authorized', array('status' => 403));
            }
        }
        
        if (!$this->check_rate_limit($client_ip)) {
            return new WP_Error('rate_limit_exceeded', 'Too many requests', array('status' => 429));
        }
        
        $auth_key = get_option('wc_sync_api_auth_key', '');
        if (empty($auth_key)) {
            return new WP_Error('no_auth_key', 'API authentication key not configured', array('status' => 401));
        }
        
        $provided_key = $request->get_header('X-WC-Sync-Auth');
        if (empty($provided_key)) {
            $provided_key = $request->get_param('auth_key');
        }
        
        if ($provided_key !== $auth_key) {
            $this->log_to_wordfence("Invalid API authentication attempt from: {$client_ip}", 'warning', 'Security');
            $this->log("Invalid API authentication attempt from: {$client_ip}");
            return new WP_Error('invalid_auth_key', 'Invalid authentication key', array('status' => 401));
        }
        
        if (get_option('wc_sync_enable_signature', 1) && in_array($request->get_method(), array('POST', 'PUT'))) {
            if (!$this->validate_request_signature($request)) {
                $this->log_to_wordfence("Invalid request signature from: {$client_ip}", 'warning', 'Security');
                $this->log("Invalid request signature from: {$client_ip}");
                return new WP_Error('invalid_signature', 'Invalid request signature', array('status' => 401));
            }
        }
        
        $this->log_to_wordfence("Successful API authentication from: {$client_ip}", 'info', 'API');
        
        return true;
    }
    
    public function api_get_security_status($request) {
        $client_ip = $this->get_client_ip();
        
        return rest_ensure_response(array(
            'success' => true,
            'data' => array(
                'wordfence_active' => $this->wordfence_enabled,
                'client_ip' => $client_ip,
                'ip_blocked' => $this->is_ip_blocked($client_ip),
                'rate_limit_max' => get_option('wc_sync_rate_limit_max', 60),
                'rate_limit_window' => get_option('wc_sync_rate_limit_window', 3600),
                'signature_validation' => (bool) get_option('wc_sync_enable_signature', 1),
                'ip_whitelist_enabled' => !empty(get_option('wc_sync_ip_whitelist', '')),
                'timestamp' => current_time('Y-m-d H:i:s')
            )
        ));
    }
    
    public function api_update_product_from_external($request) {
        $product_id = $request->get_param('id');
        $update_data = $request->get_json_params();
        
        $product = wc_get_product($product_id);
        if (!$product) {
            return new WP_Error('product_not_found', 'Product not found', array('status' => 404));
        }
        
        try {
            $result = $this->update_product_from_external_data($product, $update_data);
            
            if (is_wp_error($result)) {
                return $result;
            }
            
            $this->log('Product updated from external API: ' . $product_id);
            $this->log_to_wordfence("Product {$product_id} updated via API", 'info', 'API');
            
            return rest_ensure_response(array(
                'success' => true,
                'data' => array(
                    'product_id' => $product_id,
                    'product_name' => $product->get_name(),
                    'updated_fields' => $result,
                    'timestamp' => current_time('Y-m-d H:i:s')
                )
            ));
            
        } catch (Exception $e) {
            $this->log('Error updating product from external API: ' . $e->getMessage());
            $this->log_to_wordfence("Error updating product {$product_id}: " . $e->getMessage(), 'error', 'API');
            return new WP_Error('update_failed', $e->getMessage(), array('status' => 500));
        }
    }
    
    private function update_product_from_external_data($product, $data) {
        $updated_fields = array();
        
        remove_action('woocommerce_update_product', array($this, 'sync_single_product'), 10);
        
        try {
            if (isset($data['name'])) {
                $product->set_name(sanitize_text_field($data['name']));
                $updated_fields[] = 'name';
            }
            
            if (isset($data['description'])) {
                $product->set_description(wp_kses_post($data['description']));
                $updated_fields[] = 'description';
            }
            
            if (isset($data['short_description'])) {
                $product->set_short_description(wp_kses_post($data['short_description']));
                $updated_fields[] = 'short_description';
            }
            
            if (isset($data['sku'])) {
                $sku = sanitize_text_field($data['sku']);
                if (!empty($sku) && $this->is_sku_unique($sku, $product->get_id())) {
                    $product->set_sku($sku);
                    $updated_fields[] = 'sku';
                } elseif (!empty($sku)) {
                    return new WP_Error('duplicate_sku', 'SKU already exists');
                }
            }
            
            if (isset($data['regular_price'])) {
                $product->set_regular_price(wc_format_decimal($data['regular_price']));
                $updated_fields[] = 'regular_price';
            }
            
            if (isset($data['sale_price'])) {
                $product->set_sale_price(wc_format_decimal($data['sale_price']));
                $updated_fields[] = 'sale_price';
            }
            
            if (isset($data['stock_quantity'])) {
                $product->set_stock_quantity(wc_stock_amount($data['stock_quantity']));
                $updated_fields[] = 'stock_quantity';
            }
            
            if (isset($data['stock_status'])) {
                $status = sanitize_text_field($data['stock_status']);
                if (in_array($status, array('instock', 'outofstock', 'onbackorder'))) {
                    $product->set_stock_status($status);
                    $updated_fields[] = 'stock_status';
                }
            }
            
            $product->save();
            
            return $updated_fields;
            
        } finally {
            add_action('woocommerce_update_product', array($this, 'sync_single_product'), 10, 1);
        }
    }
    
    private function is_sku_unique($sku, $product_id) {
        $existing_id = wc_get_product_id_by_sku($sku);
        return !$existing_id || $existing_id == $product_id;
    }
    
    public function admin_menu() {
        add_submenu_page(
            'woocommerce',
            'QUX Pay® Product Sync',
            'QUX Pay® Product Sync',
            'manage_woocommerce',
            'wc-product-sync',
            array($this, 'admin_page')
        );
    }
    
    public function admin_page() {
        $active_tab = isset($_GET['tab']) ? $_GET['tab'] : 'settings';
        ?>
        <div class="wrap">
            <h1>QUX Pay® Product Sync</h1>
            
            <?php if ($this->wordfence_enabled): ?>
            <div class="notice notice-success">
                <p><span class="dashicons dashicons-shield"></span> <strong>WordFence Integration Active</strong> - Enhanced security features enabled</p>
            </div>
            <?php else: ?>
            <div class="notice notice-warning">
                <p><span class="dashicons dashicons-warning"></span> WordFence not detected. Install WordFence for enhanced security features.</p>
            </div>
            <?php endif; ?>
            
            <h2 class="nav-tab-wrapper">
                <a href="?page=wc-product-sync&tab=settings" class="nav-tab <?php echo $active_tab == 'settings' ? 'nav-tab-active' : ''; ?>">Settings</a>
                <a href="?page=wc-product-sync&tab=updates" class="nav-tab <?php echo $active_tab == 'updates' ? 'nav-tab-active' : ''; ?>">Auto-Updates</a>
                <a href="?page=wc-product-sync&tab=sync" class="nav-tab <?php echo $active_tab == 'sync' ? 'nav-tab-active' : ''; ?>">Sync Actions</a>
            </h2>
            
            <div id="sync-messages"></div>
            
            <?php if ($active_tab == 'settings'): ?>
            <div class="postbox">
                <h2>API Settings</h2>
                <div class="inside">
                    <form method="post" action="options.php">
                        <?php settings_fields('wc_sync_settings'); ?>
                        <table class="form-table">
                            <tr>
                                <th scope="row">API Key</th>
                                <td>
                                    <input type="password" name="wc_sync_api_key" value="<?php echo esc_attr($this->api_key); ?>" class="regular-text" />
                                    <p class="description">Enter your API key for authentication</p>
                                </td>
                            </tr>
                            <tr>
                                <th scope="row">Secret Key</th>
                                <td>
                                    <input type="password" name="wc_sync_secret_key" value="<?php echo esc_attr($this->secret_key); ?>" class="regular-text" />
                                    <p class="description">Enter your Secret key for authentication</p>
                                </td>
                            </tr>
                            <tr>
                                <th scope="row">Auto Sync</th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="wc_sync_auto_sync" value="1" <?php checked(get_option('wc_sync_auto_sync', 1)); ?> />
                                        Automatically sync products when created/updated
                                    </label>
                                </td>
                            </tr>
                            <tr>
                                <th scope="row">Debug Mode</th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="wc_sync_debug_mode" value="1" <?php checked(get_option('wc_sync_debug_mode', 0)); ?> />
                                        Enable debug logging
                                    </label>
                                </td>
                            </tr>
                            <tr>
                                <th scope="row">API Authentication Key</th>
                                <td>
                                    <div class="auth-key-container">
                                        <input type="password" name="wc_sync_api_auth_key" id="auth-key-input" value="<?php echo esc_attr(get_option('wc_sync_api_auth_key', '')); ?>" class="regular-text" readonly />
                                        <button type="button" class="button button-secondary" id="toggle-auth-key">
                                            <span class="dashicons dashicons-visibility"></span> Show
                                        </button>
                                        <button type="button" class="button button-secondary" id="copy-auth-key">
                                            <span class="dashicons dashicons-clipboard"></span> Copy
                                        </button>
                                        <button type="button" class="button button-primary" id="generate-auth-key">
                                            <span class="dashicons dashicons-update"></span> Generate New Key
                                        </button>
                                    </div>
                                    <p class="description">
                                        Secure key for API authentication. <strong>Warning:</strong> Generating a new key will invalidate the current one.
                                    </p>
                                </td>
                            </tr>
                        </table>
                        
                        <h3>Security Settings <?php if ($this->wordfence_enabled): ?><span class="dashicons dashicons-shield" style="color: green;"></span><?php endif; ?></h3>
                        <table class="form-table">
                            <tr>
                                <th scope="row">Enable Request Signatures</th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="wc_sync_enable_signature" value="1" <?php checked(get_option('wc_sync_enable_signature', 1)); ?> />
                                        Require HMAC-SHA256 signatures for POST/PUT requests
                                    </label>
                                    <p class="description">Prevents replay attacks and unauthorized modifications</p>
                                </td>
                            </tr>
                            <tr>
                                <th scope="row">Rate Limit - Max Requests</th>
                                <td>
                                    <input type="number" name="wc_sync_rate_limit_max" value="<?php echo esc_attr(get_option('wc_sync_rate_limit_max', 60)); ?>" min="1" max="1000" />
                                    <p class="description">Maximum number of API requests allowed per time window</p>
                                </td>
                            </tr>
                            <tr>
                                <th scope="row">Rate Limit - Time Window (seconds)</th>
                                <td>
                                    <input type="number" name="wc_sync_rate_limit_window" value="<?php echo esc_attr(get_option('wc_sync_rate_limit_window', 3600)); ?>" min="60" max="86400" />
                                    <p class="description">Time window in seconds (3600 = 1 hour)</p>
                                </td>
                            </tr>
                            <tr>
                                <th scope="row">IP Whitelist</th>
                                <td>
                                    <textarea name="wc_sync_ip_whitelist" class="large-text" rows="3"><?php echo esc_textarea(get_option('wc_sync_ip_whitelist', '')); ?></textarea>
                                    <p class="description">Comma-separated list of allowed IP addresses. Leave empty to allow all IPs (not recommended). Example: 192.168.1.1, 10.0.0.1</p>
                                </td>
                            </tr>
                            <tr>
                                <th scope="row">Security Status</th>
                                <td>
                                    <ul style="list-style: disc; padding-left: 20px;">
                                        <li><strong>WordFence:</strong> <?php echo $this->wordfence_enabled ? '<span style="color: green;">✓ Active</span>' : '<span style="color: orange;">○ Not Installed</span>'; ?></li>
                                        <li><strong>Authentication Key:</strong> <?php echo !empty(get_option('wc_sync_api_auth_key', '')) ? '<span style="color: green;">✓ Configured</span>' : '<span style="color: red;">✗ Not Set</span>'; ?></li>
                                        <li><strong>Rate Limiting:</strong> <span style="color: green;">✓ Enabled</span></li>
                                        <li><strong>Request Signatures:</strong> <?php echo get_option('wc_sync_enable_signature', 1) ? '<span style="color: green;">✓ Enabled</span>' : '<span style="color: orange;">○ Disabled</span>'; ?></li>
                                        <li><strong>IP Whitelist:</strong> <?php echo !empty(get_option('wc_sync_ip_whitelist', '')) ? '<span style="color: green;">✓ Active</span>' : '<span style="color: orange;">○ Disabled</span>'; ?></li>
                                    </ul>
                                </td>
                            </tr>
                        </table>
                        
                        <?php submit_button('Save Settings'); ?>
                    </form>
                </div>
            </div>
            
            <?php elseif ($active_tab == 'updates'): ?>
            <div class="postbox">
                <h2>Auto-Update Settings</h2>
                <div class="inside">
                    <?php
                    $auto_updates_enabled = get_option('qux_product_sync_auto_updates_enabled', 1);
                    $current_version = $this->get_plugin_version();
                    $next_check = wp_next_scheduled('qux_product_sync_check_updates');
                    
                    // Handle form submission
                    if (isset($_POST['save_update_settings']) && check_admin_referer('wc_sync_update_settings')) {
                        $new_value = isset($_POST['qux_product_sync_auto_updates_enabled']) ? 1 : 0;
                        update_option('qux_product_sync_auto_updates_enabled', $new_value);
                        
                        echo '<div class="notice notice-success is-dismissible"><p>Auto-update settings saved successfully.</p></div>';
                        $auto_updates_enabled = $new_value;
                        
                        $this->log('Auto-updates ' . ($new_value ? 'enabled' : 'disabled'));
                        $this->log_to_wordfence('Auto-updates ' . ($new_value ? 'enabled' : 'disabled'), 'info', 'Settings');
                    }
                    ?>
                    
                    <form method="post" action="">
                        <?php wp_nonce_field('wc_sync_update_settings'); ?>
                        <input type="hidden" name="save_update_settings" value="1" />
                        
                        <table class="form-table">
                            <tr>
                                <th scope="row">Current Version</th>
                                <td>
                                    <strong><?php echo esc_html($current_version); ?></strong>
                                </td>
                            </tr>
                            <tr>
                                <th scope="row">Enable Auto-Updates</th>
                                <td>
                                    <label>
                                        <input type="checkbox" name="qux_product_sync_auto_updates_enabled" value="1" <?php checked($auto_updates_enabled); ?> />
                                        Automatically check for and notify about plugin updates
                                    </label>
                                    <p class="description">When enabled, the plugin will check for updates twice daily</p>
                                </td>
                            </tr>
                            <tr>
                                <th scope="row">Next Scheduled Check</th>
                                <td>
                                    <?php if ($next_check): ?>
                                        <strong><?php echo date('Y-m-d H:i:s', $next_check); ?></strong>
                                    <?php else: ?>
                                        <em>Not scheduled - Please deactivate and reactivate the plugin</em>
                                    <?php endif; ?>
                                </td>
                            </tr>
                            <tr>
                                <th scope="row">Check for Updates</th>
                                <td>
                                    <button type="button" class="button button-secondary" id="check-updates-now">
                                        <span class="dashicons dashicons-update"></span> Check Now
                                    </button>
                                    <p class="description">Manually check for available updates</p>
                                    <div id="update-check-result" style="margin-top: 10px;"></div>
                                </td>
                            </tr>
                        </table>
                        
                        <?php submit_button('Save Update Settings'); ?>
                    </form>
                </div>
            </div>
            
            <?php elseif ($active_tab == 'sync'): ?>
            <div class="postbox">
                <h2>Sync Actions</h2>
                <div class="inside">
                    <p>
                        <button type="button" class="button button-primary" id="sync-all-products">Sync All Products</button>
                    </p>
                </div>
            </div>
            <?php endif; ?>
            
            <?php if ($this->wordfence_enabled): ?>
            <div class="postbox">
                <h2><span class="dashicons dashicons-shield"></span> WordFence Integration</h2>
                <div class="inside">
                    <p>WordFence security features are active and protecting your API endpoints:</p>
                    <ul style="list-style: disc; padding-left: 20px;">
                        <li>Blocked IP detection and prevention</li>
                        <li>Advanced IP address detection</li>
                        <li>Security event logging integration</li>
                        <li>Activity monitoring</li>
                    </ul>
                    <p><a href="<?php echo admin_url('admin.php?page=WordfenceLiveTraffic'); ?>" class="button button-secondary">View WordFence Live Traffic</a></p>
                </div>
            </div>
            <?php endif; ?>
        </div>
        
        <style>
        .auth-key-container { display: flex; align-items: center; gap: 5px; }
        .auth-key-container input[type="password"], .auth-key-container input[type="text"] { min-width: 400px; font-family: monospace; }
        .postbox { margin-top: 20px; }
        .postbox h2 { padding: 10px; margin: 0; background: #f1f1f1; }
        .postbox .inside { padding: 15px; }
        .sync-success { background: #d4edda; color: #155724; padding: 10px; border-radius: 5px; margin: 10px 0; }
        .sync-error { background: #f8d7da; color: #721c24; padding: 10px; border-radius: 5px; margin: 10px 0; }
        .sync-warning { background: #fff3cd; color: #856404; padding: 10px; border-radius: 5px; margin: 10px 0; }
        .sync-info { background: #d1ecf1; color: #0c5460; padding: 10px; border-radius: 5px; margin: 10px 0; }
        </style>
        
        <script>
        jQuery(document).ready(function($) {
            var authKeyInput = $('#auth-key-input');
            var originalKeyValue = authKeyInput.val();
            var isKeyVisible = false;
            
            $('#toggle-auth-key').click(function() {
                var btn = $(this);
                if (isKeyVisible) {
                    authKeyInput.attr('type', 'password');
                    btn.html('<span class="dashicons dashicons-visibility"></span> Show');
                    isKeyVisible = false;
                } else {
                    authKeyInput.attr('type', 'text');
                    btn.html('<span class="dashicons dashicons-hidden"></span> Hide');
                    isKeyVisible = true;
                }
            });
            
            $('#copy-auth-key').click(function() {
                var btn = $(this);
                var originalHtml = btn.html();
                
                var tempInput = $('<input>');
                $('body').append(tempInput);
                tempInput.val(originalKeyValue).select();
                document.execCommand('copy');
                tempInput.remove();
                
                btn.html('<span class="dashicons dashicons-yes"></span> Copied!');
                setTimeout(function() {
                    btn.html(originalHtml);
                }, 2000);
            });
            
            $('#generate-auth-key').click(function() {
                if (!confirm('Are you sure you want to generate a new authentication key? This will invalidate the current key and may break existing integrations.')) {
                    return;
                }
                
                var btn = $(this);
                var originalHtml = btn.html();
                btn.prop('disabled', true).html('<span class="dashicons dashicons-update"></span> Generating...');
                
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'generate_auth_key',
                        nonce: '<?php echo wp_create_nonce('wc_sync_nonce'); ?>'
                    },
                    success: function(response) {
                        if (response.success) {
                            var newKey = response.data.new_key;
                            originalKeyValue = newKey;
                            authKeyInput.val(newKey);
                            $('#sync-messages').html('<div class="sync-success"><strong>Success!</strong> New authentication key generated. Make sure to update your external API integration with the new key.</div>');
                        } else {
                            $('#sync-messages').html('<div class="sync-error">Failed to generate new key: ' + response.data + '</div>');
                        }
                    },
                    error: function() {
                        $('#sync-messages').html('<div class="sync-error">AJAX request failed</div>');
                    },
                    complete: function() {
                        btn.prop('disabled', false).html(originalHtml);
                    }
                });
            });
            
            $('#check-updates-now').click(function() {
                var btn = $(this);
                var originalHtml = btn.html();
                var resultDiv = $('#update-check-result');
                
                btn.prop('disabled', true).html('<span class="dashicons dashicons-update"></span> Checking...');
                resultDiv.html('');
                
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'check_updates_now',
                        nonce: '<?php echo wp_create_nonce('qux_product_sync_nonce'); ?>'
                    },
                    success: function(response) {
                        var data = JSON.parse(response);
                        if (data.success) {
                            var html = '<div class="sync-info">';
                            html += '<strong>Current Version:</strong> ' + data.current_version + '<br>';
                            html += '<strong>Latest Version:</strong> ' + data.remote_version + '<br>';
                            
                            if (data.update_available) {
                                html += '<strong style="color: #0073aa;">Update Available!</strong> Please visit the Plugins page to update.';
                            } else {
                                html += '<strong style="color: green;">You are running the latest version.</strong>';
                            }
                            html += '</div>';
                            resultDiv.html(html);
                        } else {
                            resultDiv.html('<div class="sync-error">Error: ' + data.message + '</div>');
                        }
                    },
                    error: function() {
                        resultDiv.html('<div class="sync-error">AJAX request failed</div>');
                    },
                    complete: function() {
                        btn.prop('disabled', false).html(originalHtml);
                    }
                });
            });
            
            $('#sync-all-products').click(function() {
                if (!confirm('This will sync all products to the external API. Continue?')) {
                    return;
                }
                
                var btn = $(this);
                btn.prop('disabled', true).text('Syncing...');
                
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'sync_all_products',
                        nonce: '<?php echo wp_create_nonce('qux_product_sync_nonce'); ?>'
                    },
                    success: function(response) {
                        var data = JSON.parse(response);
                        if (data.success) {
                            $('#sync-messages').html('<div class="sync-success"><strong>Success!</strong> All products synced successfully! ' + data.data.synced + ' products processed.</div>');
                        } else {
                            $('#sync-messages').html('<div class="sync-error"><strong>Error:</strong> Sync failed: ' + data.data + '</div>');
                        }
                    },
                    error: function() {
                        $('#sync-messages').html('<div class="sync-error">AJAX request failed</div>');
                    },
                    complete: function() {
                        btn.prop('disabled', false).text('Sync All Products');
                    }
                });
            });
        });
        </script>
        <?php
    }
    
    public function ajax_test_api_connection() {
        check_ajax_referer('qux_product_sync_nonce', 'nonce');
        
        if (empty($this->api_url)) {
            wp_die(json_encode(array('success' => false, 'data' => 'API URL not configured')));
        }
        
        $response = wp_remote_get($this->api_url, array(
            'headers' => array(
                'Api-Key' => $this->api_key,
                'Secret-Key' => $this->secret_key,
                'Content-Type' => 'application/json'
            ),
            'timeout' => 30
        ));
        
        if (is_wp_error($response)) {
            wp_die(json_encode(array('success' => false, 'data' => $response->get_error_message())));
        }
        
        $status_code = wp_remote_retrieve_response_code($response);
        if ($status_code >= 200 && $status_code < 300) {
            wp_die(json_encode(array('success' => true, 'data' => 'Connection successful')));
        } else {
            wp_die(json_encode(array('success' => false, 'data' => 'HTTP ' . $status_code)));
        }
    }
    
    public function ajax_sync_all_products() {
        check_ajax_referer('qux_product_sync_nonce', 'nonce');
        
        $products = wc_get_products(array('limit' => -1, 'status' => 'publish'));
        
        $synced = 0;
        $errors = 0;
        
        foreach ($products as $product) {
            $result = $this->send_product_to_api($product);
            if ($result) {
                $synced++;
            } else {
                $errors++;
            }
        }
        
        update_option('wc_sync_last_full_sync', current_time('Y-m-d H:i:s'));
        update_option('wc_sync_count', get_option('wc_sync_count', 0) + $synced);
        
        $this->log_to_wordfence("Bulk sync completed: {$synced} products synced, {$errors} errors", 'info', 'API');
        
        wp_die(json_encode(array(
            'success' => true,
            'data' => array('synced' => $synced, 'errors' => $errors, 'total' => count($products))
        )));
    }
    
    private function send_product_to_api($product) {
        if (empty($this->api_url)) {
            return false;
        }
        
        $product_data = $this->prepare_product_data($product);
        
        $response = wp_remote_post($this->api_url, array(
            'body' => wp_json_encode($product_data),
            'headers' => array(
                'Api-Key' => $this->api_key,
                'Secret-Key' => $this->secret_key,
                'Content-Type' => 'application/json'
            ),
            'timeout' => 30
        ));
        
        if (is_wp_error($response)) {
            $this->log('Error syncing product ' . $product->get_id() . ': ' . $response->get_error_message());
            return false;
        }
        
        $status_code = wp_remote_retrieve_response_code($response);
        if ($status_code >= 200 && $status_code < 300) {
            $this->log('Product synced successfully: ' . $product->get_id());
            return true;
        } else {
            $this->log('Error syncing product ' . $product->get_id() . ': HTTP ' . $status_code);
            return false;
        }
    }
    
    private function prepare_product_data($product) {
        return array(
            'id' => $product->get_id(),
            'name' => $product->get_name(),
            'slug' => $product->get_slug(),
            'type' => $product->get_type(),
            'status' => $product->get_status(),
            'featured' => $product->is_featured(),
            'catalog_visibility' => $product->get_catalog_visibility(),
            'description' => $product->get_description(),
            'short_description' => $product->get_short_description(),
            'sku' => $product->get_sku(),
            'price' => $product->get_price(),
            'regular_price' => $product->get_regular_price(),
            'sale_price' => $product->get_sale_price(),
            'stock_quantity' => $product->get_stock_quantity(),
            'stock_status' => $product->get_stock_status(),
            'categories' => $this->get_product_categories($product),
            'tags' => $this->get_product_tags($product),
            'images' => $this->get_product_images($product),
        );
    }
    
    private function get_product_categories($product) {
        $categories = array();
        $terms = get_the_terms($product->get_id(), 'product_cat');
        if ($terms && !is_wp_error($terms)) {
            foreach ($terms as $term) {
                $categories[] = array('id' => $term->term_id, 'name' => $term->name, 'slug' => $term->slug);
            }
        }
        return $categories;
    }
    
    private function get_product_tags($product) {
        $tags = array();
        $terms = get_the_terms($product->get_id(), 'product_tag');
        if ($terms && !is_wp_error($terms)) {
            foreach ($terms as $term) {
                $tags[] = array('id' => $term->term_id, 'name' => $term->name, 'slug' => $term->slug);
            }
        }
        return $tags;
    }
    
    private function get_product_images($product) {
        $images = array();
        $image_ids = $product->get_gallery_image_ids();
        if ($product->get_image_id()) {
            array_unshift($image_ids, $product->get_image_id());
        }
        foreach ($image_ids as $image_id) {
            $image = wp_get_attachment_image_src($image_id, 'full');
            if ($image) {
                $images[] = array('id' => $image_id, 'src' => $image[0], 'name' => get_the_title($image_id));
            }
        }
        return $images;
    }
    
    public function sync_single_product($product_id) {
        if (!get_option('wc_sync_auto_sync', 1)) {
            return;
        }
        $product = wc_get_product($product_id);
        if ($product) {
            $this->send_product_to_api($product);
        }
    }
    
    public function delete_product_from_api($product_id) {
        if (empty($this->api_url)) {
            return false;
        }
        $response = wp_remote_request($this->api_url . '/' . $product_id, array(
            'method' => 'DELETE',
            'headers' => array(
                'Api-Key' => $this->api_key,
                'Secret-Key' => $this->secret_key,
                'Content-Type' => 'application/json'
            ),
            'timeout' => 30
        ));
        $this->log('Product deleted from API: ' . $product_id);
        $this->log_to_wordfence("Product {$product_id} deleted via API", 'info', 'API');
        return !is_wp_error($response);
    }
    
    public function add_bulk_sync_action($bulk_actions) {
        $bulk_actions['sync_to_api'] = 'Sync to API';
        return $bulk_actions;
    }
    
    public function handle_bulk_sync_action($redirect_to, $doaction, $post_ids) {
        if ($doaction !== 'sync_to_api') {
            return $redirect_to;
        }
        $synced = 0;
        foreach ($post_ids as $post_id) {
            $product = wc_get_product($post_id);
            if ($product && $this->send_product_to_api($product)) {
                $synced++;
            }
        }
        $this->log_to_wordfence("Bulk sync action: {$synced} products synced", 'info', 'API');
        return add_query_arg('bulk_sync_products', $synced, $redirect_to);
    }
    
    public function api_bulk_update_products_from_external($request) {
        $products_data = $request->get_param('products');
        $updated = 0;
        $errors = 0;
        $results = array();
        
        foreach ($products_data as $product_data) {
            if (!isset($product_data['id'])) {
                $errors++;
                $results[] = array('product_id' => 'unknown', 'success' => false, 'error' => 'Product ID is required');
                continue;
            }
            
            $product_id = $product_data['id'];
            $product = wc_get_product($product_id);
            
            if (!$product) {
                $errors++;
                $results[] = array('product_id' => $product_id, 'success' => false, 'error' => 'Product not found');
                continue;
            }
            
            try {
                $result = $this->update_product_from_external_data($product, $product_data);
                
                if (is_wp_error($result)) {
                    $errors++;
                    $results[] = array('product_id' => $product_id, 'success' => false, 'error' => $result->get_error_message());
                } else {
                    $updated++;
                    $results[] = array('product_id' => $product_id, 'product_name' => $product->get_name(), 'success' => true, 'updated_fields' => $result);
                }
            } catch (Exception $e) {
                $errors++;
                $results[] = array('product_id' => $product_id, 'success' => false, 'error' => $e->getMessage());
            }
        }
        
        $this->log("Bulk update from external API: {$updated} updated, {$errors} errors");
        $this->log_to_wordfence("Bulk update completed: {$updated} products updated, {$errors} errors", 'info', 'API');
        
        return rest_ensure_response(array(
            'success' => true,
            'data' => array('updated' => $updated, 'errors' => $errors, 'total' => count($products_data), 'results' => $results, 'timestamp' => current_time('Y-m-d H:i:s'))
        ));
    }
    
    public function api_sync_all_products($request) {
        $products = wc_get_products(array('limit' => -1, 'status' => 'publish'));
        $synced = 0;
        $errors = 0;
        
        foreach ($products as $product) {
            if ($this->send_product_to_api($product)) {
                $synced++;
            } else {
                $errors++;
            }
        }
        
        update_option('wc_sync_last_full_sync', current_time('Y-m-d H:i:s'));
        update_option('wc_sync_count', get_option('wc_sync_count', 0) + $synced);
        $this->log_to_wordfence("Full sync via API: {$synced} products synced, {$errors} errors", 'info', 'API');
        
        return rest_ensure_response(array(
            'success' => true,
            'data' => array('synced' => $synced, 'errors' => $errors, 'total' => count($products), 'timestamp' => current_time('Y-m-d H:i:s'))
        ));
    }
    
    public function api_sync_single_product($request) {
        $product_id = $request->get_param('id');
        $product = wc_get_product($product_id);
        
        if (!$product) {
            return new WP_Error('product_not_found', 'Product not found', array('status' => 404));
        }
        
        if ($this->send_product_to_api($product)) {
            update_option('wc_sync_count', get_option('wc_sync_count', 0) + 1);
            $this->log_to_wordfence("Single product {$product_id} synced via API", 'info', 'API');
            return rest_ensure_response(array('success' => true, 'data' => array('product_id' => $product_id, 'product_name' => $product->get_name(), 'synced' => true, 'timestamp' => current_time('Y-m-d H:i:s'))));
        }
        
        return new WP_Error('sync_failed', 'Failed to sync product to external API', array('status' => 500));
    }
    
    public function api_sync_multiple_products($request) {
        $product_ids = $request->get_param('product_ids');
        $synced = 0;
        $errors = 0;
        $results = array();
        
        foreach ($product_ids as $product_id) {
            $product = wc_get_product($product_id);
            if (!$product) {
                $errors++;
                $results[] = array('product_id' => $product_id, 'success' => false, 'error' => 'Product not found');
                continue;
            }
            
            if ($this->send_product_to_api($product)) {
                $synced++;
                $results[] = array('product_id' => $product_id, 'product_name' => $product->get_name(), 'success' => true);
            } else {
                $errors++;
                $results[] = array('product_id' => $product_id, 'product_name' => $product->get_name(), 'success' => false, 'error' => 'Failed to sync');
            }
        }
        
        if ($synced > 0) {
            update_option('wc_sync_count', get_option('wc_sync_count', 0) + $synced);
        }
        $this->log_to_wordfence("Multiple products synced: {$synced} synced, {$errors} errors", 'info', 'API');
        
        return rest_ensure_response(array(
            'success' => true,
            'data' => array('synced' => $synced, 'errors' => $errors, 'total' => count($product_ids), 'results' => $results, 'timestamp' => current_time('Y-m-d H:i:s'))
        ));
    }
    
    public function api_get_sync_status($request) {
        return rest_ensure_response(array(
            'success' => true,
            'data' => array(
                'total_products' => wp_count_posts('product')->publish,
                'last_full_sync' => get_option('wc_sync_last_full_sync', 'Never'),
                'products_synced' => get_option('wc_sync_count', 0),
                'auto_sync_enabled' => (bool) get_option('wc_sync_auto_sync', 1),
                'debug_mode_enabled' => (bool) get_option('wc_sync_debug_mode', 0),
                'wordfence_active' => $this->wordfence_enabled,
                'timestamp' => current_time('Y-m-d H:i:s')
            )
        ));
    }
    
    public function api_test_connection($request) {
        if (empty($this->api_url)) {
            return new WP_Error('no_api_url', 'API URL not configured', array('status' => 400));
        }
        
        $response = wp_remote_get($this->api_url, array(
            'headers' => array('Api-Key' => $this->api_key, 'Secret-Key' => $this->secret_key, 'Content-Type' => 'application/json'),
            'timeout' => 30
        ));
        
        if (is_wp_error($response)) {
            $this->log_to_wordfence("API connection test failed: " . $response->get_error_message(), 'warning', 'API');
            return new WP_Error('connection_failed', $response->get_error_message(), array('status' => 500));
        }
        
        $status_code = wp_remote_retrieve_response_code($response);
        $success = ($status_code >= 200 && $status_code < 300);
        
        $this->log_to_wordfence("API connection test " . ($success ? 'successful' : "failed with status {$status_code}"), $success ? 'info' : 'warning', 'API');
        
        return rest_ensure_response(array('success' => $success, 'data' => array('status_code' => $status_code, 'timestamp' => current_time('Y-m-d H:i:s'))));
    }
    
    public function api_get_settings($request) {
        return rest_ensure_response(array(
            'success' => true,
            'data' => array(
                'api_url' => $this->api_url,
                'auto_sync' => get_option('wc_sync_auto_sync', 1),
                'debug_mode' => get_option('wc_sync_debug_mode', 0),
                'wordfence_active' => $this->wordfence_enabled
            )
        ));
    }
    
    public function api_update_settings($request) {
        $settings = $request->get_json_params();
        $updated = array();
        
        if (isset($settings['api_url'])) {
            update_option('wc_sync_api_url', sanitize_url($settings['api_url']));
            $this->api_url = $settings['api_url'];
            $updated[] = 'api_url';
        }
        
        $this->log_to_wordfence("Settings updated via API: " . implode(', ', $updated), 'info', 'Settings');
        return rest_ensure_response(array('success' => true, 'data' => array('updated_settings' => $updated, 'timestamp' => current_time('Y-m-d H:i:s'))));
    }
    
    public function api_get_logs($request) {
        $lines = $request->get_param('lines') ?: 100;
        
        if (!file_exists($this->log_file)) {
            return rest_ensure_response(array('success' => true, 'data' => array('logs' => array(), 'message' => 'No log file found')));
        }
        
        $logs = array();
        $file = new SplFileObject($this->log_file);
        $file->seek(PHP_INT_MAX);
        $total_lines = $file->key();
        
        $start_line = max(0, $total_lines - $lines);
        $file->seek($start_line);
        
        while (!$file->eof()) {
            $line = trim($file->fgets());
            if (!empty($line)) {
                $logs[] = $line;
            }
        }
        
        return rest_ensure_response(array('success' => true, 'data' => array('logs' => $logs, 'total_lines' => $total_lines, 'showing_lines' => count($logs))));
    }
    
    private function log($message) {
        if (get_option('wc_sync_debug_mode', 0)) {
            $timestamp = current_time('Y-m-d H:i:s');
            error_log("[$timestamp] WC Product Sync: $message\n", 3, $this->log_file);
        }
    }
}

new QuxProductSync();

add_action('admin_notices', function() {
    if (!empty($_REQUEST['bulk_sync_products'])) {
        $synced = intval($_REQUEST['bulk_sync_products']);
        printf('<div class="notice notice-success is-dismissible"><p>%d products synced to API.</p></div>', $synced);
    }
});
?>