<?php
namespace QuxSync\Admin;

use QuxSync\Security\WordfenceIntegration;

class AdminSettings {
    
    public function __construct() {
        add_action('init', [$this, 'register_settings']);
        add_action('admin_menu', [$this, 'add_menu']);
        add_action('wp_ajax_sync_all_products', [$this, 'ajax_sync_all']);
        add_action('wp_ajax_generate_auth_key', [$this, 'ajax_generate_key']);
    }
    
    public function register_settings() {
        $settings = [
            'wc_sync_api_url',
            'wc_sync_api_key',
            'wc_sync_secret_key',
            'wc_sync_auto_sync',
            'wc_sync_debug_mode',
            'wc_sync_api_auth_key',
            'wc_sync_rate_limit_max',
            'wc_sync_rate_limit_window',
            'wc_sync_enable_signature',
            'wc_sync_ip_whitelist',
            'qux_product_sync_update_server_url'
        ];
        
        foreach ($settings as $setting) {
            register_setting('wc_sync_settings', $setting);
        }
    }
    
    public function add_menu() {
        add_submenu_page(
            'woocommerce',
            'QUX Pay® Product Sync',
            'QUX Pay® Product Sync',
            'manage_woocommerce',
            'wc-product-sync',
            [$this, 'render_page']
        );
    }
    
    public function render_page() {
        require_once QUX_SYNC_PLUGIN_DIR . 'includes/admin/class-admin-pages.php';
        $pages = new AdminPages();
        $pages->render();
    }
    
    public function ajax_sync_all() {
        check_ajax_referer('qux_product_sync_nonce', 'nonce');
        
        require_once QUX_SYNC_PLUGIN_DIR . 'includes/sync/class-bulk-sync.php';
        $bulk_sync = new \QuxSync\Sync\BulkSync();
        $result = $bulk_sync->sync_all();
        
        wp_die(wp_json_encode([
            'success' => true,
            'data' => $result->data['data']
        ]));
    }
    
    public function ajax_generate_key() {
        check_ajax_referer('wc_sync_nonce', 'nonce');
        
        if (!current_user_can('manage_woocommerce')) {
            wp_die(wp_json_encode(['success' => false, 'data' => 'Insufficient permissions']));
        }
        
        require_once QUX_SYNC_PLUGIN_DIR . 'includes/security/class-authentication.php';
        $new_key = \QuxSync\Security\Authentication::generate_secure_key(64);
        update_option('wc_sync_api_auth_key', $new_key);
        update_option('wc_sync_last_key_generation', current_time('Y-m-d H:i:s'));
        
        wp_die(wp_json_encode([
            'success' => true,
            'data' => [
                'new_key' => $new_key,
                'message' => 'New authentication key generated',
                'timestamp' => current_time('Y-m-d H:i:s')
            ]
        ]));
    }
}
