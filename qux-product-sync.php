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

if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('QUX_SYNC_VERSION', '1.1.3');
define('QUX_SYNC_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('QUX_SYNC_PLUGIN_URL', plugin_dir_url(__FILE__));
define('QUX_SYNC_PLUGIN_FILE', __FILE__);

// Autoloader
spl_autoload_register(function ($class) {
    $prefix = 'QuxSync\\';
    $base_dir = QUX_SYNC_PLUGIN_DIR . 'includes/';
    
    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }
    
    $relative_class = substr($class, $len);
    $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';
    
    if (file_exists($file)) {
        require $file;
    }
});

// Initialize plugin
function qux_sync_init() {
    require_once QUX_SYNC_PLUGIN_DIR . 'includes/class-qux-product-sync.php';
    $plugin = new QuxSync\QuxProductSync();
    $plugin->init();
}
add_action('plugins_loaded', 'qux_sync_init');

// Activation hook
register_activation_hook(__FILE__, function() {
    require_once QUX_SYNC_PLUGIN_DIR . 'includes/class-qux-product-sync.php';
    QuxSync\QuxProductSync::activate();
});

// Deactivation hook
register_deactivation_hook(__FILE__, function() {
    require_once QUX_SYNC_PLUGIN_DIR . 'includes/class-qux-product-sync.php';
    QuxSync\QuxProductSync::deactivate();
});

add_action('admin_notices', function() {
    if (!empty($_REQUEST['bulk_sync_products'])) {
        $synced = intval($_REQUEST['bulk_sync_products']);
        printf('<div class="notice notice-success is-dismissible"><p>%d products synced to API.</p></div>', $synced);
    }
});

// Add bulk action to products list
add_filter('bulk_actions-edit-product', function($bulk_actions) {
    $bulk_actions['sync_to_api'] = 'Sync to API';
    return $bulk_actions;
});

// Handle bulk action
add_filter('handle_bulk_actions-edit-product', function($redirect_to, $doaction, $post_ids) {
    if ($doaction !== 'sync_to_api') {
        return $redirect_to;
    }
    
    require_once QUX_SYNC_PLUGIN_DIR . 'includes/sync/class-bulk-sync.php';
    $bulk_sync = new \QuxSync\Sync\BulkSync();
    $result = $bulk_sync->sync_multiple($post_ids);
    
    $synced = $result->data['data']['synced'];
    return add_query_arg('bulk_sync_products', $synced, $redirect_to);
}, 10, 3);
