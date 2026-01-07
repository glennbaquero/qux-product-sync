<?php
namespace QuxSync;

class QuxProductSync {
    
    private static $instance = null;
    private $admin_settings;
    private $rest_api;
    private $product_sync;
    private $auto_updater;
    private $logger;
    
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    public function init() {
        $this->load_dependencies();
        $this->init_components();
        $this->register_hooks();
    }
    
    private function load_dependencies() {
        require_once QUX_SYNC_PLUGIN_DIR . 'includes/helpers/class-logger.php';
        require_once QUX_SYNC_PLUGIN_DIR . 'includes/admin/class-admin-settings.php';
        require_once QUX_SYNC_PLUGIN_DIR . 'includes/api/class-rest-api.php';
        require_once QUX_SYNC_PLUGIN_DIR . 'includes/sync/class-product-sync.php';
        require_once QUX_SYNC_PLUGIN_DIR . 'includes/updates/class-auto-updater.php';
    }
    
    private function init_components() {
        $this->logger = new Helpers\Logger();
        $this->admin_settings = new Admin\AdminSettings();
        $this->rest_api = new API\RestAPI();
        $this->product_sync = new Sync\ProductSync();
        $this->auto_updater = new Updates\AutoUpdater();
    }
    
    private function register_hooks() {
        add_action('before_woocommerce_init', [$this, 'declare_hpos_compatibility']);
    }
    
    public function declare_hpos_compatibility() {
        if (class_exists(\Automattic\WooCommerce\Utilities\FeaturesUtil::class)) {
            \Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility(
                'custom_order_tables',
                QUX_SYNC_PLUGIN_FILE,
                true
            );
        }
    }
    
    public static function activate() {
        require_once QUX_SYNC_PLUGIN_DIR . 'includes/security/class-authentication.php';
        Security\Authentication::generate_initial_key();
        
        $defaults = [
            'wc_sync_rate_limit_max' => 60,
            'wc_sync_rate_limit_window' => 3600,
            'wc_sync_enable_signature' => 1,
            'qux_product_sync_auto_updates_enabled' => 1,
            'qux_product_sync_update_server_url' => 'https://qa.api.quxtech.tv/wp/qux-product-sync'
        ];
        
        foreach ($defaults as $key => $value) {
            if (empty(get_option($key))) {
                update_option($key, $value);
            }
        }
        
        require_once QUX_SYNC_PLUGIN_DIR . 'includes/updates/class-auto-updater.php';
        Updates\AutoUpdater::schedule_checks();
    }
    
    public static function deactivate() {
        require_once QUX_SYNC_PLUGIN_DIR . 'includes/updates/class-auto-updater.php';
        Updates\AutoUpdater::unschedule_checks();
    }
}
