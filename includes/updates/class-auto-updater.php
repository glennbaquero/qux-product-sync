<?php
namespace QuxSync\Updates;

use QuxSync\Helpers\Logger;

class AutoUpdater {
    
    private $update_checker;
    private $logger;
    
    public function __construct() {
        $this->logger = new Logger();
        require_once QUX_SYNC_PLUGIN_DIR . 'includes/updates/class-update-checker.php';
        $this->update_checker = new UpdateChecker();
        
        $this->register_hooks();
    }
    
    private function register_hooks() {
        add_filter('pre_set_site_transient_update_plugins', [$this, 'check_for_updates']);
        add_filter('plugins_api', [$this, 'plugin_info'], 10, 3);
        add_filter('plugin_row_meta', [$this, 'plugin_row_meta'], 10, 2);
        add_action('in_plugin_update_message-' . plugin_basename(QUX_SYNC_PLUGIN_FILE), [$this, 'update_message'], 10, 2);
        add_action('qux_product_sync_check_updates', [$this, 'cron_check_updates']);
        add_action('wp_ajax_toggle_auto_updates', [$this, 'ajax_toggle_auto_updates']);
        add_action('wp_ajax_check_updates_now', [$this, 'ajax_check_updates_now']);
        add_action('admin_footer-plugins.php', [$this, 'add_plugins_page_script']);
    }
    
    public function check_for_updates($transient) {
        if (empty($transient->checked)) {
            return $transient;
        }
        
        if (!get_option('qux_product_sync_auto_updates_enabled', 1)) {
            return $transient;
        }
        
        $plugin_slug = plugin_basename(QUX_SYNC_PLUGIN_FILE);
        $remote_version = $this->update_checker->get_remote_version();
        
        if ($remote_version && version_compare(QUX_SYNC_VERSION, $remote_version->version, '<')) {
            $obj = new \stdClass();
            $obj->slug = 'qux-product-sync';
            $obj->plugin = $plugin_slug;
            $obj->new_version = $remote_version->version;
            $obj->url = $remote_version->homepage ?? '';
            $obj->package = $remote_version->download_url ?? '';
            $obj->tested = $remote_version->tested ?? '';
            $obj->requires = $remote_version->requires ?? '';
            $obj->requires_php = $remote_version->requires_php ?? '';
            
            if (isset($remote_version->icons)) {
                $obj->icons = (array) $remote_version->icons;
            }
            
            $transient->response[$plugin_slug] = $obj;
        }
        
        return $transient;
    }
    
    public function plugin_info($false, $action, $response) {
        if ($action !== 'plugin_information' || $response->slug !== 'qux-product-sync') {
            return $false;
        }
        
        $remote_version = $this->update_checker->get_remote_version();
        
        if (!$remote_version) {
            return $false;
        }
        
        $info = new \stdClass();
        $info->name = $remote_version->name ?? 'QUX Pay® Product Sync';
        $info->slug = 'qux-product-sync';
        $info->version = $remote_version->version;
        $info->author = $remote_version->author ?? 'Qux';
        $info->homepage = $remote_version->homepage ?? 'https://qux.tv';
        $info->requires = $remote_version->requires ?? '6.7';
        $info->tested = $remote_version->tested ?? '6.8.2';
        $info->requires_php = $remote_version->requires_php ?? '7.4';
        $info->download_link = $remote_version->download_url ?? '';
        $info->sections = [
            'description' => $remote_version->sections->description ?? 'Syncs WooCommerce products to Qux',
            'changelog' => $remote_version->sections->changelog ?? ''
        ];
        
        return $info;
    }
    
    public function plugin_row_meta($links, $file) {
        if ($file === plugin_basename(QUX_SYNC_PLUGIN_FILE)) {
            $auto_updates_enabled = get_option('qux_product_sync_auto_updates_enabled', 1);
            $status = $auto_updates_enabled ? 'enabled' : 'disabled';
            $links[] = '<a href="#" class="qux-toggle-auto-updates" data-nonce="' . wp_create_nonce('qux_product_sync_nonce') . '" data-enabled="' . $auto_updates_enabled . '">Auto-updates <span class="auto-update-status">' . $status . '</span></a>';
            $links[] = '<a href="' . admin_url('admin.php?page=wc-product-sync&tab=updates') . '">Update Settings</a>';
        }
        return $links;
    }
    
    public function update_message($plugin_data, $response) {
        echo '<br><strong>Important:</strong> Please backup your site before updating.';
    }
    
    public function cron_check_updates() {
        if (!get_option('qux_product_sync_auto_updates_enabled', 1)) {
            return;
        }
        
        delete_transient('qux_product_sync_remote_version');
        delete_site_transient('update_plugins');
        
        $this->logger->log('Automated update check triggered', 'info');
    }
    
    public function ajax_toggle_auto_updates() {
        check_ajax_referer('qux_product_sync_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die(wp_json_encode(['success' => false, 'message' => 'Insufficient permissions']));
        }
        
        $current = get_option('qux_product_sync_auto_updates_enabled', 1);
        $new_value = !$current;
        
        update_option('qux_product_sync_auto_updates_enabled', $new_value);
        
        $this->logger->log('Auto-updates ' . ($new_value ? 'enabled' : 'disabled'), 'info');
        
        wp_die(wp_json_encode([
            'success' => true,
            'enabled' => $new_value,
            'message' => 'Auto-updates ' . ($new_value ? 'enabled' : 'disabled')
        ]));
    }
    
    public function ajax_check_updates_now() {
        check_ajax_referer('qux_product_sync_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die(wp_json_encode(['success' => false, 'message' => 'Insufficient permissions']));
        }
        
        delete_transient('qux_product_sync_remote_version');
        delete_site_transient('update_plugins');
        
        $remote_version = $this->update_checker->get_remote_version();
        
        if (!$remote_version) {
            wp_die(wp_json_encode([
                'success' => false,
                'message' => 'Could not connect to update server'
            ]));
        }
        
        $update_available = version_compare(QUX_SYNC_VERSION, $remote_version->version, '<');
        
        wp_die(wp_json_encode([
            'success' => true,
            'current_version' => QUX_SYNC_VERSION,
            'remote_version' => $remote_version->version,
            'update_available' => $update_available,
            'message' => $update_available 
                ? 'Update available: ' . $remote_version->version 
                : 'You are using the latest version'
        ]));
    }
    
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
                    data: { action: 'toggle_auto_updates', nonce: nonce },
                    success: function(response) {
                        var data = JSON.parse(response);
                        if (data.success) {
                            statusSpan.text(data.enabled ? 'enabled' : 'disabled');
                            link.data('enabled', data.enabled ? 1 : 0);
                        } else {
                            statusSpan.text(originalText);
                            alert('Error: ' + data.message);
                        }
                    },
                    error: function() {
                        statusSpan.text(originalText);
                        alert('Failed to toggle auto-updates');
                    }
                });
            });
        });
        </script>
        <?php
    }
    
    public static function schedule_checks() {
        if (!wp_next_scheduled('qux_product_sync_check_updates')) {
            wp_schedule_event(time(), 'twicedaily', 'qux_product_sync_check_updates');
        }
    }
    
    public static function unschedule_checks() {
        $timestamp = wp_next_scheduled('qux_product_sync_check_updates');
        if ($timestamp) {
            wp_unschedule_event($timestamp, 'qux_product_sync_check_updates');
        }
    }
}
