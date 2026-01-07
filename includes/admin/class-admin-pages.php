<?php
namespace QuxSync\Admin;

use QuxSync\Security\WordfenceIntegration;

class AdminPages {
    
    public function render() {
        $active_tab = isset($_GET['tab']) ? $_GET['tab'] : 'settings';
        $wordfence_enabled = WordfenceIntegration::is_active();
        
        include QUX_SYNC_PLUGIN_DIR . 'includes/admin/views/header.php';
        
        switch ($active_tab) {
            case 'settings':
                include QUX_SYNC_PLUGIN_DIR . 'includes/admin/views/settings-tab.php';
                break;
            case 'updates':
                include QUX_SYNC_PLUGIN_DIR . 'includes/admin/views/updates-tab.php';
                break;
            case 'sync':
                include QUX_SYNC_PLUGIN_DIR . 'includes/admin/views/sync-tab.php';
                break;
        }
        
        include QUX_SYNC_PLUGIN_DIR . 'includes/admin/views/footer.php';
    }
}
