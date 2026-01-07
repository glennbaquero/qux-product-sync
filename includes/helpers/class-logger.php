<?php
namespace QuxSync\Helpers;

class Logger {
    
    private $log_file;
    
    public function __construct() {
        $this->log_file = WP_CONTENT_DIR . '/wc-product-sync.log';
    }
    
    public function log($message, $level = 'info') {
        if (!get_option('wc_sync_debug_mode', 0) && $level === 'debug') {
            return;
        }
        
        $timestamp = current_time('Y-m-d H:i:s');
        $formatted = sprintf("[%s] [%s] %s\n", $timestamp, strtoupper($level), $message);
        error_log($formatted, 3, $this->log_file);
    }
    
    public function get_logs($lines = 100) {
        if (!file_exists($this->log_file)) {
            return [];
        }
        
        $logs = [];
        $file = new \SplFileObject($this->log_file);
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
        
        return $logs;
    }
}
