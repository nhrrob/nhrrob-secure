<?php

namespace NHRRob\Secure;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * File Scanner to detect malware and core file integrity
 */
class FileScanner
{

    /**
     * WP Core Checksums API
     */
    const CORE_CHECKSUMS_API = 'https://api.wordpress.org/core/checksums/1.0/';

    /**
     * Malware signatures (basic heuristics)
     */
    private $signatures = [
        'base64_eval' => '/eval\s*\(\s*base64_decode\s*\(/i',
        'gzinflate_base64' => '/eval\s*\(\s*gzinflate\s*\(\s*base64_decode\s*\(/i',
        'shell_exec' => '/shell_exec\s*\(/i',
        'passthru' => '/passthru\s*\(/i',
        'system_exec' => '/system\s*\(/i',
        'eval_post' => '/eval\s*\(\s*\$_POST/i',
        'eval_request' => '/eval\s*\(\s*\$_REQUEST/i',
    ];

    /**
     * Scan WP Core files for integrity
     *
     * @return array
     */
    public function scan_core()
    {
        global $wp_version;
        $locale = get_locale();

        $url = self::CORE_CHECKSUMS_API . "?version={$wp_version}&locale={$locale}";
        $response = wp_remote_get($url);

        if (is_wp_error($response)) {
            return ['error' => $response->get_error_message()];
        }

        $body = wp_remote_retrieve_body($response);
        $checksums = json_decode($body, true);

        if (empty($checksums) || !is_array($checksums) || empty($checksums['checksums'])) {
            return ['error' => 'Could not retrieve checksums from WordPress.org'];
        }

        $modified_files = [];
        $missing_files = [];
        $unknown_files = []; // We won't check unknown files in core scan for now, as that's complex (user uploads etc)

        foreach ($checksums['checksums'] as $file => $checksum) {
            $fullpath = ABSPATH . $file;

            if (!file_exists($fullpath)) {
                $missing_files[] = $file;
                continue;
            }

            if (md5_file($fullpath) !== $checksum) {
                // Ignore wp-config.php and other naturally modified files if necessary,
                // but usually wp-config-sample.php is the one in checksums.
                // wp-content files are usually not in checksums except standard themes/plugins which we might want to skip here.
                $modified_files[] = $file;
            }
        }

        return [
            'modified' => $modified_files,
            'missing' => $missing_files,
            'timestamp' => time()
        ];
    }

    /**
     * Recursive directory scan for malware
     *
     * @param string $path
     * @return array
     */
    public function scan_directory($path = '', $recursive = true)
    {
        if (empty($path)) {
            $path = WP_CONTENT_DIR;
        }

        $files = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($path, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        $suspicious_files = [];
        $scanned_count = 0;

        foreach ($files as $file) {
            if ($file->isDir()) {
                continue;
            }

            $ext = $file->getExtension();
            if (!in_array($ext, ['php', 'js', 'html', 'htaccess'])) {
                continue;
            }

            // Skip huge files
            if ($file->getSize() > 1048576) { // 1MB
                continue;
            }

            $content = file_get_contents($file->getRealPath());

            foreach ($this->signatures as $signature_name => $pattern) {
                if (preg_match($pattern, $content)) {
                    $suspicious_files[] = [
                        'file' => $file->getPathname(),
                        'signature' => $signature_name,
                        'reason' => 'Matched pattern: ' . $signature_name
                    ];
                    break;
                }
            }
            
            $scanned_count++;
            
            // Safety break for now to prevent timeouts in non-chunked version
            if ($scanned_count > 2000) {
                 break; 
            }
        }

        return [
            'suspicious' => $suspicious_files,
            'scanned_count' => $scanned_count,
            'timestamp' => time()
        ];
    }

    /**
     * Restore a core file from WordPress.org
     * 
     * @param string $file_path Relative path to ABSPATH
     * @return bool|\WP_Error
     */
    public function repair_core_file($file_path)
    {
        global $wp_version;
        $locale = get_locale();
        
        // GitHub mirror: https://raw.githubusercontent.com/WordPress/WordPress/{version}/{file_path}
        
        $tag = $wp_version; 
        // Note: WP versions on GitHub tags are like 6.4.2
        
        $url = "https://raw.githubusercontent.com/WordPress/WordPress/{$tag}/{$file_path}";
        
        $response = wp_remote_get($url);
        
        if (is_wp_error($response)) {
            return $response;
        }
        
        if (wp_remote_retrieve_response_code($response) !== 200) {
            return new \WP_Error('download_failed', 'Could not download original file from repository.');
        }
        
        $content = wp_remote_retrieve_body($response);
        
        if (empty($content)) {
            return new \WP_Error('empty_file', 'Downloaded file is empty.');
        }
        
        $full_path = ABSPATH . $file_path;
        
        // Verify we are writing to a valid path
        if (strpos($full_path, ABSPATH) !== 0) {
             return new \WP_Error('invalid_path', 'Invalid file path.');
        }
        
        global $wp_filesystem;
        
        if (empty($wp_filesystem)) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
            WP_Filesystem();
        }
        
        if (!$wp_filesystem->put_contents($full_path, $content)) {
            return new \WP_Error('fs_error', 'Could not write file using WP_Filesystem.');
        }
        
        return true;
    }
    
    /**
     * Delete a suspicious file
     * 
     * @param string $file_path Absolute path
     * @return bool
     */
    public function delete_file($file_path)
    {
        global $wp_filesystem;
        
        if (empty($wp_filesystem)) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
            WP_Filesystem();
        }
        
        if ($wp_filesystem->exists($file_path)) {
            return $wp_filesystem->delete($file_path);
        }
        
        return false;
    }
}
