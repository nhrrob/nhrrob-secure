<?php
namespace NHRRob\Secure;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Advanced Firewall (IPS) Handler
 */
class Firewall
{
    /**
     * @var array Common attack patterns
     */
    private $patterns = [
        'sqli' => [
            '/union\s+select/i',
            '/select\s+.*\s+from/i',
            '/insert\s+into/i',
            '/update\s+.*\s+set/i',
            '/delete\s+from/i',
            '/drop\s+table/i',
            '/truncate\s+table/i',
            '/sleep\(\d+\)/i',
            '/benchmark\(/i',
            '/\'\s*or\s*\'?\d+\'?\s*=\s*\'?\d+/i',
            '/--/i',
            '/\/\*/i',
        ],
        'xss' => [
            '/<script/i',
            '/javascript:/i',
            '/onerror\s*=/i',
            '/onload\s*=/i',
            '/onclick\s*=/i',
            '/onmouseover\s*=/i',
            '/alert\(/i',
            '/eval\(/i',
            '/expression\(/i',
            '/base64_decode/i',
            '/<iframe/i',
            '/<object/i',
            '/<embed/i',
        ],
        'lfi' => [
            '/\.\.\//',
            '/\.\.%2f/i',
            '/\/etc\/passwd/i',
            '/\/proc\/self\/environ/i',
            '/.php\0/i',
            '/.ini/i',
            '/win.ini/i',
            '/boot.ini/i',
        ]
    ];

    /**
     * Initialize the firewall
     */
    public function __construct()
    {
        if (!get_option('nhrrob_secure_enable_advanced_firewall', 0)) {
            return;
        }

        add_action('init', [$this, 'inspect_request'], 5);
    }

    /**
     * Inspect the current request for malicious patterns
     */
    public function inspect_request()
    {
        // Skip for admins or specific requests
        if (is_admin() || wp_doing_cron() || (defined('WP_CLI') && WP_CLI)) {
            return;
        }

        $request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        $query_string = isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : '';
        
        // Data to check
        $target_data = [
            'URI' => $request_uri,
            'Query' => $query_string,
        ];

        // Add POST if not empty
        if (!empty($_POST)) {
            $target_data['POST'] = wp_json_encode($_POST);
        }

        foreach ($target_data as $source => $value) {
            if (empty($value)) continue;

            $detected = $this->check_patterns($value);
            if ($detected) {
                $this->block_request($detected, $source, $value);
            }
        }
    }

    /**
     * Check string against all patterns
     *
     * @param string $data
     * @return string|bool Pattern ID or false
     */
    private function check_patterns($data)
    {
        $decoded_data = urldecode($data);

        foreach ($this->patterns as $type => $patterns) {
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $data) || preg_match($pattern, $decoded_data)) {
                    return $type;
                }
            }
        }

        return false;
    }

    /**
     * Block the request and log it
     *
     * @param string $type
     * @param string $source
     * @param string $value
     */
    private function block_request($type, $source, $value)
    {
        $ip = $this->get_ip();
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field($_SERVER['HTTP_USER_AGENT']) : 'Unknown';

        // Log the event
        $audit_log = new AuditLog();
        $audit_log->log(
            'firewall',
            'block',
            sprintf(__('Blocked %s attempt', 'nhrrob-secure'), strtoupper($type)),
            sprintf(__('Source: %s | Type: %s | Value: %s', 'nhrrob-secure'), $source, $type, mb_strimwidth($value, 0, 100, '...')),
            3 // High severity
        );

        // Terminate
        $message = sprintf(
            __('Access Denied: Your request was blocked by the security firewall. Protection Type: %s. Your IP: %s', 'nhrrob-secure'),
            strtoupper($type),
            $ip
        );

        wp_die($message, __('Security Block', 'nhrrob-secure'), ['response' => 403]);
    }

    /**
     * Get client IP address
     *
     * @return string
     */
    private function get_ip()
    {
        if (get_option('nhrrob_secure_enable_proxy_ip') && isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            return sanitize_text_field(trim($ips[0]));
        }
        return isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field($_SERVER['REMOTE_ADDR']) : '0.0.0.0';
    }
}
