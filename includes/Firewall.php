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

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Inspecting raw URI for attacks.
        $request_uri = isset($_SERVER['REQUEST_URI']) ? wp_unslash($_SERVER['REQUEST_URI']) : '';
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Inspecting raw query string for attacks.
        $query_string = isset($_SERVER['QUERY_STRING']) ? wp_unslash($_SERVER['QUERY_STRING']) : '';
        
        // Data to check
        $target_data = [
            'URI' => $request_uri,
            'Query' => $query_string,
        ];

        // Add POST if not empty
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Firewall needs to inspect all incoming POST data regardless of nonce.
        if (!empty($_POST)) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Firewall inspection.
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
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : 'Unknown';

        // Log the event
        $audit_log = new AuditLog();
        /* translators: %s: Attack type (e.g. SQLi, XSS) */
        $log_message = sprintf(__('Blocked %s attempt', 'nhrrob-secure'), strtoupper($type));
        
        $log_details = sprintf(
            /* translators: 1: Source (e.g. URI, POST), 2: Attack type, 3: Malicious value snippet, 4: User Agent */
            __('Source: %1$s | Type: %2$s | Value: %3$s | UA: %4$s', 'nhrrob-secure'), 
            $source, 
            $type, 
            sanitize_text_field(mb_strimwidth($value, 0, 100, '...')), 
            mb_strimwidth($ua, 0, 50, '...')
        );

        $audit_log->log(
            'firewall',
            'block',
            $log_message,
            $log_details,
            3 // High severity
        );

        // Terminate
        $message = sprintf(
            /* translators: 1: Attack type, 2: IP address */
            __('Access Denied: Your request was blocked by the security firewall. Protection Type: %1$s. Your IP: %2$s', 'nhrrob-secure'),
            strtoupper($type),
            $ip
        );

        wp_die(esc_html($message), esc_html__('Security Block', 'nhrrob-secure'), ['response' => 403]);
    }

    /**
     * Get client IP address
     *
     * @return string
     */
    private function get_ip()
    {
        if (get_option('nhrrob_secure_enable_proxy_ip') && isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = explode(',', sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_FOR'])));
            return trim($ips[0]);
        }
        return isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '0.0.0.0';
    }
}
