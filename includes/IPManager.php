<?php
namespace NHRRob\Secure;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * IP & Country Management Handler
 */
class IPManager
{
    /**
     * Initialize the IP Manager
     */
    public function __construct()
    {
        // Hook early to block access
        add_action('init', [$this, 'handle_blocking'], 1);
    }

    /**
     * Core blocking logic
     */
    public function handle_blocking()
    {
        if (is_admin() || wp_doing_cron() || (defined('WP_CLI') && WP_CLI)) {
            return;
        }

        $ip = $this->get_client_ip();

        // 1. Check Whitelist (Always bypass)
        if ($this->is_whitelisted($ip)) {
            return;
        }

        // 2. Check Blacklist
        if ($this->is_blacklisted($ip)) {
            $this->terminate_request('IP_BLACKLIST', $ip);
        }

        // 3. Check Country Block
        if ($this->is_country_blocked($ip)) {
            $this->terminate_request('COUNTRY_BLOCK', $ip);
        }
    }

    /**
     * Check if IP is whitelisted
     *
     * @param string $ip
     * @return bool
     */
    public function is_whitelisted($ip)
    {
        $whitelist = $this->get_list('nhrrob_secure_ip_whitelist');
        return $this->ip_in_list($ip, $whitelist);
    }

    /**
     * Check if IP is blacklisted
     *
     * @param string $ip
     * @return bool
     */
    public function is_blacklisted($ip)
    {
        $blacklist = $this->get_list('nhrrob_secure_ip_blacklist');
        return $this->ip_in_list($ip, $blacklist);
    }

    /**
     * Check if IP's country is blocked
     *
     * @param string $ip
     * @return bool
     */
    public function is_country_blocked($ip)
    {
        $blocked_countries = get_option('nhrrob_secure_blocked_countries', []);
        if (empty($blocked_countries)) {
            return false;
        }

        $country_code = $this->get_country_by_ip($ip);
        if (!$country_code) {
            return false;
        }

        return in_array($country_code, $blocked_countries);
    }

    /**
     * Get list from options
     *
     * @param string $option_name
     * @return array
     */
    private function get_list($option_name)
    {
        $raw = get_option($option_name, '');
        if (empty($raw)) {
            return [];
        }
        return array_filter(array_map('trim', explode("\n", $raw)));
    }

    /**
     * Check if IP exists in a list (supports CIDR)
     *
     * @param string $ip
     * @param array $list
     * @return bool
     */
    private function ip_in_list($ip, $list)
    {
        foreach ($list as $range) {
            if ($this->ip_matches($ip, $range)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Match IP against range/CIDR
     *
     * @param string $ip
     * @param string $range
     * @return bool
     */
    private function ip_matches($ip, $range)
    {
        if (strpos($range, '/') !== false) {
            // CIDR
            list($subnet, $bits) = explode('/', $range);
            $ip_long = ip2long($ip);
            $subnet_long = ip2long($subnet);
            $mask = -1 << (32 - $bits);
            $subnet_long &= $mask;
            return ($ip_long & $mask) == $subnet_long;
        }
        
        // Exact match
        return $ip === $range;
    }

    /**
     * Get country code by IP using API lookup with caching
     *
     * @param string $ip
     * @return string|false Country code or false
     */
    private function get_country_by_ip($ip)
    {
        // Skip local/private IPs
        if ($this->is_private_ip($ip)) {
            return false;
        }

        // Check cache first (24 hour transient)
        $cache_key = 'nhrrob_secure_geoip_' . md5($ip);
        $cached = get_transient($cache_key);
        
        if ($cached !== false) {
            return $cached;
        }

        // Use ip-api.com (free, no key required, 45 requests/minute)
        $response = wp_remote_get(
            'http://ip-api.com/json/' . $ip . '?fields=status,countryCode',
            [
                'timeout' => 3,
                'user-agent' => 'WordPress/NHRRob-Secure',
            ]
        );

        if (is_wp_error($response)) {
            return false;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (isset($data['status']) && $data['status'] === 'success' && !empty($data['countryCode'])) {
            $country_code = sanitize_text_field($data['countryCode']);
            
            // Cache for 24 hours
            set_transient($cache_key, $country_code, DAY_IN_SECONDS);
            
            return $country_code;
        }

        return false;
    }

    /**
     * Check if IP is private/local
     *
     * @param string $ip
     * @return bool
     */
    private function is_private_ip($ip)
    {
        $private_ranges = [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '127.0.0.0/8',
            '0.0.0.0/8',
        ];

        foreach ($private_ranges as $range) {
            list($subnet, $bits) = explode('/', $range);
            $ip_long = ip2long($ip);
            $subnet_long = ip2long($subnet);
            $mask = -1 << (32 - $bits);
            $subnet_long &= $mask;
            
            if (($ip_long & $mask) == $subnet_long) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get client IP
     */
    private function get_client_ip()
    {
        $security = new Security();
        return $security->get_ip();
    }

    /**
     * Terminate request with 403
     */
    private function terminate_request($reason, $ip)
    {
        $audit_log = new AuditLog();
        $audit_log->log(
            'ip_manager',
            'block',
            /* translators: 1: IP Address, 2: Reason */
            sprintf(__('Blocked request from IP: %1$s (%2$s)', 'nhrrob-secure'), $ip, $reason),
            /* translators: %s: Reason */
            sprintf(__('Reason: %s', 'nhrrob-secure'), $reason),
            2 // Medium severity
        );

        wp_die(
            esc_html__('Access Denied: Your IP or country has been blocked by the security settings.', 'nhrrob-secure'),
            esc_html__('Security Block', 'nhrrob-secure'),
            ['response' => 403]
        );
    }
}
