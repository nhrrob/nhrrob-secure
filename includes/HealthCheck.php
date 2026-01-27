<?php
namespace NHRRob\Secure;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Health Check & Security Score Handler
 */
class HealthCheck
{
    /**
     * Get security status and score
     *
     * @return array
     */
    public function get_stats()
    {
        $checks = $this->get_checks();
        $score = 0;
        $total_weight = 0;

        foreach ($checks as $check) {
            $total_weight += $check['weight'];
            if ($check['passed']) {
                $score += $check['weight'];
            }
        }

        return [
            'score' => $score,
            'total' => $total_weight,
            'checks' => $checks,
            'grade' => $this->get_grade($score),
        ];
    }

    /**
     * Get all security checks
     *
     * @return array
     */
    private function get_checks()
    {
        $checks = [];

        // 1. Custom Login URL
        $login_url = get_option('nhrrob_secure_custom_login_url', '/hidden-access-52w');
        $checks[] = [
            'id' => 'custom_login',
            'label' => __('Custom Login URL', 'nhrrob-secure'),
            'description' => __('Changing the default wp-login.php URL helps prevent brute-force attacks.', 'nhrrob-secure'),
            'passed' => get_option('nhrrob_secure_custom_login_page', 1) && $login_url !== '/wp-login.php',
            'weight' => 15,
        ];

        // 2. Limit Login Attempts
        $checks[] = [
            'id' => 'limit_login',
            'label' => __('Limit Login Attempts', 'nhrrob-secure'),
            'description' => __('Restricting failed login attempts blocks automated brute-force tools.', 'nhrrob-secure'),
            'passed' => (bool) get_option('nhrrob_secure_limit_login_attempts', 1),
            'weight' => 15,
        ];

        // 3. Two-Factor Authentication
        $checks[] = [
            'id' => 'two_factor',
            'label' => __('Two-Factor Authentication', 'nhrrob-secure'),
            'description' => __('2FA adds a critical second layer of defense to user accounts.', 'nhrrob-secure'),
            'passed' => (bool) get_option('nhrrob_secure_enable_2fa', 0),
            'weight' => 20,
        ];

        // 4. Disable XML-RPC
        $checks[] = [
            'id' => 'disable_xmlrpc',
            'label' => __('Disable XML-RPC', 'nhrrob-secure'),
            'description' => __('XML-RPC is often used for DDoS and brute-force attacks.', 'nhrrob-secure'),
            'passed' => (bool) get_option('nhrrob_secure_disable_xmlrpc', 0),
            'weight' => 10,
        ];

        // 5. Disable File Editor
        $checks[] = [
            'id' => 'disable_file_editor',
            'label' => __('Disable File Editor', 'nhrrob-secure'),
            'description' => __('Prevents attackers from modifying your theme or plugin files directly.', 'nhrrob-secure'),
            'passed' => (bool) get_option('nhrrob_secure_disable_file_editor', 0),
            'weight' => 10,
        ];

        // 6. Hide WP Version
        $checks[] = [
            'id' => 'hide_wp_version',
            'label' => __('Hide WordPress Version', 'nhrrob-secure'),
            'description' => __('Removing version exposure makes it harder for bots to find vulnerable sites.', 'nhrrob-secure'),
            'passed' => (bool) get_option('nhrrob_secure_hide_wp_version', 0),
            'weight' => 5,
        ];

        // 7. REST Users Endpoint
        $checks[] = [
            'id' => 'disable_rest_users',
            'label' => __('Protect REST API Users', 'nhrrob-secure'),
            'description' => __('Blocks attackers from harvesting usernames via the REST API.', 'nhrrob-secure'),
            'passed' => (bool) get_option('nhrrob_secure_disable_rest_users', 0),
            'weight' => 5,
        ];

        // 8. Protect Debug Log
        $checks[] = [
            'id' => 'protect_debug_log',
            'label' => __('Protect Debug Log', 'nhrrob-secure'),
            'description' => __('Ensures your debug.log file is not publicly accessible.', 'nhrrob-secure'),
            'passed' => (bool) get_option('nhrrob_secure_protect_debug_log', 1),
            'weight' => 10,
        ];

        // 9. Recent Vulnerability Scan
        $last_scan = get_transient('nhrrob_secure_vulnerability_results');
        $passed_scan = false;
        if ($last_scan && isset($last_scan['last_scan'])) {
            $passed_scan = (time() - $last_scan['last_scan']) < DAY_IN_SECONDS;
        }

        $checks[] = [
            'id' => 'recent_scan',
            'label' => __('Recent Security Scan', 'nhrrob-secure'),
            'description' => __('Regular vulnerability scans ensure you are notified of new security threats.', 'nhrrob-secure'),
            'passed' => $passed_scan,
            'weight' => 10,
        ];

        return $checks;
    }

    /**
     * Apply one-click secure settings
     *
     * @return bool
     */
    public function apply_one_click_secure()
    {
        update_option('nhrrob_secure_limit_login_attempts', 1);
        update_option('nhrrob_secure_disable_xmlrpc', 1);
        update_option('nhrrob_secure_disable_file_editor', 1);
        update_option('nhrrob_secure_hide_wp_version', 1);
        update_option('nhrrob_secure_disable_rest_users', 1);
        update_option('nhrrob_secure_protect_debug_log', 1);
        
        // We don't force 2FA as it requires user setup, but we provide progress.
        
        return true;
    }

    /**
     * Get grade based on score
     *
     * @param int $score
     * @return string
     */
    private function get_grade($score)
    {
        if ($score >= 90) return 'A+';
        if ($score >= 80) return 'A';
        if ($score >= 70) return 'B';
        if ($score >= 60) return 'C';
        return 'F';
    }
}
