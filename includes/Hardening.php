<?php
namespace NHRRob\Secure;

if (!defined('ABSPATH')) {
    exit;
}

class Hardening
{

    public function __construct()
    {
        $this->init_hardening();
        $this->init_firewall();
    }

    private function init_hardening()
    {
        // Disable XML-RPC
        if (get_option('nhrrob_secure_disable_xmlrpc')) {
            add_filter('xmlrpc_enabled', '__return_false');

            // Disable X-Pingback header
            add_filter('wp_headers', function ($headers) {
                unset($headers['X-Pingback']);
                return $headers;
            });
        }

        // Disable File Editor
        if (get_option('nhrrob_secure_disable_file_editor')) {
            // Using map_meta_cap to disallow editing files
            add_filter('map_meta_cap', [$this, 'block_file_edit_caps'], 10, 2);
        }

        // Hide WP Version
        if (get_option('nhrrob_secure_hide_wp_version')) {
            remove_action('wp_head', 'wp_generator');
            add_filter('the_generator', '__return_empty_string');
        }

        // Disable REST API User Enumeration
        if (get_option('nhrrob_secure_disable_rest_users')) {
            add_filter('rest_endpoints', [$this, 'disable_users_endpoint']);
        }
    }

    private function init_firewall()
    {
        // Hook early for firewall check
        add_action('init', [$this, 'check_firewall_rules']);
    }

    public function block_file_edit_caps($caps, $cap)
    {
        if (in_array($cap, ['edit_themes', 'edit_plugins', 'edit_files'])) {
            return ['do_not_allow'];
        }
        return $caps;
    }

    public function disable_users_endpoint($endpoints)
    {
        if (isset($endpoints['/wp/v2/users']) && !current_user_can('list_users')) {
            unset($endpoints['/wp/v2/users']);
        }
        if (isset($endpoints['/wp/v2/users/(?P<id>[\d]+)']) && !current_user_can('list_users')) {
            unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
        }
        return $endpoints;
    }

    public function check_firewall_rules()
    {
        if (is_admin() || wp_doing_cron()) {
            return;
        }

        $blocked_uas_setting = get_option('nhrrob_secure_firewall_blocked_uas', '');
        if (empty($blocked_uas_setting)) {
            return;
        }

        $blocked_uas = array_filter(array_map('trim', explode("\n", $blocked_uas_setting)));
        if (empty($blocked_uas)) {
            return;
        }

        $current_ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';

        foreach ($blocked_uas as $ua) {
            if (empty($ua))
                continue;

            // Simple containment check (case-insensitive)
            if (stripos($current_ua, $ua) !== false) {
                wp_die('Access Denied: Your User-Agent is blocked.', 'Access Denied', ['response' => 403]);
            }
        }
    }
}
