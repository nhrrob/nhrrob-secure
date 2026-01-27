<?php

namespace NHRRob\Secure\Admin;

if (!defined('ABSPATH')) {
    exit;
}


/**
 * REST API handler class
 */
class Api
{

    /**
     * Initialize the class
     */
    public function __construct()
    {
        add_action('rest_api_init', [$this, 'register_routes']);
    }

    /**
     * Register REST API endpoints
     */
    public function register_routes()
    {
        // Get settings
        register_rest_route('nhrrob-secure/v1', '/settings', [
            'methods' => 'GET',
            'callback' => [$this, 'get_settings'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
        ]);

        // Update settings
        register_rest_route('nhrrob-secure/v1', '/settings', [
            'methods' => 'POST',
            'callback' => [$this, 'update_settings'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
            'args' => [
                'nhrrob_secure_limit_login_attempts' => [
                    'type' => 'boolean',
                    'sanitize_callback' => 'rest_sanitize_boolean',
                ],
                'nhrrob_secure_login_attempts_limit' => [
                    'type' => 'integer',
                    'sanitize_callback' => 'absint',
                ],
                'nhrrob_secure_custom_login_page' => [
                    'type' => 'boolean',
                    'sanitize_callback' => 'rest_sanitize_boolean',
                ],
                'nhrrob_secure_custom_login_url' => [
                    'type' => 'string',
                    'sanitize_callback' => 'sanitize_text_field',
                ],
                'nhrrob_secure_protect_debug_log' => [
                    'type' => 'boolean',
                    'sanitize_callback' => 'rest_sanitize_boolean',
                ],
                'nhrrob_secure_enable_proxy_ip' => [
                    'type' => 'boolean',
                    'sanitize_callback' => 'rest_sanitize_boolean',
                ],
                'nhrrob_secure_enable_2fa' => [
                    'type' => 'boolean',
                    'sanitize_callback' => 'rest_sanitize_boolean',
                ],
                'nhrrob_secure_2fa_enforced_roles' => [
                    'type' => 'array',
                    'items' => [
                        'type' => 'string',
                    ],
                    'sanitize_callback' => function ($roles) {
                        return is_array($roles) ? array_map('sanitize_text_field', $roles) : [];
                    },
                ],
                'nhrrob_secure_2fa_type' => [
                    'type' => 'string',
                    'enum' => ['app', 'email'],
                    'sanitize_callback' => 'sanitize_text_field',
                ],
                'nhrrob_secure_dark_mode' => [
                    'type' => 'boolean',
                    'sanitize_callback' => 'rest_sanitize_boolean',
                ],
                'nhrrob_secure_log_retention_days' => [
                    'type' => 'integer',
                    'sanitize_callback' => 'absint',
                ],
                'nhrrob_secure_disable_xmlrpc' => [
                    'type' => 'boolean',
                    'sanitize_callback' => 'rest_sanitize_boolean',
                ],
                'nhrrob_secure_disable_file_editor' => [
                    'type' => 'boolean',
                    'sanitize_callback' => 'rest_sanitize_boolean',
                ],
                'nhrrob_secure_hide_wp_version' => [
                    'type' => 'boolean',
                    'sanitize_callback' => 'rest_sanitize_boolean',
                ],
                'nhrrob_secure_disable_rest_users' => [
                    'type' => 'boolean',
                    'sanitize_callback' => 'rest_sanitize_boolean',
                ],
                'nhrrob_secure_firewall_blocked_uas' => [
                    'type' => 'string',
                    'sanitize_callback' => 'sanitize_textarea_field',
                ],
                'nhrrob_secure_idle_timeout' => [
                    'type' => 'integer',
                    'sanitize_callback' => 'absint',
                ],
                'nhrrob_secure_enable_advanced_firewall' => [
                    'type' => 'boolean',
                    'sanitize_callback' => 'rest_sanitize_boolean',
                ],
            ],
        ]);

        // Get vulnerability status
        register_rest_route('nhrrob-secure/v1', '/vulnerability/status', [
            'methods' => 'GET',
            'callback' => [$this, 'get_vulnerability_status'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
        ]);

        // Trigger manual scan
        register_rest_route('nhrrob-secure/v1', '/vulnerability/scan', [
            'methods' => 'POST',
            'callback' => [$this, 'trigger_vulnerability_scan'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
        ]);

        // File Scanner - Core Integrity Check
        register_rest_route('nhrrob-secure/v1', '/scanner/core', [
            'methods' => 'POST',
            'callback' => [$this, 'scan_core_files'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
        ]);

        // File Scanner - Malware Scan
        register_rest_route('nhrrob-secure/v1', '/scanner/malware', [
            'methods' => 'POST',
            'callback' => [$this, 'scan_malware'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
        ]);

        // File Scanner - Repair File
        register_rest_route('nhrrob-secure/v1', '/scanner/repair', [
            'methods' => 'POST',
            'callback' => [$this, 'repair_file'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
            'args' => [
                'file' => [
                    'required' => true,
                    'type' => 'string',
                    'sanitize_callback' => 'sanitize_text_field',
                ],
            ],
        ]);

        // File Scanner - Delete File
        register_rest_route('nhrrob-secure/v1', '/scanner/delete', [
            'methods' => 'POST',
            'callback' => [$this, 'delete_suspicious_file'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
            'args' => [
                'file' => [
                    'required' => true,
                    'type' => 'string',
                    'sanitize_callback' => 'sanitize_text_field',
                ],
            ],
        ]);

        // Get audit logs
        register_rest_route('nhrrob-secure/v1', '/logs', [
            'methods' => 'GET',
            'callback' => [$this, 'get_logs'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
        ]);

        // Get sessions
        register_rest_route('nhrrob-secure/v1', '/sessions', [
            'methods' => 'GET',
            'callback' => [$this, 'get_sessions_list'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
        ]);

        // Destroy session
        register_rest_route('nhrrob-secure/v1', '/sessions/destroy', [
            'methods' => 'POST',
            'callback' => [$this, 'destroy_session'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
            'args' => [
                'verifier' => [
                    'required' => true,
                    'type' => 'string',
                    'sanitize_callback' => 'sanitize_text_field',
                ],
            ],
        ]);

        // Destroy other sessions
        register_rest_route('nhrrob-secure/v1', '/sessions/destroy-others', [
            'methods' => 'POST',
            'callback' => [$this, 'destroy_other_sessions'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
        ]);

        // Health check stats
        register_rest_route('nhrrob-secure/v1', '/health-stats', [
            'methods' => 'GET',
            'callback' => [$this, 'get_health_stats'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
        ]);

        // One-click secure
        register_rest_route('nhrrob-secure/v1', '/one-click-secure', [
            'methods' => 'POST',
            'callback' => [$this, 'apply_one_click_secure'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
        ]);
    }

    /**
     * Get settings
     */
    public function get_settings()
    {
        return [
            'nhrrob_secure_limit_login_attempts' => (bool) get_option('nhrrob_secure_limit_login_attempts', 1),
            'nhrrob_secure_login_attempts_limit' => (int) get_option('nhrrob_secure_login_attempts_limit', 5),
            'nhrrob_secure_custom_login_page' => (bool) get_option('nhrrob_secure_custom_login_page', 1),
            'nhrrob_secure_custom_login_url' => get_option('nhrrob_secure_custom_login_url', '/hidden-access-52w'),
            'nhrrob_secure_protect_debug_log' => (bool) get_option('nhrrob_secure_protect_debug_log', 1),
            'nhrrob_secure_enable_proxy_ip' => (bool) get_option('nhrrob_secure_enable_proxy_ip', false),
            'nhrrob_secure_enable_2fa' => (bool) get_option('nhrrob_secure_enable_2fa', 0),
            'nhrrob_secure_2fa_enforced_roles' => (array) get_option('nhrrob_secure_2fa_enforced_roles', []),
            'nhrrob_secure_2fa_type' => get_option('nhrrob_secure_2fa_type', 'app'),
            'nhrrob_secure_dark_mode' => (bool) get_option('nhrrob_secure_dark_mode', false),
            'nhrrob_secure_log_retention_days' => (int) get_option('nhrrob_secure_log_retention_days', 30),
            'nhrrob_secure_disable_xmlrpc' => (bool) get_option('nhrrob_secure_disable_xmlrpc', false),
            'nhrrob_secure_disable_file_editor' => (bool) get_option('nhrrob_secure_disable_file_editor', false),
            'nhrrob_secure_hide_wp_version' => (bool) get_option('nhrrob_secure_hide_wp_version', false),
            'nhrrob_secure_disable_rest_users' => (bool) get_option('nhrrob_secure_disable_rest_users', false),
            'nhrrob_secure_firewall_blocked_uas' => get_option('nhrrob_secure_firewall_blocked_uas', ''),
            'nhrrob_secure_idle_timeout' => (int) get_option('nhrrob_secure_idle_timeout', 0),
            'nhrrob_secure_enable_advanced_firewall' => (bool) get_option('nhrrob_secure_enable_advanced_firewall', false),
            'available_roles' => $this->get_available_roles(),
        ];
    }

    /**
     * Get available user roles
     */
    private function get_available_roles()
    {
        if (!function_exists('get_editable_roles')) {
            require_once ABSPATH . 'wp-admin/includes/user.php';
        }

        $roles = get_editable_roles();
        $output = [];

        foreach ($roles as $role_key => $role_data) {
            $output[] = [
                'value' => $role_key,
                'label' => translate_user_role($role_data['name']),
            ];
        }

        return $output;
    }

    /**
     * Get vulnerability status
     */
    public function get_vulnerability_status()
    {
        $vulnerability = new \NHRRob\Secure\Vulnerability();
        return $vulnerability->get_results();
    }

    /**
     * Trigger vulnerability scan
     */
    public function trigger_vulnerability_scan()
    {
        $vulnerability = new \NHRRob\Secure\Vulnerability();
        return $vulnerability->run_scan();
    }

    /**
     * Update settings
     */
    /**
     * Update settings
     */
    public function update_settings($request)
    {
        $params = $request->get_params();

        foreach ($params as $key => $value) {
            if (strpos($key, 'nhrrob_secure_') === 0) {
                update_option($key, $value);
            }
        }

        return $this->get_settings();
    }

    /**
     * Scan Core Files
     */
    public function scan_core_files()
    {
        $scanner = new \NHRRob\Secure\FileScanner();
        return $scanner->scan_core();
    }

    /**
     * Scan Malware
     */
    public function scan_malware()
    {
        $scanner = new \NHRRob\Secure\FileScanner();
        return $scanner->scan_directory(WP_CONTENT_DIR);
    }

    /**
     * Repair File
     */
    public function repair_file($request)
    {
        $file = $request->get_param('file');
        $scanner = new \NHRRob\Secure\FileScanner();
        $result = $scanner->repair_core_file($file);

        if (is_wp_error($result)) {
            return $result;
        }

        return ['success' => true, 'message' => 'File repaired successfully.'];
    }

    /**
     * Delete Suspicious File
     */
    public function delete_suspicious_file($request)
    {
        $file = $request->get_param('file');
        $scanner = new \NHRRob\Secure\FileScanner();

        // Security check: ensure file is inside WP_CONTENT_DIR
        if (strpos($file, WP_CONTENT_DIR) !== 0) {
            return new \WP_Error('invalid_path', 'Cannot delete files outside of wp-content.');
        }

        if ($scanner->delete_file($file)) {
            return ['success' => true, 'message' => 'File deleted successfully.'];
        }

        return new \WP_Error('delete_failed', 'Could not delete file.');
    }

    /**
     * Get audit logs
     */
    public function get_logs($request)
    {
        $limit = $request->get_param('limit') ? (int) $request->get_param('limit') : 20;
        $offset = $request->get_param('offset') ? (int) $request->get_param('offset') : 0;

        $audit_log = new \NHRRob\Secure\AuditLog();
        return $audit_log->get_logs($limit, $offset);
    }
    /**
     * Get sessions list
     */
    public function get_sessions_list()
    {
        $manager = new \NHRRob\Secure\SessionManager();
        $sessions = $manager->get_sessions(get_current_user_id());
        $current_token = wp_get_session_token();

        $formatted = [];
        foreach ($sessions as $verifier => $session) {
            $formatted[] = [
                'verifier' => $verifier,
                'ip' => $session['ip'],
                'ua' => $session['ua'],
                'login' => $session['login'],
                'expiration' => $session['expiration'],
                'is_current' => $verifier === $current_token,
            ];
        }

        return $formatted;
    }

    /**
     * Destroy session
     */
    public function destroy_session($request)
    {
        $verifier = $request->get_param('verifier');
        $manager = new \NHRRob\Secure\SessionManager();
        $manager->destroy_session(get_current_user_id(), $verifier);

        return ['success' => true];
    }

    /**
     * Destroy other sessions
     */
    public function destroy_other_sessions()
    {
        $manager = new \NHRRob\Secure\SessionManager();
        $manager->destroy_other_sessions(get_current_user_id());

        return ['success' => true];
    }

    /**
     * Get health stats
     */
    public function get_health_stats()
    {
        $health = new \NHRRob\Secure\HealthCheck();
        return $health->get_stats();
    }

    /**
     * Apply one-click secure
     */
    public function apply_one_click_secure()
    {
        $health = new \NHRRob\Secure\HealthCheck();
        $health->apply_one_click_secure();

        return [
            'success' => true,
            'settings' => $this->get_settings(),
            'stats' => $health->get_stats(),
        ];
    }
}
