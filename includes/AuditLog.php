<?php

namespace NHRRob\Secure;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Activity Audit Log Handler
 */
class AuditLog
{

    /**
     * Table name
     */
    const TABLE_NAME = 'nhrrob_audit_log';

    /**
     * Initialize the class
     */
    public function __construct()
    {
        // Create table on init if not exists (checked via option to avoid overhead)
        add_action('init', [$this, 'maybe_install_schema']);

        // Register hooks
        $this->register_hooks();
    }

    /**
     * Register audit hooks
     */
    private function register_hooks()
    {
        // Login/Logout
        add_action('wp_login', [$this, 'log_login'], 10, 2);
        add_action('wp_logout', [$this, 'log_logout']);
        add_action('wp_login_failed', [$this, 'log_login_failed']);

        // Plugins
        add_action('activated_plugin', [$this, 'log_plugin_activation']);
        add_action('deactivated_plugin', [$this, 'log_plugin_deactivation']);

        // Users
        add_action('user_register', [$this, 'log_user_register']);
        add_action('delete_user', [$this, 'log_user_delete']);
        add_action('set_user_role', [$this, 'log_user_role_change'], 10, 3);

        // Posts
        add_action('wp_trash_post', [$this, 'log_post_trash']);
        add_action('untrash_post', [$this, 'log_post_untrash']);
        add_action('delete_post', [$this, 'log_post_delete']);

        // Themes
        add_action('switch_theme', [$this, 'log_switch_theme']);

        // Settings (NHR Secure)
        add_action('nhrrob_secure_settings_updated', [$this, 'log_settings_update']);

        // Cleanup hook
        add_action('nhrrob_secure_daily_cleanup', [$this, 'cleanup_logs']);
    }

    /**
     * Install database schema
     */
    public function maybe_install_schema()
    {
        $installed_ver = get_option('nhrrob_secure_audit_log_version');
        $current_ver = '1.0.0';

        if ($installed_ver !== $current_ver) {
            global $wpdb;
            $table_name = $wpdb->prefix . self::TABLE_NAME;
            $charset_collate = $wpdb->get_charset_collate();

            $sql = "CREATE TABLE $table_name (
                id bigint(20) NOT NULL AUTO_INCREMENT,
                user_id bigint(20) NOT NULL DEFAULT 0,
                event_context varchar(50) NOT NULL,
                event_action varchar(50) NOT NULL,
                item_label varchar(255) NOT NULL,
                details text DEFAULT NULL,
                ip_address varchar(45) NOT NULL,
                severity tinyint(1) NOT NULL DEFAULT 1,
                created_at datetime DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY  (id),
                KEY event_context (event_context),
                KEY user_id (user_id),
                KEY created_at (created_at)
            ) $charset_collate;";

            require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
            dbDelta($sql);

            update_option('nhrrob_secure_audit_log_version', $current_ver);
        }
    }

    /**
     * Log an event
     *
     * @param string $context
     * @param string $action
     * @param string $item_label
     * @param array $details
     * @param int $severity 1: Info, 2: Warning, 3: Critical
     */
    public function log($context, $action, $item_label, $details = [], $severity = 1)
    {
        global $wpdb;
        $table_name = $wpdb->prefix . self::TABLE_NAME;

        $user_id = get_current_user_id();
        $ip = $this->get_ip();

        $wpdb->insert(
            $table_name,
            [
                'user_id' => $user_id,
                'event_context' => $context,
                'event_action' => $action,
                'item_label' => $item_label,
                'details' => json_encode($details),
                'ip_address' => $ip,
                'severity' => $severity,
                'created_at' => current_time('mysql'),
            ],
            ['%d', '%s', '%s', '%s', '%s', '%s', '%d', '%s']
        );
    }

    /**
     * Log login
     */
    public function log_login($user_login, $user)
    {
        $this->log('user', 'login', $user_login, [], 1);
    }

    /**
     * Log logout
     */
    public function log_logout()
    {
        $user = wp_get_current_user();
        if ($user->ID) {
            $this->log('user', 'logout', $user->user_login, [], 1);
        }
    }

    /**
     * Log failed login
     */
    public function log_login_failed($username)
    {
        $this->log('user', 'failed_login', $username, [], 2);
    }

    /**
     * Log plugin activation
     */
    public function log_plugin_activation($plugin)
    {
        $this->log('plugin', 'activated', $plugin, [], 2);
    }

    /**
     * Log plugin deactivation
     */
    public function log_plugin_deactivation($plugin)
    {
        $this->log('plugin', 'deactivated', $plugin, [], 2);
    }

    /**
     * Log user registration
     */
    public function log_user_register($user_id)
    {
        $user = get_userdata($user_id);
        $this->log('user', 'registered', $user->user_login, ['role' => implode(', ', $user->roles)], 2);
    }

    /**
     * Log user deletion
     */
    public function log_user_delete($user_id)
    {
        $user = get_userdata($user_id);
        if ($user) {
            $this->log('user', 'deleted', $user->user_login, [], 3);
        }
    }

    /**
     * Log user role change
     */
    public function log_user_role_change($user_id, $role, $old_roles)
    {
        $user = get_userdata($user_id);
        $this->log('user', 'role_changed', $user->user_login, ['new_role' => $role, 'old_roles' => implode(', ', $old_roles)], 2);
    }

    /**
     * Log post trash
     */
    public function log_post_trash($post_id)
    {
        if (!current_user_can('edit_post', $post_id))
            return;
        $post = get_post($post_id);
        if ($post->post_status !== 'auto-draft' && $post->post_type !== 'revision') {
            $this->log('post', 'trashed', $post->post_title, ['type' => $post->post_type], 1);
        }
    }

    /**
     * Log post untrash
     */
    public function log_post_untrash($post_id)
    {
        $post = get_post($post_id);
        $this->log('post', 'restored', $post->post_title, [], 1);
    }

    /**
     * Log post delete (permanent)
     */
    public function log_post_delete($post_id)
    {
        $post = get_post($post_id);
        if ($post && $post->post_status !== 'auto-draft' && $post->post_type !== 'revision') {
            $this->log('post', 'deleted_permanently', $post->post_title, ['type' => $post->post_type], 2);
        }
    }

    /**
     * Log theme switch
     */
    public function log_switch_theme($new_name, $new_theme = null)
    {
        // WP 5.0+ passes WP_Theme object as second arg, or just name
        $name = is_object($new_name) ? $new_name->get('Name') : $new_name;
        $this->log('theme', 'switched', $name, [], 2);
    }

    /**
     * Log settings update
     */
    public function log_settings_update($settings)
    {
        $this->log('settings', 'updated', 'NHR Secure Settings', $settings, 2);
    }

    /**
     * Cleanup old logs
     */
    public function cleanup_logs()
    {
        global $wpdb;
        $table_name = $wpdb->prefix . self::TABLE_NAME;

        $days = (int) get_option('nhrrob_secure_log_retention_days', 30);
        $date_limit = date('Y-m-d H:i:s', strtotime("-$days days"));

        $wpdb->query($wpdb->prepare("DELETE FROM $table_name WHERE created_at < %s", $date_limit));
    }

    /**
     * Get client IP
     */
    private function get_ip()
    {
        $ip = 'unknown';
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = sanitize_text_field(wp_unslash($_SERVER['HTTP_CLIENT_IP']));
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_FOR']));
        } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
            $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
        }
        return $ip;
    }

    /**
     * Get logs for API
     * 
     * @param int $limit
     * @param int $offset
     * @return array
     */
    public function get_logs($limit = 20, $offset = 0)
    {
        global $wpdb;
        $table_name = $wpdb->prefix . self::TABLE_NAME;

        $items = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM $table_name ORDER BY created_at DESC LIMIT %d OFFSET %d",
            $limit,
            $offset
        ));

        $formatted = [];
        foreach ($items as $item) {
            $user_info = get_userdata($item->user_id);
            $username = $user_info ? $user_info->user_login : 'System/Guest';
            if ($item->user_id == 0)
                $username = 'System/Guest';

            $formatted[] = [
                'id' => $item->id,
                'user' => $username,
                'context' => $item->event_context,
                'action' => $item->event_action,
                'label' => $item->item_label,
                'ip' => $item->ip_address,
                'date' => $item->created_at,
                'severity' => $item->severity,
            ];
        }

        $total = $wpdb->get_var("SELECT COUNT(*) FROM $table_name");

        return [
            'items' => $formatted,
            'total' => (int) $total
        ];
    }
}
