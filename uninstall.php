<?php
/**
 * Fired when the plugin is uninstalled.
 */

// If uninstall not called from WordPress, then exit.
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Drop the audit log table
global $wpdb;
$table_name = $wpdb->prefix . 'nhrrob_audit_log';
$wpdb->query("DROP TABLE IF EXISTS $table_name");

// Delete options
delete_option('nhrrob_secure_limit_login_attempts');
delete_option('nhrrob_secure_login_attempts_limit');
delete_option('nhrrob_secure_custom_login_page');
delete_option('nhrrob_secure_custom_login_url');
delete_option('nhrrob_secure_protect_debug_log');
delete_option('nhrrob_secure_enable_proxy_ip');
delete_option('nhrrob_secure_enable_2fa');
delete_option('nhrrob_secure_2fa_enforced_roles');
delete_option('nhrrob_secure_2fa_type');
delete_option('nhrrob_secure_dark_mode');
delete_option('nhrrob_secure_audit_log_version');
delete_option('nhrrob_secure_log_retention_days');

// Delete transients
$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_nhrrob_secure_%'");
$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_nhrrob_secure_%'");
