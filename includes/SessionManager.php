<?php

namespace NHRRob\Secure;

if (!defined('ABSPATH')) {
    exit;
}

class SessionManager
{

    public function __construct()
    {
        // Hook for idle timeout
        add_action('admin_init', [$this, 'check_idle_timeout']);
        add_action('wp_login', [$this, 'reset_last_activity'], 10, 2);
    }

    /**
     * Get all sessions for a user
     */
    public function get_sessions($user_id)
    {
        $manager = \WP_Session_Tokens::get_instance($user_id);
        return $manager->get_all();
    }

    /**
     * Destroy a specific session
     */
    public function destroy_session($user_id, $verifier)
    {
        $manager = \WP_Session_Tokens::get_instance($user_id);
        $manager->destroy($verifier);
    }

    /**
     * Destroy all sessions except the current one
     */
    public function destroy_other_sessions($user_id)
    {
        $manager = \WP_Session_Tokens::get_instance($user_id);
        $manager->destroy_others(wp_get_session_token());
    }

    /**
     * Check for idle timeout
     */
    public function check_idle_timeout()
    {
        if (!is_user_logged_in()) {
            return;
        }

        $timeout_minutes = (int) get_option('nhrrob_secure_idle_timeout', 0);
        if ($timeout_minutes <= 0) {
            return;
        }

        $user_id = get_current_user_id();
        $last_activity = get_user_meta($user_id, 'nhrrob_secure_last_activity', true);
        $current_time = time();

        if ($last_activity && ($current_time - $last_activity > $timeout_minutes * 60)) {
            // Idle timeout exceeded
            wp_destroy_current_session();
            wp_clear_auth_cookie();

            // Redirect to login with a message
            wp_safe_redirect(wp_login_url() . '?forced_logout=idle');
            exit;
        }

        // Update last activity
        update_user_meta($user_id, 'nhrrob_secure_last_activity', $current_time);
    }

    /**
     * Reset last activity on login
     */
    public function reset_last_activity($user_login, $user)
    {
        update_user_meta($user->ID, 'nhrrob_secure_last_activity', time());
    }
}
