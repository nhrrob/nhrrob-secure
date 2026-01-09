<?php

namespace NHRRob\Secure;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}


/**
 * Security Features Handler
 */
class Security {
    
    /**
     * Initialize security features
     */
    public function __construct() {
        $this->init_limit_login_attempts();
        $this->init_custom_login_page();
        $this->init_protect_debug_log();
    }

    /**
     * Get client IP address
     *
     * @return string
     */
    public function get_ip() {
        $ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : 'unknown';

        $enable_proxy_option = get_option( 'nhrrob_secure_enable_proxy_ip', false );
        $enable_proxy = apply_filters( 'nhrrob_secure_enable_proxy_ip', $enable_proxy_option );

        if ( $enable_proxy ) {
            if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
                $ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
            } elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
                $parts = explode( ',', sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
                $ip = sanitize_text_field( trim( $parts[0] ) );
            }
        }

        return apply_filters( 'nhrrob_secure_get_ip', $ip );
    }

    /**
     * Get limit login transients
     *
     * @param string $username
     * @return array
     */
    public function get_limit_login_transients( $username ) {
        $ip = $this->get_ip();
        $username_clean = is_string( $username ) ? strtolower( sanitize_user( $username, true ) ) : 'unknown';
        $md5 = md5( $ip . '|' . $username_clean );

        $failed_key = 'nhrrob_secure_failed_' . $md5;
        $failed_value = (int) get_transient( $failed_key );
        $block_key = 'nhrrob_secure_block_' . $md5;
        $block_value = get_transient( $block_key );
        
        return [ 
            'failed_key' => $failed_key, 
            'block_key' => $block_key, 
            'failed_value' => $failed_value, 
            'block_value' => $block_value,
        ];
    }

    /**
     * Render 404 page
     */
    public function render_404() {
        wp_safe_redirect( home_url( '404' ) );
        exit;
    }

    /**
     * Initialize limit login attempts feature
     */
    private function init_limit_login_attempts() {
        $limit_login_option = get_option( 'nhrrob_secure_limit_login_attempts', 1 );
        if ( ! apply_filters( 'nhrrob_secure_limit_login_attempts', $limit_login_option ) ) {
            return;
        }

        add_action( 'wp_login_failed', [ $this, 'handle_login_failed' ] );
        add_action( 'wp_login', [ $this, 'handle_login_success' ] );
        add_filter( 'authenticate', [ $this, 'check_login_block' ], 30, 3 );
    }

    /**
     * Handle failed login
     */
    public function handle_login_failed( $username ) {
        $transients = $this->get_limit_login_transients( $username );
        $failed_value = (int) $transients['failed_value'] + 1;

        set_transient( $transients['failed_key'], $failed_value, HOUR_IN_SECONDS );

        $limit_option = get_option( 'nhrrob_secure_login_attempts_limit', 5 );
        $limit = (int) apply_filters( 'nhrrob_secure_login_attempts_limit', $limit_option );

        if ( $failed_value >= $limit ) {
            set_transient( $transients['block_key'], true, 2 * HOUR_IN_SECONDS );
        }
    }

    /**
     * Handle successful login
     */
    public function handle_login_success( $user_login ) {
        $transients = $this->get_limit_login_transients( $user_login );
        delete_transient( $transients['failed_key'] );
        delete_transient( $transients['block_key'] );
    }

    /**
     * Check if login is blocked
     */
    public function check_login_block( $user, $username = null, $password = null ) {
        $username_clean = is_string( $username ) ? strtolower( sanitize_user( $username, true ) ) : '';
        if ( empty( $username_clean ) ) {
            return $user;
        }

        $transients = $this->get_limit_login_transients( $username_clean );

        if ( $transients['block_value'] ) {
            return new \WP_Error(
                'nhrrob_secure_blocked',
                esc_html__( 'Too many failed login attempts for this account from your IP. Try again later.', 'nhrrob-secure' )
            );
        }

        return $user;
    }

    /**
     * Initialize custom login page feature
     */
    private function init_custom_login_page() {
        $custom_login_page_option = get_option( 'nhrrob_secure_custom_login_page', 1 );
        if ( ! apply_filters( 'nhrrob_secure_custom_login_page', $custom_login_page_option ) ) {
            return;
        }

        // Block direct access to wp-login.php
        $script_name = isset( $_SERVER['SCRIPT_NAME'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) : '';
        if ( strpos( $script_name, '/wp-login.php' ) !== false ) {
            $this->render_404();
        }
        
        // Block direct access to wp-admin for guests
        add_action( 'init', [ $this, 'block_admin_access' ] );

        // Handle custom login URL
        add_action( 'template_redirect', [ $this, 'handle_custom_login_url' ], 1 );

        // Rewrite wp-login.php URLs
        add_filter( 'site_url', [ $this, 'rewrite_login_url' ], 10, 3 );
    }

    /**
     * Block admin access for guests
     */
    public function block_admin_access() {
        $script_name = isset( $_SERVER['SCRIPT_NAME'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) : '';
        
        if ( is_admin() && ! is_user_logged_in() && ! defined( 'DOING_AJAX' ) && ! defined( 'DOING_CRON' ) ) {
            if ( strpos( $script_name, 'admin-post.php' ) === false ) {
                $this->render_404();
            }
        }
    }

    /**
     * Handle custom login URL
     */
    public function handle_custom_login_url() {
        $custom_login_url_option = get_option( 'nhrrob_secure_custom_login_url', '/hidden-access-52w' );
        $custom_login_url = apply_filters( 'nhrrob_secure_custom_login_url', $custom_login_url_option );
        $custom_login_url = trim( $custom_login_url, '/' );
        $custom_login_url = '/' . ltrim( $custom_login_url, '/' );

        $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
        $parsed_url = wp_parse_url( $request_uri );
        $path = isset( $parsed_url['path'] ) ? $parsed_url['path'] : '';

        $path_normalized = rtrim( $path, '/' );
        $custom_login_url_normalized = rtrim( $custom_login_url, '/' );

        if ( $path_normalized === $custom_login_url_normalized || $path === $custom_login_url || $path === $custom_login_url . '/' ) {
            $query_string = isset( $parsed_url['query'] ) ? '?' . $parsed_url['query'] : '';
            $_SERVER['REQUEST_URI'] = '/wp-login.php' . $query_string;
            
            global $error, $interim_login, $action, $wp_error, $user_login;
            
            if ( function_exists( 'status_header' ) ) {
                status_header( 200 );
            }
            if ( function_exists( 'nocache_headers' ) ) {
                nocache_headers();
            }

            require_once( ABSPATH . 'wp-login.php' );
            exit;
        }
    }

    /**
     * Rewrite login URL
     */
    public function rewrite_login_url( $url, $path, $scheme ) {
        if ( strpos( $url, 'wp-login.php' ) !== false ) {
            $custom_login_url_option = get_option( 'nhrrob_secure_custom_login_url', '/hidden-access-52w' );
            $custom_login_url = apply_filters( 'nhrrob_secure_custom_login_url', $custom_login_url_option );
            $custom_login_url = trim( $custom_login_url, '/' ); 
            $url = str_replace( 'wp-login.php', $custom_login_url, $url );
            $url = str_replace( '//' . $custom_login_url, '/' . $custom_login_url, $url );
        }
        return $url;
    }

    /**
     * Initialize debug log protection
     */
    private function init_protect_debug_log() {
        $protect_debug_log_option = get_option( 'nhrrob_secure_protect_debug_log', 1 );
        if ( ! apply_filters( 'nhrrob_secure_protect_debug_log', $protect_debug_log_option ) ) {
            return;
        }

        add_action( 'plugins_loaded', [ $this, 'check_debug_log_access' ], 1 );
        add_action( 'template_redirect', [ $this, 'check_debug_log_access_template' ], 1 );
    }

    /**
     * Check debug log access early
     */
    public function check_debug_log_access() {
        $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
        $parsed_url = wp_parse_url( $request_uri );
        $path = isset( $parsed_url['path'] ) ? $parsed_url['path'] : '';

        if ( strpos( $path, '/wp-content/debug.log' ) !== false || 
             ( strpos( $path, 'debug.log' ) !== false && strpos( $path, 'wp-content' ) !== false ) ) {
            if ( function_exists( 'status_header' ) ) {
                status_header( 403 );
            } else {
                http_response_code( 403 );
            }
            if ( function_exists( 'nocache_headers' ) ) {
                nocache_headers();
            }
            header( 'Content-Type: text/html; charset=utf-8' );
            die( '403 Forbidden' );
        }
    }

    /**
     * Check debug log access in template redirect
     */
    public function check_debug_log_access_template() {
        $this->check_debug_log_access();
    }
}
