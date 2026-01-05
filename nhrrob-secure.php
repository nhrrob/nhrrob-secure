<?php
/**
 * Plugin Name: NHR Secure | Protect Admin, Debug Logs & Limit Logins
 * Plugin URI: http://wordpress.org/plugins/nhrrob-secure/
 * Description: Lightweight WordPress security plugin that protects your admin area, hides debug logs, and limits login attempts. Minimal code, maximum protection.
 * Author: Nazmul Hasan Robin
 * Author URI: https://profiles.wordpress.org/nhrrob/
 * Version: 1.0.3
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Text Domain: nhrrob-secure
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly

define( 'NHRROB_SECURE_VERSION', '1.0.3' );
define( 'NHRROB_SECURE_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );

/**
 * Feature List
 * 1. Limit Login Attempts
 * 2. Custom Login Page (/hidden-access-52w instead of /wp-login.php)
 * 3. Protect Sensitive Files (debug.log)
 */

 /**
 * ============================
 * Helper: Get client IP
 * ============================
 *
 * - Default: uses REMOTE_ADDR
 * - Enable proxy detection:
 *   add_filter( 'nhrrob_secure_enable_proxy_ip', '__return_true' );
 */
function nhrrob_secure_get_ip() {
    $ip   = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : 'unknown';

    $enable_proxy = apply_filters( 'nhrrob_secure_enable_proxy_ip', false );

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
 * ============================
 * Helper: Get limit login failed and block transients
 * ============================
 *
 * @param string $username The username of the user.
 * @return array The array contains the failed_key, block_key, failed_value, and block_value.
 */
function nhrrob_secure_get_limit_login_transients( $username ) {
    $ip = nhrrob_secure_get_ip();
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
 * ============================
 * Helper: Render 404 Page
 * ============================
 */
function nhrrob_secure_render_404() {
    wp_safe_redirect( home_url( '404' ) );
    exit;
}

/**
 * ============================================================
 * 1. LIMIT LOGIN ATTEMPTS (IP + Username)
 * ============================================================
 *
 * Tracks failed login attempts and blocks IP addresses that exceed the limit.
 *
 * Usage:
 * - Change the maximum allowed login attempts:
 *   add_filter( 'nhrrob_secure_login_attempts_limit', fn() => 10 );
 * - Turn off the feature:
 *   add_filter( 'nhrrob_secure_limit_login_attempts', fn() => false );
 */
function nhrrob_secure_limit_login_attempts_init() {
    if ( ! apply_filters( 'nhrrob_secure_limit_login_attempts', true ) ) {
        return;
    }

    add_action( 'wp_login_failed', function( $username ) {
        $transients = nhrrob_secure_get_limit_login_transients( $username );
        $failed_value = (int) $transients['failed_value'] + 1;

        set_transient( $transients['failed_key'], $failed_value, HOUR_IN_SECONDS );

        $limit = (int) apply_filters( 'nhrrob_secure_login_attempts_limit', 5 );

        if ( $failed_value >= $limit ) {
            set_transient( $transients['block_key'], true, 2 * HOUR_IN_SECONDS );
        }
    });

    add_action( 'wp_login', function( $user_login ) {
        $transients = nhrrob_secure_get_limit_login_transients( $user_login );
        delete_transient( $transients['failed_key'] );
        delete_transient( $transients['block_key'] );
    });

    add_filter( 'authenticate', function( $user, $username = null, $password = null ) {
        $username_clean = is_string( $username ) ? strtolower( sanitize_user( $username, true ) ) : '';
        if ( empty( $username_clean ) ) {
            return $user;
        }

        $transients = nhrrob_secure_get_limit_login_transients( $username_clean );

        if ( $transients['block_value'] ) {
            return new WP_Error(
                'nhrrob_secure_blocked',
                __( 'Too many failed login attempts for this account from your IP. Try again later.', 'nhrrob-secure' )
            );
        }

        return $user;
    }, 30, 3 );
}

add_action( 'init', 'nhrrob_secure_limit_login_attempts_init' );

/**
 * ============================================================
 * 2. CUSTOM LOGIN PAGE
 * ============================================================
 *
 * Changes default login URL from /wp-login.php to /hidden-access-52w
 *
 * Usage:
 * - Change the custom login URL:
 *   add_filter( 'nhrrob_secure_custom_login_url', fn() => '/my-custom-login' );
 * - Turn off the feature:
 *   add_filter( 'nhrrob_secure_custom_login_page', '__return_false' );
 */
function nhrrob_secure_custom_login_page_init() {
    if ( ! apply_filters( 'nhrrob_secure_custom_login_page', true ) ) {
        return;
    }

    // Block direct access to wp-login.php
    $script_name = isset( $_SERVER['SCRIPT_NAME'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) : '';
    if ( strpos( $script_name, '/wp-login.php' ) !== false ) {
        nhrrob_secure_render_404();
    }
    
    // Block direct access to wp-admin for guests
    add_action( 'init', function() {
        $script_name = isset( $_SERVER['SCRIPT_NAME'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) : '';
        
        if ( is_admin() && ! is_user_logged_in() && ! defined( 'DOING_AJAX' ) && ! defined( 'DOING_CRON' ) ) {
             // Allow admin-post.php for frontend form submissions
             if ( strpos( $script_name, 'admin-post.php' ) === false ) {
                 nhrrob_secure_render_404();
             }
        }
    });

    // Handle custom login URL (use template_redirect for proper WordPress context)
    add_action( 'template_redirect', function() {
        $custom_login_url = apply_filters( 'nhrrob_secure_custom_login_url', '/hidden-access-52w' );
        $custom_login_url = trim( $custom_login_url, '/' );
        $custom_login_url = '/' . ltrim( $custom_login_url, '/' );

        $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
        $parsed_url = wp_parse_url( $request_uri );
        $path = isset( $parsed_url['path'] ) ? $parsed_url['path'] : '';

        // Normalize path (remove trailing slash for comparison)
        $path_normalized = rtrim( $path, '/' );
        $custom_login_url_normalized = rtrim( $custom_login_url, '/' );

        // Check if request is for custom login URL
        if ( $path_normalized === $custom_login_url_normalized || $path === $custom_login_url || $path === $custom_login_url . '/' ) {
            // Preserve query string
            $query_string = isset( $parsed_url['query'] ) ? '?' . $parsed_url['query'] : '';
            
            // Temporarily modify REQUEST_URI to load wp-login.php
            $_SERVER['REQUEST_URI'] = '/wp-login.php' . $query_string;
            
            // Bring globals into scope for wp-login.php
            global $error, $interim_login, $action, $wp_error, $user_login;
            
            // Override 404 status (since WP thinks this slug doesn't exist)
            if ( function_exists( 'status_header' ) ) {
                status_header( 200 );
            }
            if ( function_exists( 'nocache_headers' ) ) {
                nocache_headers();
            }

            // Suppress warnings for re-definition of constants in wp-config.php
            if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
                $error_reporting = error_reporting( E_ERROR | E_PARSE );
            }
            
            // Load WordPress login
            require_once( ABSPATH . 'wp-login.php' );
            
            if ( isset( $error_reporting ) ) {
                error_reporting( $error_reporting );
            }
            
            exit;
        }
    }, 1 );

    // Rewrite wp-login.php URLs to custom login URL
    add_filter( 'site_url', function( $url, $path, $scheme ) {
        if ( strpos( $url, 'wp-login.php' ) !== false ) {
            $custom_login_url = apply_filters( 'nhrrob_secure_custom_login_url', '/hidden-access-52w' );
            $custom_login_url = trim( $custom_login_url, '/' ); 
            $url = str_replace( 'wp-login.php', $custom_login_url, $url );
            $url = str_replace( '//' . $custom_login_url, '/' . $custom_login_url, $url ); // fix potential double slash if any
        }
        return $url;
    }, 10, 3 );
}

add_action( 'init', 'nhrrob_secure_custom_login_page_init', 0 );

/**
 * ============================================================
 * 3. PROTECT DEBUG LOG FILE
 * ============================================================
 *
 * Blocks direct access to /wp-content/debug.log
 * Shows 403 Forbidden for all users
 *
 * Usage:
 * - Turn off the feature:
 *   add_filter( 'nhrrob_secure_protect_debug_log', '__return_false' );
 */
function nhrrob_secure_protect_debug_log_init() {
    if ( ! apply_filters( 'nhrrob_secure_protect_debug_log', true ) ) {
        return;
    }

    // Check early to catch direct file access
    add_action( 'plugins_loaded', function() {
        $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
        $parsed_url = wp_parse_url( $request_uri );
        $path = isset( $parsed_url['path'] ) ? $parsed_url['path'] : '';

        // Check if request is for debug.log in wp-content directory
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
    }, 1 );

    // Also check in template_redirect as backup
    add_action( 'template_redirect', function() {
        $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
        $parsed_url = wp_parse_url( $request_uri );
        $path = isset( $parsed_url['path'] ) ? $parsed_url['path'] : '';

        // Check if request is for debug.log in wp-content directory
        if ( strpos( $path, '/wp-content/debug.log' ) !== false || 
             ( strpos( $path, 'debug.log' ) !== false && strpos( $path, 'wp-content' ) !== false ) ) {
            status_header( 403 );
            nocache_headers();
            header( 'Content-Type: text/html; charset=utf-8' );
            die( '403 Forbidden' );
        }
    }, 1 );
}

add_action( 'init', 'nhrrob_secure_protect_debug_log_init', 0 );

/**
 * Enable/Disable Features
 * Example usages are shown below
 */

// Turn off limit login attempts
// add_filter( 'nhrrob_secure_limit_login_attempts', '__return_false' );

// Turn off custom login page
// add_filter( 'nhrrob_secure_custom_login_page', '__return_false' );

// Turn off debug log protection
// add_filter( 'nhrrob_secure_protect_debug_log', '__return_false' );