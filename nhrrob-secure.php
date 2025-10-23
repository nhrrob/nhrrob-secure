<?php
/**
 * Plugin Name: NHR Secure | Protect Admin, Debug Logs & Limit Logins
 * Plugin URI: http://wordpress.org/plugins/nhrrob-secure/
 * Description: Lightweight WordPress security plugin that protects your admin area, hides debug logs, and limits login attempts. Minimal code, maximum protection.
 * Author: Nazmul Hasan Robin
 * Author URI: https://profiles.wordpress.org/nhrrob/
 * Version: 1.0.0
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Text Domain: nhrrob-secure
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly

define( 'NHRROB_SECURE_VERSION', '1.0.0' );
define( 'NHRROB_SECURE_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );

/**
 * Feature List
 * 1. Limit Login Attempts
 * 2. Customizable Login URL
 * 3. Protect Sensitive Files (debug.log)
 */

/**
 * ============================================================
 * 1. LIMIT LOGIN ATTEMPTS
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
function nhrrob_secure_limit_login_attempts() {
    add_action( 'wp_login_failed', function( $username ) {
        $ip   = sanitize_text_field( $_SERVER['REMOTE_ADDR'] ?? 'unknown' );
        $key  = 'nhrrob_secure_failed_' . md5( $ip );
        $fails = (int) get_transient( $key );
    
        $fails++;
        set_transient( $key, $fails, HOUR_IN_SECONDS );
    
        $limit = apply_filters( 'nhrrob_secure_login_attempts_limit', 5 );

        if ( $fails >= $limit ) {
            set_transient( 'nhrrob_secure_block_' . md5( $ip ), true, 2 * HOUR_IN_SECONDS );
        }
    });
    
    add_filter( 'authenticate', function( $user ) {
        $ip = sanitize_text_field( $_SERVER['REMOTE_ADDR'] ?? 'unknown' );
        $blocked = get_transient( 'nhrrob_secure_block_' . md5( $ip ) );
        
        if ( $blocked ) {
            return new WP_Error( 
                'nhrrob_secure_blocked',
                __( 'Too many failed login attempts. Please try again later.', 'nhrrob-secure' ) 
            );
        }
    
        return $user;
    }, 30 );
}

/**
 * ============================================================
 * 2. CUSTOMIZABLE LOGIN URL
 * ============================================================
 *
 * Default login URL: /login
 * 
 * Usage:
 * - Change the custom login URL:
 *   add_filter( 'nhrrob_secure_custom_login_url', fn() => 'secure-login' );
 * - Turn off the feature:
 *   add_filter( 'nhrrob_secure_custom_login_url', fn() => false );
 */
function nhrrob_secure_custom_login_url() {
    add_filter( 'login_url', function( $login_url, $redirect, $force_reauth ) {
        $custom_login_slug = apply_filters( 'nhrrob_secure_custom_login_url', 'login' );
        $custom_login_slug = sanitize_text_field( $custom_login_slug );
    
        $custom_login_url = home_url( $custom_login_slug );
    
        if ( ! empty( $redirect ) ) {
            $custom_login_url = add_query_arg( 'redirect_to', urlencode( $redirect ), $custom_login_url );
        }
    
        return $custom_login_url;
    }, 10, 3 );

    // Handle requests to the custom login page
    add_action( 'template_redirect', function() {
        $custom_login_slug = apply_filters( 'nhrrob_secure_custom_login_url', 'login' );
        $custom_login_slug = sanitize_title( $custom_login_slug );
        $request_uri       = trim( $_SERVER['REQUEST_URI'], '/' );
    
        if ( $request_uri === $custom_login_slug ) {
            status_header( 200 );
            nocache_headers();
            require_once ABSPATH . 'wp-login.php';
            exit;
        }
    });    
}

/**
 * ============================================================
 * 3. PROTECT SENSITIVE FILES (debug.log)
 * ============================================================
 *
 * Protects sensitive files from unauthorized access.
 *
 * Usage:
 * - Add more files to protect:
 *   add_filter( 'nhrrob_secure_protected_files', fn( $files ) => array_merge( $files, ['my-secret-file.txt'] ) );
 * - Turn off the feature:
 *   add_filter( 'nhrrob_secure_protect_sensitive_files', fn() => false );
 */
function nhrrob_secure_protect_sensitive_files() {
    add_action( 'init', function() {
        $request_uri = sanitize_text_field( $_SERVER['REQUEST_URI'] ?? '' );

        $sensitive_files = apply_filters(
            'nhrrob_secure_protected_files',
            ['debug.log', '.env', '.git', 'readme.html', 'readme.txt']
        );

        foreach ( $sensitive_files as $file ) {
            if ( strpos( $request_uri, $file ) !== false ) {
                wp_safe_redirect( home_url() );
                exit;
            }
        }
    });
}

// Call the functions
if ( apply_filters( 'nhrrob_secure_limit_login_attempts', true ) ) {
    nhrrob_secure_limit_login_attempts();
}

if ( apply_filters( 'nhrrob_secure_custom_login_url', true ) ) {
    nhrrob_secure_custom_login_url();
}

if ( apply_filters( 'nhrrob_secure_protect_sensitive_files', true ) ) {
    nhrrob_secure_protect_sensitive_files();
}