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
 * 2. Protect Sensitive Files (debug.log)
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
            $parts = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] );
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
function get_limit_login_transients( $username ) {
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
        $transients = get_limit_login_transients( $username );
        $failed_value = (int) $transients['failed_value'] + 1;

        set_transient( $transients['failed_key'], $failed_value, HOUR_IN_SECONDS );

        $limit = (int) apply_filters( 'nhrrob_secure_login_attempts_limit', 5 );

        if ( $failed_value >= $limit ) {
            set_transient( $transients['block_key'], true, 2 * HOUR_IN_SECONDS );
        }
    });

    add_action( 'wp_login', function( $user_login ) {
        $transients = get_limit_login_transients( $user_login );
        delete_transient( $transients['failed_key'] );
        delete_transient( $transients['block_key'] );
    });

    add_filter( 'authenticate', function( $user, $username = null, $password = null ) {
        $username_clean = is_string( $username ) ? strtolower( sanitize_user( $username, true ) ) : '';
        if ( empty( $username_clean ) ) {
            return $user;
        }

        $transients = get_limit_login_transients( $username_clean );

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
 * 2. PROTECT SENSITIVE FILES (debug.log)
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
function nhrrob_secure_protect_sensitive_files_init() {
    if ( ! apply_filters( 'nhrrob_secure_protect_sensitive_files', true ) ) {
        return;
    }

    add_action( 'init', function() {
        $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
        
        if ( empty( $request_uri ) ) {
            return;
        }

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
    }, 1 );
}

add_action( 'init', 'nhrrob_secure_protect_sensitive_files_init' );

/**
 * Enable/Disable Features
 * Example usages are shown below
 */

// Turn off limit login attempts
// add_filter( 'nhrrob_secure_limit_login_attempts', '__return_false' );

// Turn off protect sensitive files
// add_filter( 'nhrrob_secure_protect_sensitive_files', '__return_false' );