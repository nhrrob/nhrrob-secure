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
 * 2. Hide /wp-admin/ from non-admins
 * 3. Protect Sensitive Files
 * 4. Remove WordPress Version Info
 * 5. Disable File Editing in wp-admin
 * 6. Customizable Login URL
 * 7. Block XML-RPC
 * 8. Block wp-config.php Access
 * 9. Block wp-includes Access
 * 10. Block wp-content/plugins and wp-content/themes Access
 */

// 1. Limit Login Attempts
add_action( 'wp_login_failed', function( $username ) {
    $ip   = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $key  = 'nhrrob_secure_failed_' . md5( $ip );
    $fails = (int) get_transient( $key );

    $fails++;
    set_transient( $key, $fails, HOUR_IN_SECONDS );

    // If 5 or more failed attempts, block IP for 2 hours.
    $limit = apply_filters( 'nhrrob_secure_login_attempts_limit', 5 );
    if ( $fails >= $limit ) {
        set_transient( 'nhrrob_secure_block_' . md5( $ip ), true, 2 * HOUR_IN_SECONDS );
    }
});

add_filter( 'authenticate', function( $user ) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if ( get_transient( 'nhrrob_secure_block_' . md5( $ip ) ) ) {
        wp_die(
            __( 'Too many failed login attempts. Please try again later.', 'nhrrob-secure' ),
            __( 'Login Temporarily Blocked', 'nhrrob-secure' ),
            array( 'response' => 403 )
        );
    }
    return $user;
}, 30 );


// 2. Hide /wp-admin/ from non-admins
add_action( 'init', function() {
    if ( is_admin() && ! current_user_can( 'manage_options' ) && ! ( defined( 'DOING_AJAX' ) && DOING_AJAX ) ) {
        wp_redirect( home_url() );
        exit;
    }
});

// 3. Protect Sensitive Files
add_action( 'init', function() {
    $wp_content = WP_CONTENT_DIR;
    $htaccess_path = trailingslashit( $wp_content ) . '.htaccess';

    // Rules to block sensitive files if .htaccess doesn’t already exist.
    if ( ! file_exists( $htaccess_path ) ) {
        $rules = <<<HTACCESS
# NHR Secure Protection
<FilesMatch "(debug\.log|\.env|\.git|readme\.html|readme\.txt)">
Order allow,deny
Deny from all
</FilesMatch>
HTACCESS;
        file_put_contents( $htaccess_path, $rules );
    }
});

// 4. Remove WordPress Version Info
remove_action( 'wp_head', 'wp_generator' );
add_filter( 'the_generator', '__return_empty_string' );

// 5. Disable file editing in wp-admin (safeguard)
if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
    define( 'DISALLOW_FILE_EDIT', true );
}

// 6. Customizable Login URL
add_filter( 'login_url', function( $login_url, $redirect, $force_reauth ) {
    return home_url( 'login' ); // Change 'login' to your desired URL slug.
}, 10, 3 );

// 7. Block XML-RPC
add_filter( 'xmlrpc_enabled', '__return_false' );

// 8. Block wp-config.php Access
add_action( 'init', function() {
    if ( basename( $_SERVER['PHP_SELF'] ) === 'wp-config.php' ) {
        wp_die( 'Access Denied', 'Error', array( 'response' => 403 ) );
    }
});

// 9. Block wp-includes Access
add_action( 'init', function() {
    if ( strpos( $_SERVER['PHP_SELF'], 'wp-includes' ) !== false ) {
        wp_die( 'Access Denied', 'Error', array( 'response' => 403 ) );
    }
});

// 10. Block wp-content/plugins and wp-content/themes Access
add_action( 'init', function() {
    if ( strpos( $_SERVER['PHP_SELF'], 'wp-content/plugins' ) !== false || strpos( $_SERVER['PHP_SELF'], 'wp-content/themes' ) !== false ) {
        wp_die( 'Access Denied', 'Error', array( 'response' => 403 ) );
    }
});