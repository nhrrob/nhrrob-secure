<?php
/**
 * Protection of files the web server hands out directly.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Services;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Core\Settings;

/**
 * Keeps debug.log, readme files (WordPress's own readme.html and
 * license.txt, which give its version away, included) and PHP in uploads
 * from being served.
 *
 * A file that exists is served by the web server without WordPress ever
 * loading, so this cannot be done from PHP. On Apache and LiteSpeed the
 * plugin writes rules to .htaccess; on nginx it shows the lines to add. Either
 * way each item is then requested from the site itself, and the screen only
 * says "Protected" when that request was refused.
 */
class FileProtection {

	const MARKER = 'NHRRob Secure';

	/**
	 * The .htaccess rules.
	 *
	 * @return string[]
	 */
	public static function htaccess_rules() {
		return [
			'<IfModule mod_rewrite.c>',
			'RewriteEngine On',
			'RewriteRule (^|/)debug\.log$ - [F,L,NC]',
			'RewriteRule ^wp-content/.*/(readme|license|licence|changelog)\.(txt|md|html)$ - [F,L,NC]',
			'RewriteRule (^|/)(readme\.html|license\.txt)$ - [F,L,NC]',
			'RewriteRule ^wp-content/uploads/.*\.(php\d?|phtml|phar)$ - [F,L,NC]',
			'</IfModule>',
		];
	}

	/**
	 * The equivalent nginx lines, for the owner to add.
	 *
	 * @return string
	 */
	public static function nginx_rules() {
		return "location ~* /debug\\.log$ { deny all; }\n"
			. "location ~* /wp-content/.*/(readme|license|licence|changelog)\\.(txt|md|html)$ { deny all; }\n"
			. "location ~* /(readme\\.html|license\\.txt)$ { deny all; }\n"
			. 'location ~* /wp-content/uploads/.*\\.(php\\d?|phtml|phar)$ { deny all; }';
	}

	/**
	 * Which kind of web server this is.
	 *
	 * Outside a web request (WP-CLI) the server does not say, so the answer of
	 * the last check made from a web request is used.
	 *
	 * @return string apache | nginx | other
	 */
	public static function server() {
		global $is_apache, $is_nginx;
		$software = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';
		if ( $is_apache || false !== strpos( $software, 'litespeed' ) ) {
			return 'apache';
		}
		if ( $is_nginx ) {
			return 'nginx';
		}
		if ( '' === $software ) {
			$last = Scan::get( 'files' );
			if ( isset( $last['server'] ) && in_array( $last['server'], [ 'apache', 'nginx' ], true ) ) {
				return $last['server'];
			}
		}
		return 'other';
	}

	/**
	 * Whether the plugin can manage the rules itself on this server.
	 *
	 * @return bool
	 */
	public static function can_write() {
		if ( 'apache' !== self::server() || ( is_multisite() && ! is_main_site() ) ) {
			return false;
		}
		$file = self::htaccess_path();
		return file_exists( $file ) ? wp_is_writable( $file ) : wp_is_writable( dirname( $file ) );
	}

	/**
	 * Path of the site's .htaccess.
	 *
	 * @return string
	 */
	private static function htaccess_path() {
		if ( ! function_exists( 'get_home_path' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		return get_home_path() . '.htaccess';
	}

	/**
	 * Write or remove the rules to match the setting.
	 *
	 * If the site stops answering after the rules are written they are taken
	 * out again straight away.
	 *
	 * @param bool $on Whether protection should be on.
	 * @return bool Whether the file now matches what was asked.
	 */
	public static function apply( $on ) {
		if ( ! self::can_write() ) {
			return false;
		}
		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}
		$file = self::htaccess_path();
		// Nothing to take out of a file that is not there; do not create an empty one.
		if ( ! $on && ! file_exists( $file ) ) {
			return true;
		}
		if ( ! insert_with_markers( $file, self::MARKER, $on ? self::htaccess_rules() : [] ) ) {
			return false;
		}
		if ( $on && 500 <= self::status_of( home_url( '/' ) ) ) {
			insert_with_markers( $file, self::MARKER, [] );
			return false;
		}
		return true;
	}

	/**
	 * What the answer to a PHP path in uploads says. Pure.
	 *
	 * "Forbidden" means a rule is in place, and so does "Not acceptable": a
	 * ModSecurity rule on the host refused the request before ours could.
	 * "Not found" proves nothing on a server whose rules this plugin does not
	 * write: many hosts answer 404 for PHP in uploads on purpose, so it is
	 * reported as unknown, not as open.
	 *
	 * @param int    $status HTTP status (0 when the request failed).
	 * @param string $server apache | nginx | other.
	 * @return string protected | open | unknown
	 */
	public static function uploads_state( $status, $server ) {
		if ( 403 === $status || 406 === $status ) {
			return 'protected';
		}
		if ( 0 === $status || ( 404 === $status && 'apache' !== $server ) ) {
			return 'unknown';
		}
		return 'open';
	}

	/**
	 * Request each protected item from the site itself and report what came back.
	 *
	 * @return array { server, can_write, nginx, checked, items: [ id, label, path, state ] }
	 */
	public static function check() {
		$uploads = wp_get_upload_dir();
		$content = wp_parse_url( content_url(), PHP_URL_PATH );
		$items   = [];

		// A debug log only matters when one exists.
		$log = WP_CONTENT_DIR . '/debug.log';
		if ( defined( 'WP_DEBUG_LOG' ) && is_string( WP_DEBUG_LOG ) && '' !== WP_DEBUG_LOG ) {
			$log = WP_DEBUG_LOG;
		}
		$log_in_content = 0 === strpos( wp_normalize_path( $log ), wp_normalize_path( WP_CONTENT_DIR ) . '/' );
		$log_url        = content_url( ltrim( substr( wp_normalize_path( $log ), strlen( wp_normalize_path( WP_CONTENT_DIR ) ) ), '/' ) );
		if ( ! file_exists( $log ) ) {
			$state = 'absent';
		} elseif ( ! $log_in_content ) {
			$state = 'protected';
		} else {
			$state = self::state( self::status_of( $log_url ), [ 200 ] );
		}
		$items[] = [
			'id'    => 'debug_log',
			'label' => __( 'Debug log', 'nhrrob-secure' ),
			'path'  => $log_in_content ? (string) wp_parse_url( $log_url, PHP_URL_PATH ) : __( 'Stored outside the public folder', 'nhrrob-secure' ),
			'state' => $state,
		];

		// A plugin's readme, and WordPress's own readme.html when it was not deleted.
		$readme = plugins_url( 'readme.txt', NHRROB_SECURE_FILE );
		$states = [ self::state( self::status_of( $readme ), [ 200 ] ) ];
		if ( file_exists( ABSPATH . 'readme.html' ) ) {
			$states[] = self::state( self::status_of( site_url( 'readme.html' ) ), [ 200 ] );
		}
		$items[] = [
			'id'    => 'readme',
			'label' => __( 'Readme and license files', 'nhrrob-secure' ),
			'path'  => (string) wp_parse_url( $readme, PHP_URL_PATH ),
			'state' => in_array( 'open', $states, true ) ? 'open' : ( in_array( 'unknown', $states, true ) ? 'unknown' : 'protected' ),
		];

		// No file is created: a refused request for a PHP path in uploads shows the rule is in place.
		$probe   = trailingslashit( $uploads['baseurl'] ) . 'nhrrob-secure-check.php';
		$status  = self::status_of( $probe );
		$items[] = [
			'id'    => 'uploads_php',
			'label' => __( 'PHP files in uploads', 'nhrrob-secure' ),
			'path'  => (string) wp_parse_url( $probe, PHP_URL_PATH ),
			'state' => self::uploads_state( $status, self::server() ),
		];

		$listing = wp_remote_get( trailingslashit( $uploads['baseurl'] ), self::request_args() );
		if ( is_wp_error( $listing ) ) {
			$state = 'unknown';
		} else {
			$state = 200 === wp_remote_retrieve_response_code( $listing ) && false !== stripos( wp_remote_retrieve_body( $listing ), '<title>Index of' ) ? 'open' : 'protected';
		}
		$items[] = [
			'id'    => 'listing',
			'label' => __( 'Folder listings', 'nhrrob-secure' ),
			'path'  => trailingslashit( (string) wp_parse_url( $uploads['baseurl'], PHP_URL_PATH ) ),
			'state' => $state,
		];

		$result = [
			'server'    => self::server(),
			'can_write' => self::can_write(),
			'nginx'     => self::nginx_rules(),
			'checked'   => time(),
			'items'     => $items,
			'content'   => (string) $content,
		];
		Scan::set( 'files', $result );
		return $result;
	}

	/**
	 * The last check, or a fresh one when there is none.
	 *
	 * @return array
	 */
	public static function last() {
		$last = Scan::get( 'files' );
		return $last ? $last : self::check();
	}

	/**
	 * Turn a status code into a state.
	 *
	 * @param int   $status Response code (0 when the site could not reach itself).
	 * @param int[] $open   Codes that mean the file was served.
	 * @return string open | protected | unknown
	 */
	private static function state( $status, array $open ) {
		if ( 0 === $status ) {
			return 'unknown';
		}
		return in_array( $status, $open, true ) ? 'open' : 'protected';
	}

	/**
	 * Response code of a request from the site to itself.
	 *
	 * @param string $url URL.
	 * @return int 0 when the request failed.
	 */
	private static function status_of( $url ) {
		$response = wp_remote_get( $url, self::request_args() );
		return is_wp_error( $response ) ? 0 : (int) wp_remote_retrieve_response_code( $response );
	}

	/**
	 * Arguments for requests the site makes to itself.
	 *
	 * @return array
	 */
	private static function request_args() {
		return [
			'timeout'     => 6,
			'redirection' => 0,
			/** This filter is documented in wp-includes/class-wp-http-streams.php */
			'sslverify'   => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core filter for requests a site makes to itself.
		];
	}
}
