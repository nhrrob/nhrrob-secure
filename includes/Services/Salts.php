<?php
/**
 * Rotation of the secret keys in wp-config.php.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Services;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Core\Activity;

/**
 * Replaces the eight secret keys and salts with new random ones. Every
 * sign-in cookie on the site stops working, which is the point: after a
 * break-in, a copied cookie or a copied wp-config.php is worth nothing.
 *
 * A mistake in wp-config.php takes the site down, so:
 * only the eight values are touched, and only when each is a plain string
 * that appears exactly once; the new file is parsed before it replaces the
 * old one; the site is then requested and the old file is put back if it
 * does not answer. Two-factor app secrets are encrypted with a key made from
 * these values, so they are re-encrypted in the same step.
 */
class Salts {

	const NAMES = [ 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT' ];

	const MAX_SECRETS = 5000;

	/**
	 * Path of wp-config.php.
	 *
	 * @return string
	 */
	public static function config_path() {
		return file_exists( ABSPATH . 'wp-config.php' ) ? ABSPATH . 'wp-config.php' : dirname( ABSPATH ) . '/wp-config.php';
	}

	/**
	 * Put new values in place of the eight keys. Pure.
	 *
	 * @param string $contents wp-config.php as it is.
	 * @param array  $values   name => new value (no quote or backslash).
	 * @return string|null The new file, or null when a key is missing, defined twice or not a plain string.
	 */
	public static function replace( $contents, array $values ) {
		foreach ( self::NAMES as $name ) {
			if ( ! isset( $values[ $name ] ) || preg_match( '/[\'\\\\]/', $values[ $name ] ) ) {
				return null;
			}
			$pattern  = '/define\s*\(\s*([\'"])' . $name . '\1\s*,\s*(?:\'(?:[^\'\\\\]|\\\\.)*\'|"(?:[^"\\\\]|\\\\.)*")\s*\)\s*;/';
			$count    = 0;
			$contents = preg_replace_callback(
				$pattern,
				function () use ( $name, $values ) {
					return "define( '" . $name . "', '" . $values[ $name ] . "' );";
				},
				$contents,
				-1,
				$count
			);
			if ( 1 !== $count || null === $contents ) {
				return null;
			}
		}
		return $contents;
	}

	/**
	 * Why the keys cannot be rotated here ('' when they can).
	 *
	 * @return string
	 */
	public static function problem() {
		$path = self::config_path();
		if ( ! is_readable( $path ) || ! wp_is_writable( $path ) ) {
			return __( 'wp-config.php cannot be changed by WordPress on this server.', 'nhrrob-secure' );
		}
		if ( has_filter( 'salt' ) ) {
			return __( 'Another plugin manages the secret keys on this site.', 'nhrrob-secure' );
		}
		$blank = array_fill_keys( self::NAMES, 'x' );
		if ( null === self::replace( (string) file_get_contents( $path ), $blank ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file read.
			return __( 'The eight keys are not all written as plain text in wp-config.php (they may come from the server environment), so they have to be changed where they are set.', 'nhrrob-secure' );
		}
		return '';
	}

	/**
	 * Replace the file's contents in one step.
	 *
	 * @param string $path     File.
	 * @param string $contents New contents.
	 * @return bool
	 */
	private static function put( $path, $contents ) {
		// phpcs:disable WordPress.WP.AlternativeFunctions -- wp-config.php must be swapped in one step with its permissions kept; WP_Filesystem writes in place.
		$mode = (int) fileperms( $path ) & 0777;
		// A .php name: if this request dies here, what is left behind runs as PHP instead of being served as text.
		$temp = dirname( $path ) . '/wp-config-' . wp_generate_password( 12, false ) . '.php';
		if ( false !== @file_put_contents( $temp, $contents, LOCK_EX ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			chmod( $temp, $mode );
			if ( rename( $temp, $path ) ) {
				$done = true;
			} else {
				unlink( $temp );
				$done = false;
			}
		} else {
			// The folder is not writable but the file is: write in place.
			$done = false !== file_put_contents( $path, $contents, LOCK_EX );
		}
		// phpcs:enable
		if ( $done && function_exists( 'opcache_invalidate' ) ) {
			opcache_invalidate( $path, true );
		}
		return $done;
	}

	/**
	 * Whether the site answers a request to its own home page.
	 *
	 * @return bool
	 */
	private static function answers() {
		$response = wp_remote_get(
			add_query_arg( 'nhrrob_secure_check', time(), home_url( '/' ) ),
			[
				'timeout'     => 10,
				'redirection' => 0,
				/** This filter is documented in wp-includes/class-wp-http-streams.php */
				'sslverify'   => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core filter for requests a site makes to itself.
			]
		);
		return ! is_wp_error( $response ) && wp_remote_retrieve_response_code( $response ) < 500;
	}

	/**
	 * Rotate the keys.
	 *
	 * @return array|\WP_Error { verified: bool } — verified is false when the site cannot request itself, so only the parse check vouches for the new file.
	 */
	public static function rotate() {
		global $wpdb;
		$problem = self::problem();
		if ( '' !== $problem ) {
			return new \WP_Error( 'nhrrob_secure_keys', $problem, [ 'status' => 409 ] );
		}

		$path   = self::config_path();
		$old    = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file read.
		$values = [];
		foreach ( self::NAMES as $name ) {
			$values[ $name ] = wp_generate_password( 64, true, true );
		}
		$new = self::replace( $old, $values );
		try {
			$valid = null !== $new && is_array( token_get_all( $new, TOKEN_PARSE ) );
		} catch ( \ParseError $e ) {
			$valid = false;
		}
		if ( ! $valid ) {
			return new \WP_Error( 'nhrrob_secure_keys', __( 'The new wp-config.php would not be valid, so nothing was changed.', 'nhrrob-secure' ), [ 'status' => 500 ] );
		}

		// Two-factor app secrets, re-encrypted for the key the new values give. Worked out before anything is written.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one pass over this plugin's own user meta.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT user_id, meta_value FROM {$wpdb->usermeta} WHERE meta_key = %s LIMIT %d", TwoFactor::META_SECRET, self::MAX_SECRETS + 1 ) );
		if ( count( $rows ) > self::MAX_SECRETS ) {
			return new \WP_Error( 'nhrrob_secure_keys', __( 'Too many accounts use two-factor to change the keys in one step here. Use WP-CLI on the server instead.', 'nhrrob-secure' ), [ 'status' => 409 ] );
		}
		$material = $values['AUTH_KEY'] . $values['AUTH_SALT'];
		$secrets  = [];
		foreach ( $rows as $row ) {
			$plain = TwoFactor::decrypt( $row->meta_value );
			if ( '' !== $plain && 0 === strpos( (string) $row->meta_value, 'v1:' ) ) {
				$secrets[] = [ (int) $row->user_id, TwoFactor::encrypt( $plain, $material ) ];
			}
		}

		$could_check = self::answers();
		if ( ! self::put( $path, $new ) ) {
			return new \WP_Error( 'nhrrob_secure_keys', __( 'wp-config.php could not be written, so nothing was changed.', 'nhrrob-secure' ), [ 'status' => 500 ] );
		}
		if ( $could_check && ! self::answers() ) {
			self::put( $path, $old );
			return new \WP_Error( 'nhrrob_secure_keys', __( 'The site did not answer with the new keys, so the old wp-config.php was put back.', 'nhrrob-secure' ), [ 'status' => 500 ] );
		}

		foreach ( $secrets as $secret ) {
			update_user_meta( $secret[0], TwoFactor::META_SECRET, $secret[1] );
		}
		// A two-factor setup that was half done starts over; browsers that were trusted or known before are asked again.
		delete_metadata( 'user', 0, TwoFactor::META_PENDING, '', true );
		delete_metadata( 'user', 0, TwoFactor::META_TRUSTED, '', true );
		delete_metadata( 'user', 0, Access::META_KNOWN, '', true );

		Activity::record( 'setting', 'keys', '', Activity::WARNING );
		return [ 'verified' => $could_check ];
	}
}
