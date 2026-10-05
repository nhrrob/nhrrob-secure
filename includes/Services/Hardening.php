<?php
/**
 * Hardening switches.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Services;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Core\Settings;

/**
 * Switches off WordPress features an owner does not use, adds response
 * headers and enforces password rules. Every switch is off by default.
 */
class Hardening {

	/**
	 * Register the hooks for the switches that are on.
	 *
	 * @return void
	 */
	public function hooks() {
		if ( Settings::get( 'disable_xmlrpc' ) ) {
			$this->disable_xmlrpc();
		}
		if ( Settings::get( 'disable_file_editor' ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- core constant.
		}
		if ( Settings::get( 'hide_usernames' ) ) {
			add_filter( 'rest_endpoints', [ $this, 'hide_rest_users' ] );
			add_action( 'template_redirect', [ $this, 'block_author_scan' ], 0 );
			add_filter( 'redirect_canonical', [ $this, 'no_author_redirect' ] );
			add_filter( 'wp_sitemaps_add_provider', [ $this, 'no_users_sitemap' ], 10, 2 );
		}
		if ( Settings::get( 'disable_app_passwords' ) ) {
			add_filter( 'wp_is_application_passwords_available', '__return_false' );
		}
		if ( Settings::get( 'hide_wp_version' ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
			add_filter( 'style_loader_src', [ $this, 'mask_version' ], 9999 );
			add_filter( 'script_loader_src', [ $this, 'mask_version' ], 9999 );
		}
		if ( Settings::get( 'security_headers' ) ) {
			add_filter( 'wp_headers', [ $this, 'headers' ] );
			add_action( 'admin_init', [ $this, 'send_headers' ] );
			add_action( 'login_init', [ $this, 'send_headers' ] );
		}
		if ( Settings::get( 'rest_signed_in_only' ) ) {
			add_filter( 'rest_authentication_errors', [ $this, 'rest_signed_in_only' ], 99 );
		}
		if ( Settings::get( 'strong_passwords' ) || Settings::get( 'breached_passwords' ) ) {
			add_action( 'user_profile_update_errors', [ $this, 'check_profile_password' ], 10, 3 );
			add_action( 'validate_password_reset', [ $this, 'check_reset_password' ], 10, 2 );
		}
	}

	/**
	 * Close XML-RPC completely, pingbacks included.
	 *
	 * @return void
	 */
	private function disable_xmlrpc() {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			status_header( 403 );
			exit;
		}
		add_filter( 'xmlrpc_enabled', '__return_false' );
		add_filter( 'xmlrpc_methods', '__return_empty_array' );
		add_filter( 'pings_open', '__return_false' );
		remove_action( 'wp_head', 'rsd_link' );
		add_filter(
			'wp_headers',
			function ( $headers ) {
				unset( $headers['X-Pingback'] );
				return $headers;
			}
		);
	}

	/**
	 * Refuse REST requests from visitors who are not signed in, except for the
	 * route prefixes the owner left public (contact forms, checkout, embeds).
	 *
	 * @param mixed $result Result of earlier authentication checks.
	 * @return mixed
	 */
	public function rest_signed_in_only( $result ) {
		if ( is_wp_error( $result ) || is_user_logged_in() ) {
			return $result;
		}
		$route = isset( $GLOBALS['wp']->query_vars['rest_route'] ) ? ltrim( (string) $GLOBALS['wp']->query_vars['rest_route'], '/' ) : '';
		if ( self::rest_route_is_public( $route, (array) Settings::get( 'rest_public' ) ) ) {
			return $result;
		}
		return new \WP_Error( 'nhrrob_secure_rest', __( 'The REST API on this site is for signed-in users.', 'nhrrob-secure' ), [ 'status' => 401 ] );
	}

	/**
	 * Pure check behind rest_signed_in_only().
	 *
	 * @param string   $route  Requested route, without the leading slash.
	 * @param string[] $prefixes Route prefixes left public.
	 * @return bool
	 */
	public static function rest_route_is_public( $route, array $prefixes ) {
		foreach ( $prefixes as $prefix ) {
			if ( '' !== $prefix && 0 === strpos( $route, $prefix ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Remove the REST users endpoints for visitors. Signed-in users keep them:
	 * the editor asks for the current user and the list of authors, and core
	 * already limits what each role can see there.
	 *
	 * @param array $endpoints Registered endpoints.
	 * @return array
	 */
	public function hide_rest_users( $endpoints ) {
		if ( is_user_logged_in() ) {
			return $endpoints;
		}
		foreach ( array_keys( $endpoints ) as $route ) {
			if ( 0 === strpos( $route, '/wp/v2/users' ) ) {
				unset( $endpoints[ $route ] );
			}
		}
		return $endpoints;
	}

	/**
	 * Answer 404 to `/?author=1` style probes from visitors.
	 *
	 * @return void
	 */
	public function block_author_scan() {
		global $wp_query;
		if ( self::asks_for_author() && ! is_user_logged_in() ) {
			$wp_query->set_404();
			status_header( 404 );
			nocache_headers();
		}
	}

	/**
	 * Stop the redirect from `/?author=1` to `/author/name/`.
	 *
	 * @param string $redirect Redirect target.
	 * @return string|false
	 */
	public function no_author_redirect( $redirect ) {
		return self::asks_for_author() && ! is_user_logged_in() ? false : $redirect;
	}

	/**
	 * Whether the request names an author by number. WordPress reads query
	 * variables from a form post as well as from the address.
	 *
	 * @return bool
	 */
	private static function asks_for_author() {
		// phpcs:ignore WordPress.Security.NonceVerification -- only checks that a public query variable is present.
		return isset( $_GET['author'] ) || isset( $_POST['author'] );
	}

	/**
	 * Leave the users list out of the XML sitemap.
	 *
	 * @param object $provider Sitemap provider.
	 * @param string $name     Provider name.
	 * @return object|false
	 */
	public function no_users_sitemap( $provider, $name ) {
		return 'users' === $name ? false : $provider;
	}

	/**
	 * Replace the WordPress version in asset URLs with a stable hash, so
	 * browser caching still works but the version is not readable.
	 *
	 * @param string $src Asset URL.
	 * @return string
	 */
	public function mask_version( $src ) {
		$version = get_bloginfo( 'version' );
		if ( is_string( $src ) && false !== strpos( $src, 'ver=' . $version ) ) {
			$src = str_replace( 'ver=' . $version, 'ver=' . substr( md5( $version . wp_salt( 'nonce' ) ), 0, 8 ), $src );
		}
		return $src;
	}

	/**
	 * The security headers this site should send.
	 *
	 * @param array $headers Headers WordPress is about to send.
	 * @return array
	 */
	public function headers( $headers ) {
		$headers['X-Content-Type-Options'] = 'nosniff';
		$headers['X-Frame-Options']        = 'SAMEORIGIN';
		$headers['Referrer-Policy']        = 'strict-origin-when-cross-origin';
		if ( is_ssl() ) {
			$headers['Strict-Transport-Security'] = 'max-age=31536000';
		}
		return $headers;
	}

	/**
	 * Send the headers on admin and sign-in screens, which skip `wp_headers`.
	 *
	 * @return void
	 */
	public function send_headers() {
		if ( headers_sent() ) {
			return;
		}
		foreach ( $this->headers( [] ) as $name => $value ) {
			header( $name . ': ' . $value );
		}
	}

	/**
	 * Check a password set on the profile or Add User screen.
	 *
	 * @param \WP_Error $errors Errors to add to.
	 * @param bool      $update Whether this is an update.
	 * @param object    $user   User data being saved.
	 * @return void
	 */
	public function check_profile_password( $errors, $update, $user ) {
		if ( empty( $user->user_pass ) ) {
			return;
		}
		$roles = isset( $user->role ) && $user->role ? [ $user->role ] : [];
		if ( ! $roles && ! empty( $user->ID ) ) {
			$existing = get_userdata( $user->ID );
			$roles    = $existing ? (array) $existing->roles : [];
		}
		$problem = $this->password_problem( $user->user_pass, isset( $user->user_login ) ? $user->user_login : '', $roles );
		if ( '' !== $problem ) {
			$errors->add( 'nhrrob_secure_password', $problem );
		}
	}

	/**
	 * Check a password chosen through "Lost your password?".
	 *
	 * @param \WP_Error          $errors Errors to add to.
	 * @param \WP_User|\WP_Error $user   The account.
	 * @return void
	 */
	public function check_reset_password( $errors, $user ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- core validates the reset key before this hook; a password must not be altered and is only measured here, never stored.
		$password = isset( $_POST['pass1'] ) ? (string) wp_unslash( $_POST['pass1'] ) : '';
		if ( '' === $password || ! $user instanceof \WP_User ) {
			return;
		}
		$problem = $this->password_problem( $password, $user->user_login, (array) $user->roles );
		if ( '' !== $problem ) {
			$errors->add( 'nhrrob_secure_password', $problem );
		}
	}

	/**
	 * Why a password is not acceptable ('' when it is). The rules apply to
	 * roles that can change the site: administrators and editors.
	 *
	 * @param string   $password Password.
	 * @param string   $login    Username.
	 * @param string[] $roles    The account's roles.
	 * @return string
	 */
	private function password_problem( $password, $login, array $roles ) {
		$privileged = false;
		foreach ( $roles as $role ) {
			$object = get_role( $role );
			if ( $object && ( $object->has_cap( 'manage_options' ) || $object->has_cap( 'edit_others_posts' ) ) ) {
				$privileged = true;
			}
		}
		if ( ! $privileged ) {
			return '';
		}

		if ( Settings::get( 'strong_passwords' ) ) {
			$problem = self::weak_reason( $password, $login );
			if ( '' !== $problem ) {
				return $problem;
			}
		}
		if ( Settings::get( 'breached_passwords' ) && self::is_breached( $password ) ) {
			return __( 'That password has appeared in a known data breach, so attackers already have it on their lists. Choose a different one.', 'nhrrob-secure' );
		}
		return '';
	}

	/**
	 * Pure strength rule: 12+ characters, more than one kind of character,
	 * and not built from the username.
	 *
	 * @param string $password Password.
	 * @param string $login    Username.
	 * @return string Reason, or ''.
	 */
	public static function weak_reason( $password, $login ) {
		if ( strlen( $password ) < 12 ) {
			return __( 'Use a password with at least 12 characters.', 'nhrrob-secure' );
		}
		$kinds = (int) preg_match( '/[a-z]/', $password ) + (int) preg_match( '/[A-Z]/', $password ) + (int) preg_match( '/\d/', $password ) + (int) preg_match( '/[^a-zA-Z\d]/', $password );
		if ( $kinds < 2 ) {
			return __( 'Mix letters with numbers or symbols in your password.', 'nhrrob-secure' );
		}
		if ( strlen( $login ) >= 4 && false !== stripos( $password, $login ) ) {
			return __( 'Your password must not contain your username.', 'nhrrob-secure' );
		}
		return '';
	}

	/**
	 * Ask Have I Been Pwned whether a password is in a known breach.
	 *
	 * Only the first five characters of the password's SHA-1 hash leave the
	 * site (k-anonymity); the password itself never does. If the service
	 * cannot be reached the password is accepted.
	 *
	 * @param string $password Password.
	 * @return bool
	 */
	public static function is_breached( $password ) {
		$hash     = strtoupper( sha1( $password ) );
		$response = wp_remote_get(
			'https://api.pwnedpasswords.com/range/' . substr( $hash, 0, 5 ),
			[
				'timeout' => 5,
				'headers' => [ 'Add-Padding' => 'true' ],
			]
		);
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}
		$suffix = substr( $hash, 5 );
		foreach ( explode( "\n", wp_remote_retrieve_body( $response ) ) as $line ) {
			$parts = explode( ':', trim( $line ) );
			if ( isset( $parts[1] ) && $parts[0] === $suffix && (int) $parts[1] > 0 ) {
				return true;
			}
		}
		return false;
	}
}
