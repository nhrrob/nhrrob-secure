<?php
/**
 * Moved login address.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Services;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Core\Settings;

/**
 * Serves the sign-in form at an address the owner chose and answers
 * "not found" on wp-login.php and, for visitors who are not signed in, on
 * wp-admin.
 *
 * Off by default. Safe mode switches it off without touching the setting, so
 * a locked-out owner can always get back to wp-login.php.
 */
class LoginUrl {

	/**
	 * The chosen slug.
	 *
	 * @var string
	 */
	private $slug = '';

	/**
	 * Whether this request is for the moved login address.
	 *
	 * @var bool
	 */
	private $is_login = false;

	/**
	 * Whether this request went to wp-login.php directly.
	 *
	 * @var bool
	 */
	private $is_direct = false;

	/**
	 * Whether the feature is active for this request.
	 *
	 * @return bool
	 */
	public static function active() {
		return Settings::get( 'login_url_enabled' ) && '' !== (string) Settings::get( 'login_slug' ) && ! Settings::safe_mode();
	}

	/**
	 * The full moved address ('' when the feature is off).
	 *
	 * @param string $slug Optional slug to build the address for.
	 * @return string
	 */
	public static function url( $slug = '' ) {
		$slug = '' !== $slug ? $slug : (string) Settings::get( 'login_slug' );
		return '' === $slug ? '' : user_trailingslashit( home_url( '/' . $slug ) );
	}

	/**
	 * Register the hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		if ( ! self::active() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}
		$this->slug = (string) Settings::get( 'login_slug' );
		$this->inspect_request();

		add_filter( 'site_url', [ $this, 'rewrite' ], 10, 3 );
		add_filter( 'network_site_url', [ $this, 'rewrite' ], 10, 3 );
		add_filter( 'wp_redirect', [ $this, 'rewrite_redirect' ] );
		// Core redirects /login, /admin and /dashboard to the sign-in page, which would give the address away.
		remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );

		add_action( 'wp_loaded', [ $this, 'serve' ] );
		add_action( 'init', [ $this, 'guard_admin' ] );
	}

	/**
	 * Work out what this request is asking for.
	 *
	 * @return void
	 */
	private function inspect_request() {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- compared against a fixed slug only, never output or stored.
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? rawurldecode( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		$home = (string) wp_parse_url( home_url(), PHP_URL_PATH );
		if ( '' !== $home && 0 === strpos( $path, $home ) ) {
			$path = substr( $path, strlen( $home ) );
		}
		$path = trim( $path, '/' );

		$script = isset( $_SERVER['SCRIPT_NAME'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) : '';

		$this->is_login  = $path === $this->slug;
		$this->is_direct = ! $this->is_login && ( false !== stripos( $path, 'wp-login.php' ) || 'wp-login.php' === basename( $script ) );
	}

	/**
	 * Point generated wp-login.php URLs at the moved address.
	 *
	 * @param string      $url    Generated URL.
	 * @param string      $path   Path that was requested.
	 * @param string|null $scheme URL scheme.
	 * @return string
	 */
	public function rewrite( $url, $path = '', $scheme = null ) {
		if ( false === strpos( $url, 'wp-login.php' ) ) {
			return $url;
		}
		$query = strpos( $url, '?' );
		$new   = self::url( $this->slug );
		if ( $scheme ) {
			$new = set_url_scheme( $new, $scheme );
		}
		return false === $query ? $new : $new . substr( $url, $query );
	}

	/**
	 * Same for redirects that name wp-login.php.
	 *
	 * @param string $location Redirect target.
	 * @return string
	 */
	public function rewrite_redirect( $location ) {
		// Only this site's own wp-login.php. Another site's address that merely contains
		// "wp-login.php" (in its path or in a query value) is left as it is.
		$host = wp_parse_url( $location, PHP_URL_HOST );
		$path = (string) wp_parse_url( $location, PHP_URL_PATH );
		if ( ( $host && strtolower( $host ) !== strtolower( (string) wp_parse_url( site_url(), PHP_URL_HOST ) ) ) || 'wp-login.php' !== basename( $path ) ) {
			return $location;
		}
		return $this->rewrite( $location );
	}

	/**
	 * Show the sign-in form at the moved address, and a 404 on wp-login.php.
	 *
	 * @return void
	 */
	public function serve() {
		global $pagenow;

		if ( $this->is_direct ) {
			$this->not_found();
		}
		if ( ! $this->is_login ) {
			return;
		}

		// wp-login.php expects these in the global scope.
		global $error, $interim_login, $action, $user_login;
		// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- the login screen and plugins hooked into it branch on this.
		$pagenow = 'wp-login.php';

		nocache_headers();
		// Page-cache plugins read this constant; a cached sign-in form would break the cookie test.
		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			define( 'DONOTCACHEPAGE', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- the constant caching plugins agree on.
		}
		require_once ABSPATH . 'wp-login.php';
		exit;
	}

	/**
	 * Keep visitors who are not signed in out of wp-admin, without the usual
	 * redirect that would reveal the moved address.
	 *
	 * @return void
	 */
	public function guard_admin() {
		global $pagenow;
		if ( ! is_admin() || is_user_logged_in() || wp_doing_ajax() || wp_doing_cron() ) {
			return;
		}
		if ( in_array( $pagenow, [ 'admin-post.php', 'admin-ajax.php' ], true ) ) {
			return;
		}
		wp_die( esc_html__( 'Page not found.', 'nhrrob-secure' ), esc_html__( 'Not found', 'nhrrob-secure' ), [ 'response' => 404 ] );
	}

	/**
	 * Answer with the theme's own 404 page.
	 *
	 * @return void
	 */
	private function not_found() {
		global $pagenow;

		// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- makes the template loader treat this as a front-end request.
		$pagenow                = 'index.php';
		$_SERVER['REQUEST_URI'] = user_trailingslashit( '/' . wp_generate_password( 16, false ) );

		if ( ! defined( 'WP_USE_THEMES' ) ) {
			define( 'WP_USE_THEMES', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- core constant the template loader requires.
		}

		wp();
		status_header( 404 );
		nocache_headers();
		require_once ABSPATH . WPINC . '/template-loader.php';
		exit;
	}

	/**
	 * Check from the server that the moved address shows the sign-in form.
	 *
	 * @param string $slug Slug to test.
	 * @return string 'ok', 'failed' (the address answered without the form) or 'unknown' (the site could not reach itself).
	 */
	public static function test( $slug ) {
		$response = wp_remote_get(
			self::url( $slug ),
			[
				'timeout'     => 8,
				'redirection' => 2,
				/** This filter is documented in wp-includes/class-wp-http-streams.php */
				'sslverify'   => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core filter for requests a site makes to itself.
			]
		);
		if ( is_wp_error( $response ) ) {
			return 'unknown';
		}
		return false !== strpos( wp_remote_retrieve_body( $response ), 'id="loginform"' ) ? 'ok' : 'failed';
	}
}
