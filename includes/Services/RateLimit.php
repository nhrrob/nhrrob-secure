<?php
/**
 * Rate limiting.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Services;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Core\Activity;
use NHRRob\Secure\Core\Ip;
use NHRRob\Secure\Core\Settings;

/**
 * Limits how many requests one address may make per minute to the places
 * that get hammered: the sign-in page, XML-RPC, the REST API, search and the
 * comment form. Only visitors who are not signed in are counted.
 *
 * The counters live in the persistent object cache and nowhere else. Counting
 * in an option would cost a database write for every request, which is the
 * load this is meant to take away; a site without an object cache therefore
 * cannot switch it on.
 */
class RateLimit {

	const GROUP = 'nhrrob_secure_rate';

	/**
	 * Register the hook.
	 *
	 * @return void
	 */
	public function hooks() {
		if ( ! Settings::get( 'rate_limit' ) || Settings::safe_mode() || ! wp_using_ext_object_cache() || ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() ) {
			return;
		}
		add_action( 'init', [ $this, 'check' ], 0 );
	}

	/**
	 * Which limited place a request is for ('' when it is not counted). Pure.
	 *
	 * @param string $script  Name of the PHP file that was requested, e.g. wp-login.php.
	 * @param string $path    Request path.
	 * @param array  $query   Query variables.
	 * @param string $rest    REST prefix, e.g. wp-json.
	 * @param bool   $xml_rpc Whether this is an XML-RPC request.
	 * @return string login | xmlrpc | comment | rest | search | ''
	 */
	public static function bucket( $script, $path, array $query, $rest, $xml_rpc ) {
		if ( $xml_rpc ) {
			return 'xmlrpc';
		}
		if ( 'wp-login.php' === $script ) {
			return 'login';
		}
		if ( 'wp-comments-post.php' === $script ) {
			return 'comment';
		}
		if ( isset( $query['rest_route'] ) || false !== strpos( $path . '/', '/' . $rest . '/' ) ) {
			return 'rest';
		}
		return isset( $query['s'] ) ? 'search' : '';
	}

	/**
	 * Count this request and refuse it when the address is over the limit.
	 *
	 * @return void
	 */
	public function check() {
		global $pagenow;
		if ( is_user_logged_in() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- only compared with fixed strings.
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- only checks which public query variables are present.
		$bucket = self::bucket( (string) $pagenow, (string) strtok( $uri, '?' ), $_GET, rest_get_url_prefix(), defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST );
		if ( '' === $bucket ) {
			return;
		}
		$ip = Ip::client();
		if ( 'allow' === Ip::rule_for( $ip ) || LoginGuard::address_is_shared() ) {
			return;
		}

		$limit = (int) Settings::get( 'rate_limit_max' );
		$now   = time();
		$key   = md5( LoginGuard::key( $ip ) ) . ':' . (int) floor( $now / MINUTE_IN_SECONDS );
		wp_cache_add( $key, 0, self::GROUP, 2 * MINUTE_IN_SECONDS );
		$count = (int) wp_cache_incr( $key, 1, self::GROUP );
		if ( $count <= $limit ) {
			return;
		}

		// One log row for the first refused request of the minute; the rest cost nothing.
		if ( $count === $limit + 1 ) {
			Activity::record(
				'firewall',
				'rate_limit',
				$bucket,
				Activity::WARNING,
				[
					'user'     => 0,
					'coalesce' => DAY_IN_SECONDS,
				]
			);
		}
		status_header( 429 );
		header( 'Retry-After: ' . ( MINUTE_IN_SECONDS - $now % MINUTE_IN_SECONDS ) );
		nocache_headers();
		// Plain English on purpose, like every other refusal: this runs for visitors in any language.
		wp_die( 'Too many requests from your connection. Wait a minute and try again.', 'Too many requests', [ 'response' => 429 ] );
	}
}
