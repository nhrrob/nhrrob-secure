<?php
/**
 * Address rules, user-agent rules, the request filter and the country rule.
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
use NHRRob\Secure\Core\State;

/**
 * Decides who may reach the site.
 *
 * The request filter is deliberately small: a handful of patterns for
 * requests no visitor makes by accident, checked against the URL and query
 * string of visitors who are not signed in. It runs inside WordPress — it is
 * not a network firewall and does not claim to be one. Form and comment text
 * is never inspected, so normal writing cannot be blocked.
 */
class Firewall {

	const LOG_ROWS = 100;

	/**
	 * Register the hooks. Address and user-agent rules run right away; the
	 * request filter waits for `init` so it can skip signed-in users.
	 *
	 * @return void
	 */
	public function hooks() {
		if ( Settings::safe_mode() || ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() ) {
			return;
		}

		$rule = Ip::rule_for( Ip::client() );
		if ( 'allow' === $rule ) {
			return;
		}
		if ( 'block' === $rule ) {
			$this->deny( 'ip_block', '' );
		}
		$this->check_user_agent();

		if ( Settings::get( 'probe_lockout' ) ) {
			if ( LoginGuard::probe_locked( Ip::client() ) ) {
				$this->deny( 'probe_block', '' );
			}
			add_action( 'template_redirect', [ $this, 'count_probe' ], 0 );
		}

		if ( 'off' !== Settings::get( 'request_filter' ) ) {
			add_action( 'init', [ $this, 'filter_request' ], 0 );
		}
		if ( Settings::get( 'country_enabled' ) ) {
			if ( 'site' === Settings::get( 'country_scope' ) ) {
				$this->check_country();
			} else {
				add_action( 'login_init', [ $this, 'check_country' ] );
			}
		}
	}

	/**
	 * The request filter's rules: id => [ label, where it looks, pattern ].
	 *
	 * @return array
	 */
	public static function rules() {
		return [
			'traversal' => [
				__( 'Path traversal', 'nhrrob-secure' ),
				'both',
				'~(?:\.\.[/\\\\]){2,}|\.\.[/\\\\].*(?:wp-config|etc/passwd|\.env|win\.ini)~i',
			],
			'config'    => [
				__( 'Config or backup file probe', 'nhrrob-secure' ),
				'path',
				'#(?:^|/)\.(?:env|git|svn|hg|aws|ssh|htpasswd)(?:[./]|$)|wp-config\.(?:php[._~-]?)?(?:bak|old|save|swp|orig|txt|backup|copy|dist)\b|wp-config\.php~|(?:^|/)(?:dump|backup|database|db|site|wordpress)\.(?:sql|sql\.gz|zip|tar\.gz|tgz)$#i',
			],
			'shell'     => [
				__( 'Web shell probe', 'nhrrob-secure' ),
				'path',
				'~(?:^|/)(?:alfa(?:new|cgiapi)?|wso\d*|c99|r57|b374k|indoxploit|xleet|wp-conflg|shell\d+|simple-backdoor)\.php$~i',
			],
			'sqli'      => [
				__( 'SQL in the query string', 'nhrrob-secure' ),
				'query',
				'~\bunion(?:\s|/\*.*?\*/)+(?:all(?:\s|/\*.*?\*/)+)?select(?:\s|/\*.*?\*/)+(?:null\b|\d|[\'"@(*]|[\w.`]+\s*(?:,|\(|from\b))|\binformation_schema\b|\b(?:sleep|pg_sleep)\s*\(\s*\d+\s*\)|\bbenchmark\s*\(\s*\d+\s*,|\binto\s+(?:out|dump)file\b|\bload_file\s*\(|[\'"]\s*(?:or|and)\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d~i',
			],
			'xss'       => [
				__( 'Script in the query string', 'nhrrob-secure' ),
				'query',
				'~<script\b|<(?:img|svg|body|iframe)\b[^>]*\bon\w+\s*=|javascript:\s*[\w.]+\s*\(~i',
			],
			'wrapper'   => [
				__( 'PHP stream wrapper', 'nhrrob-secure' ),
				'query',
				'~(?:php://(?:input|filter)|data://text|expect://|phar://)~i',
			],
			'code'      => [
				__( 'PHP code in the query string', 'nhrrob-secure' ),
				'query',
				'~(?<![\w.])(?:eval|assert|system|passthru|shell_exec|base64_decode)\s*\(\s*[\'"$]|<\?php~i',
			],
		];
	}

	/**
	 * Which rule a request matches ('' for none). Pure, so it can be tested
	 * against a corpus of normal and hostile requests.
	 *
	 * @param string $path  URL path, decoded.
	 * @param string $query Query string, decoded.
	 * @return string Rule id or ''.
	 */
	public static function match( $path, $query ) {
		foreach ( self::rules() as $id => $rule ) {
			$where = $rule[1];
			if ( ( 'query' !== $where && preg_match( $rule[2], $path ) ) || ( 'path' !== $where && '' !== $query && preg_match( $rule[2], $query ) ) ) {
				return $id;
			}
		}
		return '';
	}

	/**
	 * Which rule submitted form data matches ('' for none). Only the rule
	 * types that do not match normal writing are used here: a comment may
	 * well contain "select … from" or a script tag in a code sample.
	 *
	 * @param string $body Submitted data as one string.
	 * @return string Rule id or ''.
	 */
	public static function match_body( $body ) {
		$rules = self::rules();
		foreach ( [ 'traversal', 'wrapper', 'code' ] as $id ) {
			if ( preg_match( $rules[ $id ][2], $body ) ) {
				return $id;
			}
		}
		return '';
	}

	/**
	 * Whether a path looks like a hunt for a file rather than a broken link.
	 *
	 * @param string $path Request path.
	 * @return bool
	 */
	public static function is_probe_path( $path ) {
		return (bool) preg_match( '~\.(?:php\d?|phtml|phar|asp|aspx|jsp|cgi|env|ini|sql|bak|old|orig|save|swp|log|ya?ml|zip|rar|tar|gz|tgz|7z)$|(?:^|/)\.(?:git|svn|aws|ssh)(?:/|$)~i', $path );
	}

	/**
	 * Count a "not found" answer for a probe-type path from a signed-out visitor.
	 *
	 * @return void
	 */
	public function count_probe() {
		if ( ! is_404() || is_user_logged_in() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- only matched against a fixed pattern.
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		$path = rawurldecode( (string) strtok( $uri, '?' ) );
		if ( self::is_probe_path( $path ) ) {
			LoginGuard::register_probe();
		}
	}

	/**
	 * Run the request filter for a visitor who is not signed in.
	 *
	 * @return void
	 */
	public function filter_request() {
		if ( is_user_logged_in() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- the raw request is what has to be inspected; it is only matched and logged escaped.
		$uri   = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		$parts = explode( '?', $uri, 2 );
		$path  = rawurldecode( $parts[0] );
		// Decoded twice so double-encoded payloads are seen as the server would see them.
		$query = isset( $parts[1] ) ? urldecode( urldecode( $parts[1] ) ) : '';

		$rule = self::match( $path, $query );
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- a filter has to look at what a signed-out visitor submits before any handler does; nothing is stored or acted on except the match.
		if ( '' === $rule && Settings::get( 'filter_forms' ) && ! empty( $_POST ) ) {
			$body = substr( (string) wp_json_encode( wp_unslash( $_POST ), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ), 0, 20000 );
			$rule = self::match_body( $body );
			if ( '' !== $rule ) {
				$query = __( '(form data)', 'nhrrob-secure' );
			}
		}
		// phpcs:enable
		if ( '' === $rule || in_array( $rule . '|' . $path, (array) Settings::get( 'filter_allowed' ), true ) ) {
			return;
		}

		$block = 'block' === Settings::get( 'request_filter' );
		self::log_hit( $rule, $path, $query, $block );
		if ( $block && Settings::get( 'probe_lockout' ) ) {
			LoginGuard::register_probe();
		}
		if ( $block ) {
			$this->deny( '', '', false );
		}
	}

	/**
	 * Keep a short list of what the filter matched, and count blocks per day.
	 *
	 * @param string $rule    Rule id.
	 * @param string $path    Request path.
	 * @param string $query   Request query string.
	 * @param bool   $blocked Whether the request was refused.
	 * @return void
	 */
	private static function log_hit( $rule, $path, $query, $blocked ) {
		$rules = self::rules();
		$log   = self::log();
		$shown = sanitize_text_field( $path . ( '' !== $query ? '?' . $query : '' ) );

		array_unshift(
			$log,
			[
				't' => time(),
				'i' => Ip::client(),
				'r' => $rule,
				'p' => sanitize_text_field( $path ),
				'u' => strlen( $shown ) > 200 ? substr( $shown, 0, 199 ) . '…' : $shown,
				'b' => $blocked ? 1 : 0,
			]
		);
		State::set( 'filter_log', array_slice( $log, 0, self::LOG_ROWS ) );
		if ( $blocked ) {
			self::bump();
		}

		Activity::record(
			'firewall',
			$blocked ? 'filter_block' : 'filter_log',
			$path,
			Activity::WARNING,
			[
				'user'     => 0,
				'detail'   => $rules[ $rule ][0],
				'coalesce' => 10 * MINUTE_IN_SECONDS,
			]
		);
	}

	/**
	 * Recent request-filter matches, newest first.
	 *
	 * @return array
	 */
	public static function log() {
		return State::get( 'filter_log' );
	}

	/**
	 * Add one to today's refused-requests counter (part of the small
	 * state option, so a refused request costs one small write) and keep a week of days.
	 *
	 * @return void
	 */
	private static function bump() {
		$days           = State::get( 'blocked' );
		$today          = gmdate( 'Y-m-d' );
		$days[ $today ] = isset( $days[ $today ] ) ? $days[ $today ] + 1 : 1;
		State::set( 'blocked', array_slice( $days, -7, 7, true ) );
	}

	/**
	 * Requests refused in the last seven days (all rule types).
	 *
	 * @return int
	 */
	public static function blocked_week() {
		return (int) array_sum( State::get( 'blocked' ) );
	}

	/**
	 * Refuse requests whose user agent contains a blocked fragment.
	 *
	 * @return void
	 */
	private function check_user_agent() {
		$blocked = (array) Settings::get( 'blocked_uas' );
		if ( ! $blocked ) {
			return;
		}
		$agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		foreach ( $blocked as $fragment ) {
			if ( '' !== $fragment && false !== stripos( $agent, $fragment ) ) {
				$this->deny( 'ua_block', $fragment );
			}
		}
	}

	/**
	 * The visitor's country as reported by Cloudflare ('' when unknown).
	 * Only trusted when the request really arrived through Cloudflare.
	 *
	 * @return string Two-letter code.
	 */
	public static function country() {
		if ( ! Ip::via_cloudflare() || empty( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ) {
			return '';
		}
		$code = strtoupper( sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ) );
		return preg_match( '/^[A-Z]{2}$/', $code ) && 'XX' !== $code ? $code : '';
	}

	/**
	 * Apply the country rule to the sign-in page only. Without a country from
	 * Cloudflare the rule does nothing rather than guess.
	 *
	 * @return void
	 */
	public function check_country() {
		$country = self::country();
		$list    = (array) Settings::get( 'country_list' );
		if ( '' === $country || ! $list ) {
			return;
		}
		$listed = in_array( $country, $list, true );
		$allow  = 'allow' === Settings::get( 'country_mode' );
		if ( $allow !== $listed ) {
			$this->deny( 'country_block', $country );
		}
	}

	/**
	 * Refuse the request with a 403.
	 *
	 * @param string $action Activity action to record ('' to skip).
	 * @param string $label  Activity label.
	 * @param bool   $count  Whether to add to the blocked-per-day counter.
	 * @return void
	 */
	private function deny( $action, $label, $count = true ) {
		if ( '' !== $action ) {
			Activity::record(
				'firewall',
				$action,
				$label,
				Activity::WARNING,
				[
					'user'     => 0,
					'coalesce' => HOUR_IN_SECONDS,
				]
			);
		}
		if ( $count ) {
			self::bump();
		}
		wp_die(
			esc_html__( 'Access to this site is not allowed from your connection.', 'nhrrob-secure' ),
			esc_html__( 'Access denied', 'nhrrob-secure' ),
			[ 'response' => 403 ]
		);
	}
}
