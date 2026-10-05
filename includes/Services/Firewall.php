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
 * is only looked at when the owner asks for it, and then only with the rules
 * normal writing cannot match.
 */
class Firewall {

	const LOG_ROWS = 100;

	/**
	 * Register the hooks. Address and user-agent rules run right away; the
	 * request filter and the probe lock wait for `init` so they can leave
	 * signed-in users alone.
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
			add_action( 'init', [ $this, 'probe_gate' ], 0 );
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
	 * The request filter's rules: id => [ where it looks, pattern ].
	 *
	 * Whitespace-or-comment runs use atomic groups, so a crafted query string
	 * cannot push the pattern into heavy backtracking.
	 *
	 * @return array
	 */
	public static function patterns() {
		$gap = '(?>\s+|/\*(?>[^*]+|\*(?!/))*\*/)++';
		return [
			'traversal' => [ 'both', '~(?:\.\.[/\\\\]){2,}|\.\.[/\\\\].*(?:wp-config|etc/passwd|\.env|win\.ini)~i' ],
			'config'    => [ 'path', '#(?:^|/)\.(?:env|git|svn|hg|aws|ssh|htpasswd)(?:[./]|$)|wp-config\.(?:php[._~-]?)?(?:bak|old|save|swp|orig|txt|backup|copy|dist)\b|wp-config\.php~|(?:^|/)(?:dump|backup|database|db|site|wordpress)\.(?:sql|sql\.gz|zip|tar\.gz|tgz)$#i' ],
			'shell'     => [ 'path', '~(?:^|/)(?:alfa(?:new|cgiapi)?|wso\d*|c99|r57|b374k|indoxploit|xleet|wp-conflg|shell\d+|simple-backdoor)\.php$~i' ],
			'sqli'      => [ 'query', '~\bunion' . $gap . '(?:all' . $gap . ')?select' . $gap . '(?:null\b|\d|[\'"@(*]|[\w.`]+\s*(?:,|\(|from\b))|\binformation_schema\b|\b(?:sleep|pg_sleep)\s*\(\s*\d+\s*\)|\bbenchmark\s*\(\s*\d+\s*,|\binto\s+(?:out|dump)file\b|\bload_file\s*\(|[\'"]\s*(?:or|and)\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d~i' ],
			'xss'       => [ 'query', '~<script\b|<(?:img|svg|body|iframe)\b[^>]*\bon\w+\s*=|javascript:\s*[\w.]+\s*\(~i' ],
			'wrapper'   => [ 'query', '~(?:php://(?:input|filter)|data://text|expect://|phar://)~i' ],
			'code'      => [ 'query', '~(?<![\w.])(?:eval|assert|system|passthru|shell_exec|base64_decode)\s*\(\s*[\'"$]|<\?php~i' ],
		];
	}

	/**
	 * Readable names of the rules. Not for use before `init`: it translates.
	 *
	 * @return array id => label
	 */
	public static function labels() {
		return [
			'traversal' => __( 'Path traversal', 'nhrrob-secure' ),
			'config'    => __( 'Config or backup file probe', 'nhrrob-secure' ),
			'shell'     => __( 'Web shell probe', 'nhrrob-secure' ),
			'sqli'      => __( 'SQL in the query string', 'nhrrob-secure' ),
			'xss'       => __( 'Script in the query string', 'nhrrob-secure' ),
			'wrapper'   => __( 'PHP stream wrapper', 'nhrrob-secure' ),
			'code'      => __( 'PHP code in the request', 'nhrrob-secure' ),
		];
	}

	/**
	 * Whether a pattern matches. A pattern that fails to run (PCRE gave up on
	 * a hostile input) counts as a match: failing open would be a bypass.
	 *
	 * @param string $pattern Pattern.
	 * @param string $subject Text.
	 * @return bool
	 */
	private static function hit( $pattern, $subject ) {
		$result = preg_match( $pattern, $subject );
		return false === $result || 1 === $result;
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
		foreach ( self::patterns() as $id => $rule ) {
			if ( ( 'query' !== $rule[0] && self::hit( $rule[1], $path ) ) || ( 'path' !== $rule[0] && '' !== $query && self::hit( $rule[1], $query ) ) ) {
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
		$patterns = self::patterns();
		foreach ( [ 'traversal', 'wrapper', 'code' ] as $id ) {
			if ( self::hit( $patterns[ $id ][1], $body ) ) {
				return $id;
			}
		}
		return '';
	}

	/**
	 * The first part of the submitted form as one string, without building
	 * the whole thing for a very large POST.
	 *
	 * @param array $post Submitted data.
	 * @param int   $max  Maximum length.
	 * @return string
	 */
	public static function flatten( array $post, $max = 20000 ) {
		$out = '';
		array_walk_recursive(
			$post,
			function ( $value ) use ( &$out, $max ) {
				if ( strlen( $out ) < $max && is_scalar( $value ) ) {
					$out .= substr( (string) $value, 0, $max - strlen( $out ) ) . "\n";
				}
			}
		);
		return substr( $out, 0, $max );
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
	 * Whether the browser says this request was triggered by another site.
	 * Such requests are never counted as probes: a page elsewhere could
	 * otherwise make a visitor's browser "probe" this site and get them
	 * locked out.
	 *
	 * @return bool
	 */
	private static function is_cross_site() {
		return isset( $_SERVER['HTTP_SEC_FETCH_SITE'] ) && 'cross-site' === $_SERVER['HTTP_SEC_FETCH_SITE'];
	}

	/**
	 * Keep an address that is locked out for probing off the front of the
	 * site. Signed-in users and the sign-in form are never affected, so an
	 * owner behind the same address can still get in.
	 *
	 * @return void
	 */
	public function probe_gate() {
		global $pagenow;
		if ( is_user_logged_in() || 'wp-login.php' === $pagenow || ! LoginGuard::probe_locked( Ip::client() ) ) {
			return;
		}
		$this->deny( 'probe_block', '' );
	}

	/**
	 * Count a "not found" answer for a probe-type path from a signed-out visitor.
	 *
	 * @return void
	 */
	public function count_probe() {
		if ( ! is_404() || is_user_logged_in() || self::is_cross_site() ) {
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
			$rule = self::match_body( self::flatten( wp_unslash( $_POST ) ) );
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
		if ( $block && Settings::get( 'probe_lockout' ) && ! self::is_cross_site() ) {
			LoginGuard::register_probe();
		}
		if ( $block ) {
			$this->refuse();
		}
	}

	/**
	 * Keep a short list of what the filter matched, and count blocks per day —
	 * in one write.
	 *
	 * @param string $rule    Rule id.
	 * @param string $path    Request path.
	 * @param string $query   Request query string.
	 * @param bool   $blocked Whether the request was refused.
	 * @return void
	 */
	private static function log_hit( $rule, $path, $query, $blocked ) {
		$shown = sanitize_text_field( $path . ( '' !== $query ? '?' . $query : '' ) );
		$row   = [
			't' => time(),
			'i' => Ip::client(),
			'r' => $rule,
			'p' => sanitize_text_field( $path ),
			'u' => strlen( $shown ) > 200 ? substr( $shown, 0, 199 ) . '…' : $shown,
			'b' => $blocked ? 1 : 0,
		];
		State::mutate(
			function ( $state ) use ( $row, $blocked ) {
				$log = isset( $state['filter_log'] ) && is_array( $state['filter_log'] ) ? $state['filter_log'] : [];
				array_unshift( $log, $row );
				$state['filter_log'] = array_slice( $log, 0, self::LOG_ROWS );
				if ( $blocked ) {
					$state['blocked'] = self::bumped( isset( $state['blocked'] ) && is_array( $state['blocked'] ) ? $state['blocked'] : [] );
				}
				return $state;
			}
		);

		// One activity row per address and rule, however many different paths are tried,
		// so a flood of probes cannot push everything else out of the log.
		Activity::record(
			'firewall',
			$blocked ? 'filter_block' : 'filter_log',
			$rule,
			Activity::WARNING,
			[
				'user'     => 0,
				'detail'   => $path,
				'coalesce' => HOUR_IN_SECONDS,
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
	 * Add one to today's counter and keep a week of days.
	 *
	 * @param array $days Counter per day.
	 * @return array
	 */
	private static function bumped( array $days ) {
		$today          = gmdate( 'Y-m-d' );
		$days[ $today ] = isset( $days[ $today ] ) ? $days[ $today ] + 1 : 1;
		return array_slice( $days, -7, 7, true );
	}

	/**
	 * Requests refused in the last seven days. For flat rules (address, user
	 * agent, country, probe lock) at most one a minute per address is counted,
	 * so a flood costs reads, not writes.
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
		$fragment = self::blocked_agent( isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '', (array) Settings::get( 'blocked_uas' ) );
		if ( '' !== $fragment ) {
			$this->deny( 'ua_block', $fragment );
		}
	}

	/**
	 * Which blocked fragment a user agent contains ('' for none). Pure.
	 *
	 * @param string   $agent   User-agent text.
	 * @param string[] $blocked Blocked fragments.
	 * @return string
	 */
	public static function blocked_agent( $agent, array $blocked ) {
		foreach ( $blocked as $fragment ) {
			if ( '' !== $fragment && false !== stripos( $agent, $fragment ) ) {
				return $fragment;
			}
		}
		return '';
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
	 * Whether a country is refused by a rule. Pure.
	 *
	 * @param string   $country Two-letter code ('' when unknown).
	 * @param string   $mode    block | allow.
	 * @param string[] $codes   The listed countries.
	 * @return bool
	 */
	public static function country_refused( $country, $mode, array $codes ) {
		if ( '' === $country || ! $codes ) {
			return false; // Without a country the rule does nothing rather than guess.
		}
		$listed = in_array( $country, $codes, true );
		return 'allow' === $mode ? ! $listed : $listed;
	}

	/**
	 * Apply the country rule.
	 *
	 * @return void
	 */
	public function check_country() {
		$country = self::country();
		if ( self::country_refused( $country, (string) Settings::get( 'country_mode' ), (array) Settings::get( 'country_list' ) ) ) {
			$this->deny( 'country_block', $country );
		}
	}

	/**
	 * Refuse a request by a flat rule (address, user agent, country, probe
	 * lock). The log row and the counter are written at most once a minute per
	 * address; every other refused request from it costs no write at all.
	 *
	 * @param string $action Activity action.
	 * @param string $label  Activity label.
	 * @return void
	 */
	private function deny( $action, $label ) {
		$ip   = Ip::client();
		$now  = time();
		$seen = State::get( 'denied' );
		if ( ! isset( $seen[ $ip ] ) || $now - (int) $seen[ $ip ] >= MINUTE_IN_SECONDS ) {
			State::mutate(
				function ( $state ) use ( $ip, $now ) {
					$denied        = isset( $state['denied'] ) && is_array( $state['denied'] ) ? $state['denied'] : [];
					$denied[ $ip ] = $now;
					arsort( $denied );
					$state['denied']  = array_slice( $denied, 0, 100, true );
					$state['blocked'] = self::bumped( isset( $state['blocked'] ) && is_array( $state['blocked'] ) ? $state['blocked'] : [] );
					return $state;
				}
			);
			Activity::record(
				'firewall',
				$action,
				$label,
				Activity::WARNING,
				[
					'user'     => 0,
					'coalesce' => DAY_IN_SECONDS,
				]
			);
		}
		$this->refuse();
	}

	/**
	 * Answer 403. Plain English on purpose: this can run before WordPress has
	 * loaded translations.
	 *
	 * @return void
	 */
	private function refuse() {
		wp_die( 'Access to this site is not allowed from your connection.', 'Access denied', [ 'response' => 403 ] );
	}
}
