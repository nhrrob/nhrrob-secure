<?php
/**
 * The plugin's single settings object.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Reads, validates and writes `nhrrob_secure_settings`.
 *
 * Every setting lives in this one small autoloaded option (it also holds the
 * data version), so a request costs no extra query. Only known keys are ever
 * written, each through its own validation.
 */
class Settings {

	const OPTION = 'nhrrob_secure_settings';

	/**
	 * Request cache of the merged settings.
	 *
	 * @var array|null
	 */
	private static $cache = null;

	/**
	 * Every setting with its default. Nothing that can lock the owner out is
	 * on by default.
	 *
	 * @return array
	 */
	public static function defaults() {
		return [
			'db_version'            => '',
			'safe_mode'             => false,
			// Login.
			'limit_login'           => true,
			'login_attempts'        => 5,
			'lockout_minutes'       => 20,
			'lockout_progressive'   => true,
			'lockout_email'         => false,
			'generic_login_errors'  => true,
			'login_url_enabled'     => false,
			'login_slug'            => '',
			'turnstile_enabled'     => false,
			'captcha_provider'      => 'turnstile',
			'turnstile_site_key'    => '',
			'turnstile_secret'      => '',
			'twofa_enabled'         => false,
			'twofa_methods'         => [ 'app', 'email' ],
			'twofa_roles'           => [],
			'twofa_grace_days'      => 7,
			'twofa_trust_days'      => 0,
			'password_expiry_days'  => 0,
			'password_force'        => [],
			// Users.
			'idle_timeout'          => 0,
			// Firewall.
			'ip_rules'              => [],
			'request_filter'        => 'off',
			'request_filter_since'  => 0,
			'filter_forms'          => false,
			'probe_lockout'         => false,
			'filter_allowed'        => [],
			'blocked_uas'           => [],
			'country_enabled'       => false,
			'country_mode'          => 'block',
			'country_list'          => [],
			'country_scope'         => 'login',
			// Hardening.
			'disable_xmlrpc'        => false,
			'disable_file_editor'   => false,
			'hide_usernames'        => false,
			'disable_app_passwords' => false,
			'hide_wp_version'       => false,
			'strong_passwords'      => false,
			'breached_passwords'    => false,
			'security_headers'      => false,
			'rest_signed_in_only'   => false,
			'rest_public'           => [ 'oembed/', 'contact-form-7/', 'wc/store/', 'wp/v2/block-renderer' ],
			'protect_files'         => false,
			// Plugin.
			'ip_source'             => 'direct',
			'trusted_proxies'       => [],
			'alert_email'           => '',
			'alert_new_admin'       => true,
			'alert_vulnerability'   => true,
			'alert_lockouts'        => false,
			'alert_scan'            => true,
			'weekly_summary'        => false,
			'scan_schedule'         => 'weekly',
			'retention_days'        => 30,
			'delete_on_uninstall'   => true,
			'upgrade_notice'        => '',
		];
	}

	/**
	 * All settings, merged over the defaults.
	 *
	 * @return array
	 */
	public static function all() {
		if ( null === self::$cache ) {
			$stored      = get_option( self::OPTION, [] );
			$defaults    = self::defaults();
			self::$cache = array_merge( $defaults, is_array( $stored ) ? array_intersect_key( $stored, $defaults ) : [] );
		}
		return self::$cache;
	}

	/**
	 * One setting.
	 *
	 * @param string $key Setting key.
	 * @return mixed
	 */
	public static function get( $key ) {
		$all = self::all();
		return isset( $all[ $key ] ) ? $all[ $key ] : null;
	}

	/**
	 * Whether the stored option exists yet (false on a fresh install).
	 *
	 * @return bool
	 */
	public static function exists() {
		return false !== get_option( self::OPTION, false );
	}

	/**
	 * Settings as the admin app sees them: the Turnstile secret is never sent
	 * back to the browser.
	 *
	 * @return array
	 */
	public static function for_app() {
		$all                         = self::all();
		$all['turnstile_secret_set'] = '' !== $all['turnstile_secret'];
		$all['turnstile_secret']     = '';
		unset( $all['db_version'] );
		return $all;
	}

	/**
	 * Merge validated values into the stored settings.
	 *
	 * @param array $incoming Raw key/value pairs. Unknown keys are ignored.
	 * @return array|\WP_Error The new settings, or an error that names the field.
	 */
	public static function update( array $incoming ) {
		$current = self::all();
		$next    = $current;

		foreach ( $incoming as $key => $value ) {
			if ( ! array_key_exists( $key, $current ) || 'db_version' === $key ) {
				continue;
			}
			$clean = self::sanitize( $key, $value, $current );
			if ( is_wp_error( $clean ) ) {
				return $clean;
			}
			$next[ $key ] = $clean;
		}

		// A moved login address needs a usable slug and pretty permalinks.
		if ( $next['login_url_enabled'] ) {
			$problem = self::slug_problem( $next['login_slug'] );
			if ( '' !== $problem ) {
				return new \WP_Error( 'nhrrob_secure_login_slug', $problem, [ 'status' => 400 ] );
			}
		}
		if ( $next['turnstile_enabled'] && ( '' === $next['turnstile_site_key'] || '' === $next['turnstile_secret'] ) ) {
			return new \WP_Error( 'nhrrob_secure_turnstile', __( 'Add both keys before turning the bot check on.', 'nhrrob-secure' ), [ 'status' => 400 ] );
		}
		if ( 'off' !== $next['request_filter'] && 'off' === $current['request_filter'] ) {
			$next['request_filter_since'] = time();
		}

		self::write( $next );
		return $next;
	}

	/**
	 * Store the settings and refresh the request cache.
	 *
	 * @param array $settings Full settings array.
	 * @return void
	 */
	public static function write( array $settings ) {
		update_option( self::OPTION, array_intersect_key( $settings, self::defaults() ), true );
		self::$cache = null;
	}

	/**
	 * Set one value without validation. For internal state only (data version,
	 * safe mode, notices) — never for user input.
	 *
	 * @param string $key   Setting key.
	 * @param mixed  $value Value.
	 * @return void
	 */
	public static function set_raw( $key, $value ) {
		$all         = self::all();
		$all[ $key ] = $value;
		self::write( $all );
	}

	/**
	 * Validate one value.
	 *
	 * @param string $key     Setting key.
	 * @param mixed  $value   Raw value.
	 * @param array  $current Current settings.
	 * @return mixed|\WP_Error
	 */
	private static function sanitize( $key, $value, array $current ) {
		$enums = [
			'request_filter'   => [ 'off', 'log', 'block' ],
			'country_mode'     => [ 'block', 'allow' ],
			'ip_source'        => [ 'direct', 'cloudflare', 'proxy' ],
			'scan_schedule'    => [ 'off', 'daily', 'weekly' ],
			'captcha_provider' => [ 'turnstile', 'recaptcha', 'hcaptcha' ],
			'country_scope'    => [ 'login', 'site' ],
		];
		$ints  = [
			'login_attempts'       => [ 1, 20 ],
			'lockout_minutes'      => [ 1, 1440 ],
			'twofa_grace_days'     => [ 0, 30 ],
			'idle_timeout'         => [ 0, 1440 ],
			'retention_days'       => [ 1, 365 ],
			'twofa_trust_days'     => [ 0, 90 ],
			'password_expiry_days' => [ 0, 365 ],
		];

		if ( isset( $enums[ $key ] ) ) {
			return in_array( $value, $enums[ $key ], true ) ? $value : $current[ $key ];
		}
		if ( isset( $ints[ $key ] ) ) {
			return max( $ints[ $key ][0], min( $ints[ $key ][1], (int) $value ) );
		}

		switch ( $key ) {
			case 'login_slug':
				return sanitize_title_with_dashes( trim( (string) $value, " \t\n\r\0\x0B/" ), '', 'save' );

			case 'turnstile_site_key':
				return sanitize_text_field( (string) $value );

			case 'turnstile_secret':
				$value = sanitize_text_field( (string) $value );
				// An empty value from the app means "unchanged": the secret is never sent to the browser.
				return '' === $value ? $current[ $key ] : $value;

			case 'alert_email':
				$value = sanitize_email( (string) $value );
				return is_email( $value ) ? $value : '';

			case 'twofa_methods':
				$value = array_values( array_intersect( [ 'app', 'email', 'passkey' ], (array) $value ) );
				return $value ? $value : [ 'app' ];

			case 'twofa_roles':
				return array_values( array_intersect( array_keys( wp_roles()->roles ), array_map( 'sanitize_key', (array) $value ) ) );

			case 'country_list':
				$out = [];
				foreach ( (array) $value as $code ) {
					$code = strtoupper( sanitize_text_field( (string) $code ) );
					if ( preg_match( '/^[A-Z]{2}$/', $code ) ) {
						$out[ $code ] = true;
					}
				}
				return array_slice( array_keys( $out ), 0, 250 );

			case 'blocked_uas':
				$out = [];
				foreach ( (array) $value as $ua ) {
					$ua = trim( sanitize_text_field( (string) $ua ) );
					// A very short fragment would match almost every browser.
					if ( strlen( $ua ) >= 3 && strlen( $ua ) <= 100 ) {
						$out[ strtolower( $ua ) ] = $ua;
					}
				}
				return array_slice( array_values( $out ), 0, 100 );

			case 'trusted_proxies':
				$out = [];
				foreach ( (array) $value as $range ) {
					$range = trim( sanitize_text_field( (string) $range ) );
					if ( Ip::valid_range( $range ) ) {
						$out[ $range ] = true;
					}
				}
				return array_slice( array_keys( $out ), 0, 50 );

			case 'filter_allowed':
				$out = [];
				foreach ( (array) $value as $entry ) {
					$entry = substr( sanitize_text_field( (string) $entry ), 0, 260 );
					if ( false !== strpos( $entry, '|' ) ) {
						$out[ $entry ] = true;
					}
				}
				return array_slice( array_keys( $out ), 0, 100 );

			case 'ip_rules':
				return self::sanitize_ip_rules( $value );

			case 'rest_public':
				$out = [];
				foreach ( (array) $value as $prefix ) {
					$prefix = ltrim( preg_replace( '#[^a-z0-9/_-]#i', '', (string) $prefix ), '/' );
					if ( strlen( $prefix ) >= 2 && strlen( $prefix ) <= 60 ) {
						$out[ $prefix ] = true;
					}
				}
				return array_slice( array_keys( $out ), 0, 50 );

			case 'password_force':
			case 'request_filter_since':
				return (int) $current[ $key ];

			case 'upgrade_notice':
				return '' === $value ? '' : $current[ $key ];
		}

		return (bool) rest_sanitize_boolean( $value );
	}

	/**
	 * Validate a list of address rules.
	 *
	 * @param mixed $rules Raw rules.
	 * @return array
	 */
	public static function sanitize_ip_rules( $rules ) {
		$out = [];
		foreach ( (array) $rules as $rule ) {
			if ( ! is_array( $rule ) || empty( $rule['range'] ) ) {
				continue;
			}
			$range = trim( sanitize_text_field( (string) $rule['range'] ) );
			if ( ! Ip::valid_range( $range ) ) {
				continue;
			}
			$out[ $range ] = [
				'range' => $range,
				'type'  => isset( $rule['type'] ) && 'allow' === $rule['type'] ? 'allow' : 'block',
				'note'  => isset( $rule['note'] ) ? substr( sanitize_text_field( (string) $rule['note'] ), 0, 80 ) : '',
				'added' => isset( $rule['added'] ) ? (int) $rule['added'] : time(),
			];
		}
		return array_slice( array_values( $out ), 0, 500 );
	}

	/**
	 * Why a login slug cannot be used ('' when it can).
	 *
	 * @param string $slug Candidate slug.
	 * @return string
	 */
	public static function slug_problem( $slug ) {
		if ( '' === (string) get_option( 'permalink_structure' ) ) {
			return __( 'Moving the sign-in page needs pretty permalinks. Choose any structure except "Plain" under Settings → Permalinks first.', 'nhrrob-secure' );
		}
		if ( strlen( $slug ) < 4 ) {
			return __( 'Choose a login address with at least 4 characters.', 'nhrrob-secure' );
		}
		$reserved = [ 'wp-admin', 'wp-login', 'wp-login-php', 'wp-content', 'wp-includes', 'wp-json', 'login', 'admin', 'dashboard', 'feed', 'index-php', 'xmlrpc-php' ];
		if ( in_array( $slug, $reserved, true ) ) {
			return __( 'That address is reserved by WordPress or too easy to guess. Choose another.', 'nhrrob-secure' );
		}
		if ( get_page_by_path( $slug, OBJECT, [ 'page', 'post' ] ) ) {
			return __( 'A page or post already uses that address. Choose another.', 'nhrrob-secure' );
		}
		return '';
	}

	/**
	 * Whether safe mode is on (wp-config constant or the WP-CLI switch).
	 *
	 * @return bool
	 */
	public static function safe_mode() {
		return ( defined( 'NHRROB_SECURE_SAFE_MODE' ) && NHRROB_SECURE_SAFE_MODE ) || (bool) self::get( 'safe_mode' );
	}

	/**
	 * Drop the request cache (tests, and after a direct option write).
	 *
	 * @return void
	 */
	public static function flush() {
		self::$cache = null;
	}
}
