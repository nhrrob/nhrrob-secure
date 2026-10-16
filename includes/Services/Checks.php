<?php
/**
 * The security score and its checks.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Services;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Core\Activity;
use NHRRob\Secure\Core\Settings;

/**
 * Looks at the site as it is — software, accounts, configuration — and
 * turns that into a score out of 100 with a list of things to fix.
 *
 * The score is about the site, not about how many of this plugin's switches
 * are on: a check only fails when something is actually exposed.
 */
class Checks {

	/**
	 * Points a failed check costs, by severity.
	 *
	 * @var int[]
	 */
	const WEIGHTS = [
		'critical' => 15,
		'high'     => 10,
		'medium'   => 6,
		'low'      => 3,
	];

	/**
	 * Severities an owner may acknowledge, that is leave on purpose. A high or
	 * critical finding always counts.
	 *
	 * @var string[]
	 */
	const ACKNOWLEDGEABLE = [ 'medium', 'low' ];

	/**
	 * Where acknowledgements are kept: id => { f: fingerprint, u: user id, t: time, n: note }.
	 */
	const ACK_PART = 'acknowledged';

	/**
	 * Run every check.
	 *
	 * @return array[] Each: id, label, detail, passed, severity, fix { section, label },
	 *                 and acknowledged { by, at, note } when the owner left a failed check on purpose.
	 */
	public static function run() {
		$checks = [];
		$add    = function ( $id, $passed, $severity, $label, $detail, $section = '', $fix = '' ) use ( &$checks ) {
			$checks[] = [
				'id'       => $id,
				'passed'   => (bool) $passed,
				'severity' => $severity,
				'label'    => $label,
				'detail'   => $detail,
				'fix'      => $section ? [
					'section' => $section,
					'label'   => $fix,
				] : null,
			];
		};

		// Software.
		$vuln  = Vulnerabilities::results();
		$count = count( $vuln['items'] );
		if ( ! $vuln['checked'] ) {
			$add( 'vulnerabilities', false, 'low', __( 'Your software has not been checked for known vulnerabilities yet.', 'nhrrob-secure' ), __( 'The first check runs within a day, or you can start it now.', 'nhrrob-secure' ), 'scanner', __( 'Check now', 'nhrrob-secure' ) );
		} else {
			$top = $count ? $vuln['items'][0] : null;
			$add(
				'vulnerabilities',
				0 === $count,
				'critical',
				$count
					/* translators: %d: number of vulnerabilities. */
					? sprintf( _n( '%d known vulnerability in your installed software.', '%d known vulnerabilities in your installed software.', $count, 'nhrrob-secure' ), $count )
					: __( 'No known vulnerabilities in your installed software.', 'nhrrob-secure' ),
				$top ? $top['name'] . ' ' . $top['version'] . ': ' . $top['title'] : '',
				'scanner',
				__( 'Review', 'nhrrob-secure' )
			);
		}

		$updates = self::pending_updates();
		$add(
			'core_update',
			! $updates['core'],
			'high',
			$updates['core'] ? __( 'A WordPress update is waiting.', 'nhrrob-secure' ) : __( 'WordPress is up to date.', 'nhrrob-secure' ),
			$updates['core'] ? __( 'WordPress updates often contain security fixes.', 'nhrrob-secure' ) : '',
			'updates',
			__( 'Go to Updates', 'nhrrob-secure' )
		);
		$waiting = $updates['plugins'] + $updates['themes'];
		$add(
			'updates',
			0 === $waiting,
			'medium',
			$waiting
				/* translators: %d: number of updates. */
				? sprintf( _n( '%d plugin or theme update is waiting.', '%d plugin or theme updates are waiting.', $waiting, 'nhrrob-secure' ), $waiting )
				: __( 'Plugins and themes are up to date.', 'nhrrob-secure' ),
			'',
			'updates',
			__( 'Go to Updates', 'nhrrob-secure' )
		);
		$closed = count( $vuln['closed'] );
		if ( $closed ) {
			$add(
				'closed_plugins',
				false,
				'high',
				/* translators: %d: number of plugins. */
				sprintf( _n( '%d installed plugin has been closed on WordPress.org.', '%d installed plugins have been closed on WordPress.org.', $closed, 'nhrrob-secure' ), $closed ),
				implode( ', ', $vuln['closed'] ) . '. ' . __( 'Closed plugins get no more updates; plan a replacement.', 'nhrrob-secure' )
			);
		}

		$stale = self::untested( self::tested_versions(), get_bloginfo( 'version' ) );
		if ( $stale ) {
			$add(
				'abandoned',
				false,
				'medium',
				/* translators: %d: number of plugins. */
				sprintf( _n( '%d plugin looks abandoned.', '%d plugins look abandoned.', count( $stale ), 'nhrrob-secure' ), count( $stale ) ),
				implode( ', ', array_slice( $stale, 0, 8 ) ) . '. ' . __( 'The latest release on WordPress.org was not tested with any of the last three WordPress versions; look for a maintained replacement.', 'nhrrob-secure' )
			);
		}

		// Accounts.
		$coverage = Sessions::admin_coverage();
		$missing  = count( $coverage['without'] );
		$add(
			'admins_2fa',
			0 === $missing,
			'high',
			$missing
				/* translators: %d: number of administrators. */
				? sprintf( _n( '%d administrator signs in with a password only.', '%d administrators sign in with a password only.', $missing, 'nhrrob-secure' ), $missing )
				: __( 'Every administrator uses two-factor.', 'nhrrob-secure' ),
			$missing ? implode( ', ', array_slice( $coverage['without'], 0, 5 ) ) : '',
			Settings::get( 'twofa_enabled' ) ? 'users' : 'login',
			Settings::get( 'twofa_enabled' ) ? __( 'Review users', 'nhrrob-secure' ) : __( 'Turn on two-factor', 'nhrrob-secure' )
		);
		$add(
			'admin_username',
			! username_exists( 'admin' ),
			'medium',
			username_exists( 'admin' ) ? __( 'An account is named "admin".', 'nhrrob-secure' ) : __( 'No account is named "admin".', 'nhrrob-secure' ),
			username_exists( 'admin' ) ? __( 'It is the first name every attack tries. Create a new administrator with another name and delete this one.', 'nhrrob-secure' ) : ''
		);

		// Two things that are only worth a line when they are wrong.
		if ( LoginGuard::address_is_shared() ) {
			$add(
				'visitor_address',
				false,
				'high',
				__( 'Secure cannot tell your visitors apart.', 'nhrrob-secure' ),
				__( 'This site is behind a proxy or load balancer, so every visitor seems to come from the same address. Lockouts are paused until you choose how visitors reach this site.', 'nhrrob-secure' ),
				'settings',
				__( 'Open Settings', 'nhrrob-secure' )
			);
		}
		if ( Settings::get( 'login_url_enabled' ) && 'hidden-access-52w' === Settings::get( 'login_slug' ) ) {
			$add(
				'login_slug_default',
				false,
				'medium',
				__( 'Your sign-in address is the one every older copy of this plugin used.', 'nhrrob-secure' ),
				__( 'It is published in the plugin\'s code, so it hides nothing. Choose an address of your own.', 'nhrrob-secure' ),
				'login',
				__( 'Change it', 'nhrrob-secure' )
			);
		}
		$add(
			'limit_login',
			Settings::get( 'limit_login' ) && ! Settings::safe_mode(),
			'high',
			Settings::get( 'limit_login' ) ? __( 'Repeated failed sign-ins are locked out.', 'nhrrob-secure' ) : __( 'Sign-in attempts are unlimited.', 'nhrrob-secure' ),
			'',
			'login',
			__( 'Limit attempts', 'nhrrob-secure' )
		);
		$open_registration = get_option( 'users_can_register' ) && ! in_array( get_option( 'default_role' ), [ 'subscriber', 'customer' ], true );
		$add(
			'registration',
			! $open_registration,
			'critical',
			$open_registration ? __( 'Anyone can register and gets more than a subscriber role.', 'nhrrob-secure' ) : __( 'New registrations do not get elevated roles.', 'nhrrob-secure' ),
			$open_registration ? __( 'Change the default role under Settings → General.', 'nhrrob-secure' ) : ''
		);

		// Configuration.
		$https = 'https' === wp_parse_url( home_url(), PHP_URL_SCHEME );
		$add(
			'https',
			$https,
			'high',
			$https ? __( 'The site is served over HTTPS.', 'nhrrob-secure' ) : __( 'The site address does not use HTTPS.', 'nhrrob-secure' ),
			$https ? '' : __( 'Passwords typed on this site can be read in transit. Site Health can switch the site to HTTPS when your server supports it.', 'nhrrob-secure' ),
			'site-health',
			__( 'Open Site Health', 'nhrrob-secure' )
		);
		$debug = defined( 'WP_DEBUG' ) && WP_DEBUG && ( ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY );
		$add(
			'debug_display',
			! $debug,
			'medium',
			$debug ? __( 'PHP errors are shown to visitors.', 'nhrrob-secure' ) : __( 'PHP errors are not shown to visitors.', 'nhrrob-secure' ),
			$debug ? __( 'Set WP_DEBUG_DISPLAY to false in wp-config.php.', 'nhrrob-secure' ) : ''
		);
		$editor = ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) || ! wp_is_file_mod_allowed( 'nhrrob_secure_check' );
		$add(
			'file_editor',
			$editor,
			'medium',
			$editor ? __( 'The theme and plugin file editor is off.', 'nhrrob-secure' ) : __( 'PHP files can be edited from wp-admin.', 'nhrrob-secure' ),
			$editor ? '' : __( 'A stolen administrator session could change code directly.', 'nhrrob-secure' ),
			'hardening',
			__( 'Turn off', 'nhrrob-secure' )
		);
		$salts = self::salts_ok();
		$add(
			'salts',
			$salts,
			'high',
			$salts ? __( 'Secret keys are set.', 'nhrrob-secure' ) : __( 'The secret keys in wp-config.php are missing or still the sample text.', 'nhrrob-secure' ),
			$salts ? '' : __( 'Generate new keys at api.wordpress.org/secret-key/1.1/salt/ and paste them into wp-config.php.', 'nhrrob-secure' )
		);
		$php = self::php_ok();
		$add(
			'php',
			$php,
			'medium',
			/* translators: %s: PHP version. */
			$php ? sprintf( __( 'PHP %s still gets security fixes.', 'nhrrob-secure' ), PHP_VERSION ) : sprintf( __( 'PHP %s no longer gets security fixes.', 'nhrrob-secure' ), PHP_VERSION ),
			$php ? '' : __( 'Ask your host to move the site to a supported PHP version.', 'nhrrob-secure' )
		);

		$open = [];
		foreach ( Permissions::items() as $item ) {
			if ( $item['open'] ) {
				$open[] = $item['path'];
			}
		}
		$add(
			'permissions',
			! $open,
			'high',
			$open ? __( 'Key files or folders can be changed by any account on the server.', 'nhrrob-secure' ) : __( 'No key file or folder is writable by other accounts on the server.', 'nhrrob-secure' ),
			implode( ', ', $open ),
			'hardening',
			__( 'Fix permissions', 'nhrrob-secure' )
		);
		global $wpdb;
		$default_prefix = 'wp_' === $wpdb->base_prefix;
		$add(
			'table_prefix',
			! $default_prefix,
			'low',
			$default_prefix ? __( 'The database tables use the default "wp_" prefix.', 'nhrrob-secure' ) : __( 'The database tables do not use the default prefix.', 'nhrrob-secure' ),
			$default_prefix ? __( 'A minor point: it only matters if another flaw already lets someone run database queries. Change it only at install time or with a tool made for it.', 'nhrrob-secure' ) : ''
		);

		// Exposure.
		$files = Scan::get( 'files' );
		$open  = [];
		$risks = [
			'debug_log'   => __( 'the debug log can be read by anyone', 'nhrrob-secure' ),
			'uploads_php' => __( 'PHP files in the uploads folder can run', 'nhrrob-secure' ),
			'listing'     => __( 'folder contents are listed', 'nhrrob-secure' ),
		];
		if ( is_array( $files ) ) {
			foreach ( $files['items'] as $item ) {
				if ( 'open' === $item['state'] && isset( $risks[ $item['id'] ] ) ) {
					$open[] = $risks[ $item['id'] ];
				}
			}
		}
		$add(
			'files',
			! $open,
			'high',
			$open
				/* translators: %s: list of items. */
				? sprintf( __( 'Files are exposed: %s.', 'nhrrob-secure' ), implode( '; ', $open ) )
				: __( 'The debug log, uploads and folder listings are not exposed.', 'nhrrob-secure' ),
			'',
			'hardening',
			__( 'Protect files', 'nhrrob-secure' )
		);
		$add(
			'xmlrpc',
			(bool) Settings::get( 'disable_xmlrpc' ),
			'low',
			Settings::get( 'disable_xmlrpc' ) ? __( 'XML-RPC is off.', 'nhrrob-secure' ) : __( 'XML-RPC is reachable.', 'nhrrob-secure' ),
			Settings::get( 'disable_xmlrpc' ) ? '' : __( 'Turn it off unless Jetpack or an old app needs it.', 'nhrrob-secure' ),
			'hardening',
			__( 'Turn off', 'nhrrob-secure' )
		);
		$add(
			'usernames',
			(bool) Settings::get( 'hide_usernames' ),
			'low',
			Settings::get( 'hide_usernames' ) ? __( 'Usernames are hidden from visitors.', 'nhrrob-secure' ) : __( 'Visitors can list your usernames.', 'nhrrob-secure' ),
			'',
			'hardening',
			__( 'Hide them', 'nhrrob-secure' )
		);

		/**
		 * Filter the security checks. Add-ons append their own.
		 *
		 * @param array[] $checks Checks, each with id, passed, severity, label, detail, fix.
		 */
		$checks = self::with_acknowledged( (array) apply_filters( 'nhrrob_secure_checks', $checks ), self::acknowledgements() );
		foreach ( $checks as $index => $check ) {
			if ( isset( $check['acknowledged'] ) ) {
				$user                                   = get_userdata( $check['acknowledged']['user'] );
				$checks[ $index ]['acknowledged']['by'] = $user ? $user->display_name : '';
				unset( $checks[ $index ]['acknowledged']['user'] );
			}
		}
		return $checks;
	}

	/**
	 * What a finding says, so an acknowledgement lapses when it changes
	 * (another plugin turns abandoned, another update waits). Pure.
	 *
	 * @param array $check Check.
	 * @return string
	 */
	public static function fingerprint( array $check ) {
		return md5( $check['label'] . "\n" . ( isset( $check['detail'] ) ? $check['detail'] : '' ) );
	}

	/**
	 * Mark the failed checks the owner acknowledged, while they still say the same. Pure.
	 *
	 * @param array[] $checks Checks.
	 * @param array   $acks   id => { f, u, t, n }.
	 * @return array[] Checks; acknowledged ones get acknowledged { user, at, note }.
	 */
	public static function with_acknowledged( array $checks, array $acks ) {
		foreach ( $checks as $index => $check ) {
			$ack = isset( $check['id'], $acks[ $check['id'] ] ) ? $acks[ $check['id'] ] : null;
			if ( ! $ack || ! empty( $check['passed'] ) || ! in_array( $check['severity'], self::ACKNOWLEDGEABLE, true ) || self::fingerprint( $check ) !== $ack['f'] ) {
				continue;
			}
			$checks[ $index ]['acknowledged'] = [
				'user' => (int) $ack['u'],
				'at'   => (int) $ack['t'],
				'note' => (string) $ack['n'],
			];
		}
		return $checks;
	}

	/**
	 * Stored acknowledgements.
	 *
	 * @return array id => { f, u, t, n }
	 */
	private static function acknowledgements() {
		$acks = Scan::get( self::ACK_PART );
		return is_array( $acks ) ? $acks : [];
	}

	/**
	 * Acknowledge a failed check, or take the acknowledgement back.
	 *
	 * @param string      $id   Check id.
	 * @param string|null $note Note; null takes the acknowledgement back.
	 * @return array|\WP_Error The check as it now stands.
	 */
	public static function acknowledge( $id, $note ) {
		$found = null;
		foreach ( self::run() as $check ) {
			if ( $check['id'] === $id ) {
				$found = $check;
			}
		}
		if ( ! $found ) {
			return new \WP_Error( 'nhrrob_secure_check', __( 'There is no such check.', 'nhrrob-secure' ), [ 'status' => 404 ] );
		}
		$acks = self::acknowledgements();
		if ( null === $note ) {
			unset( $acks[ $id ] );
			Activity::record( 'setting', 'unacknowledged', $found['label'] );
		} else {
			if ( $found['passed'] || ! in_array( $found['severity'], self::ACKNOWLEDGEABLE, true ) ) {
				return new \WP_Error( 'nhrrob_secure_check', __( 'Only a failed check of medium or low severity can be acknowledged.', 'nhrrob-secure' ), [ 'status' => 400 ] );
			}
			$acks[ $id ] = [
				'f' => self::fingerprint( $found ),
				'u' => get_current_user_id(),
				't' => time(),
				'n' => substr( $note, 0, 200 ),
			];
			Activity::record( 'setting', 'acknowledged', $found['label'], Activity::INFO, [ 'detail' => $note ] );
		}
		Scan::set( self::ACK_PART, $acks ? $acks : null );
		foreach ( self::run() as $check ) {
			if ( $check['id'] === $id ) {
				return $check;
			}
		}
		return $found;
	}

	/**
	 * Checks that need attention: failed and not acknowledged.
	 *
	 * @param array[] $checks Checks.
	 * @return array[]
	 */
	public static function open( array $checks ) {
		return array_values(
			array_filter(
				$checks,
				function ( $check ) {
					return ! $check['passed'] && empty( $check['acknowledged'] );
				}
			)
		);
	}

	/**
	 * Score out of 100: the weighted share of checks that passed. A check
	 * the owner acknowledged counts neither way.
	 *
	 * @param array[] $checks Checks.
	 * @return int
	 */
	public static function score( array $checks ) {
		$total  = 0;
		$passed = 0;
		foreach ( $checks as $check ) {
			if ( ! $check['passed'] && ! empty( $check['acknowledged'] ) ) {
				continue;
			}
			$weight = isset( self::WEIGHTS[ $check['severity'] ] ) ? self::WEIGHTS[ $check['severity'] ] : 3;
			$total += $weight;
			if ( $check['passed'] ) {
				$passed += $weight;
			}
		}
		return $total ? (int) round( 100 * $passed / $total ) : 100;
	}

	/**
	 * Updates WordPress already knows about.
	 *
	 * @return array { core: bool, plugins: int, themes: int }
	 */
	private static function pending_updates() {
		$core    = get_site_transient( 'update_core' );
		$plugins = get_site_transient( 'update_plugins' );
		$themes  = get_site_transient( 'update_themes' );
		return [
			'core'    => isset( $core->updates[0]->response ) && 'upgrade' === $core->updates[0]->response,
			'plugins' => isset( $plugins->response ) ? count( (array) $plugins->response ) : 0,
			'themes'  => isset( $themes->response ) ? count( (array) $themes->response ) : 0,
		];
	}

	/**
	 * The WordPress version each WordPress.org plugin says it was tested with,
	 * from the update data WordPress already holds. No request is made.
	 *
	 * @return array plugin name => "tested up to" version
	 */
	private static function tested_versions() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$updates = get_site_transient( 'update_plugins' );
		$names   = get_plugins();
		$out     = [];
		foreach ( [ 'response', 'no_update' ] as $list ) {
			foreach ( isset( $updates->$list ) ? (array) $updates->$list : [] as $file => $item ) {
				if ( isset( $names[ $file ] ) && is_object( $item ) && ! empty( $item->tested ) ) {
					$out[ $names[ $file ]['Name'] ] = (string) $item->tested;
				}
			}
		}
		return $out;
	}

	/**
	 * Plugins not tested with any of the last three WordPress releases. Pure.
	 *
	 * WordPress numbers its releases 6.8, 6.9, 7.0, 7.1: one step is a tenth.
	 *
	 * @param array  $tested     Plugin name => "tested up to" version.
	 * @param string $wp_version This site's WordPress version.
	 * @return string[] Plugin names.
	 */
	public static function untested( array $tested, $wp_version ) {
		$branch  = function ( $version ) {
			return preg_match( '/^(\d+)\.(\d+)/', (string) $version, $m ) ? (int) $m[1] * 10 + (int) $m[2] : 0;
		};
		$current = $branch( $wp_version );
		$out     = [];
		foreach ( $tested as $name => $version ) {
			$value = $branch( $version );
			if ( $current && $value && $value < $current - 2 ) {
				$out[] = (string) $name;
			}
		}
		return $out;
	}

	/**
	 * Whether the wp-config.php secret keys are real.
	 *
	 * @return bool
	 */
	private static function salts_ok() {
		foreach ( [ 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY' ] as $name ) {
			if ( ! defined( $name ) || strlen( (string) constant( $name ) ) < 32 || 'put your unique phrase here' === constant( $name ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Whether this PHP version still gets security fixes, as WordPress.org
	 * reports it (the same data core's dashboard notice uses).
	 *
	 * @return bool
	 */
	private static function php_ok() {
		if ( ! function_exists( 'wp_check_php_version' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}
		$info = wp_check_php_version();
		return ! is_array( $info ) || ! isset( $info['is_secure'] ) || $info['is_secure'];
	}

	/**
	 * Register one Site Health test that reports the score.
	 *
	 * @param array $tests Site Health tests.
	 * @return array
	 */
	public static function site_health( $tests ) {
		$tests['direct']['nhrrob_secure'] = [
			'label' => __( 'Secure', 'nhrrob-secure' ),
			'test'  => [ __CLASS__, 'site_health_test' ],
		];
		return $tests;
	}

	/**
	 * The Site Health test.
	 *
	 * @return array
	 */
	public static function site_health_test() {
		$checks = self::run();
		$failed = self::open( $checks );
		$score  = self::score( $checks );
		$items  = '';
		$urgent = false;
		foreach ( $failed as $check ) {
			$items .= '<li>' . esc_html( $check['label'] ) . '</li>';
			$urgent = $urgent || in_array( $check['severity'], [ 'critical', 'high' ], true );
		}
		$source = '<p>' . esc_html__( 'These checks come from the Secure plugin (Tools → Secure), not from WordPress itself.', 'nhrrob-secure' ) . '</p>';

		return [
			'label'       => $failed
				/* translators: %d: score out of 100. */
				? sprintf( __( 'Secure plugin: your security score is %d out of 100', 'nhrrob-secure' ), $score )
				: __( 'Secure plugin: all security checks passed', 'nhrrob-secure' ),
			// Critical only when the score is low because of a serious finding.
			'status'      => ! $failed ? 'good' : ( $score < 80 && $urgent ? 'critical' : 'recommended' ),
			'badge'       => [
				'label' => __( 'Secure', 'nhrrob-secure' ),
				'color' => 'blue',
			],
			'description' => $source . ( $failed ? '<ul>' . $items . '</ul>' : '<p>' . esc_html__( 'Nothing needs your attention.', 'nhrrob-secure' ) . '</p>' ),
			'actions'     => '<a href="' . esc_url( admin_url( 'tools.php?page=nhrrob-secure' ) ) . '">' . esc_html__( 'Open Secure', 'nhrrob-secure' ) . '</a>',
			'test'        => 'nhrrob_secure',
		];
	}
}
