<?php
/**
 * Data migrations.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Moves a 1.x install to the 2.0 data layout.
 *
 * 1.x kept 22 separate options, two transients per failed sign-in and an
 * audit table. 2.0 keeps one settings option and a few capped options, and no
 * table: the settings are folded in, the newest audit rows are copied into
 * the activity log, and the table is dropped.
 *
 * What the owner had switched on stays on — a moved login address and
 * enrolled two-factor users keep working. The one exception is the old
 * "advanced firewall", which blocked ordinary visitors: it comes back in
 * log-only mode with a note explaining why.
 */
class Upgrade {

	const LEGACY_TABLE = 'nhrrob_audit_log';

	/**
	 * Option names used by 1.x, with the default 1.x applied when unset.
	 *
	 * @var array
	 */
	const LEGACY = [
		'nhrrob_secure_limit_login_attempts'     => 1,
		'nhrrob_secure_login_attempts_limit'     => 5,
		'nhrrob_secure_custom_login_page'        => 1,
		'nhrrob_secure_custom_login_url'         => '/hidden-access-52w',
		'nhrrob_secure_protect_debug_log'        => 1,
		'nhrrob_secure_protect_readme_files'     => 0,
		'nhrrob_secure_enable_proxy_ip'          => 0,
		'nhrrob_secure_enable_2fa'               => 0,
		'nhrrob_secure_2fa_enforced_roles'       => [],
		'nhrrob_secure_2fa_type'                 => 'app',
		'nhrrob_secure_dark_mode'                => 0,
		'nhrrob_secure_log_retention_days'       => 30,
		'nhrrob_secure_disable_xmlrpc'           => 0,
		'nhrrob_secure_disable_file_editor'      => 0,
		'nhrrob_secure_hide_wp_version'          => 0,
		'nhrrob_secure_disable_rest_users'       => 0,
		'nhrrob_secure_firewall_blocked_uas'     => '',
		'nhrrob_secure_idle_timeout'             => 0,
		'nhrrob_secure_enable_advanced_firewall' => 0,
		'nhrrob_secure_ip_whitelist'             => '',
		'nhrrob_secure_ip_blacklist'             => '',
		'nhrrob_secure_blocked_countries'        => [],
		'nhrrob_secure_audit_log_version'        => '',
	];

	/**
	 * Bring stored data up to a version.
	 *
	 * @param string $version Target data version.
	 * @return void
	 */
	public static function run( $version ) {
		// add_option() is atomic, so only one request gets the lock. A lock
		// older than ten minutes belongs to a run that died; take it over.
		$lock = 'nhrrob_secure_migrating';
		if ( ! add_option( $lock, time(), '', false ) ) {
			if ( time() - (int) get_option( $lock ) < 10 * MINUTE_IN_SECONDS ) {
				return;
			}
			update_option( $lock, time(), false );
		}

		if ( ! Settings::exists() && self::is_legacy() ) {
			Settings::write( self::settings_from_legacy() );
			self::migrate_audit_table();
			self::remove_legacy();
		}

		Settings::set_raw( 'db_version', $version );
		delete_option( $lock );
	}

	/**
	 * Whether a 1.x install left data behind.
	 *
	 * @return bool
	 */
	public static function is_legacy() {
		foreach ( array_keys( self::LEGACY ) as $name ) {
			if ( null !== get_option( $name, null ) ) {
				return true;
			}
		}
		return self::table_exists();
	}

	/**
	 * Build 2.0 settings from the 1.x options.
	 *
	 * @return array
	 */
	public static function settings_from_legacy() {
		$old = [];
		foreach ( self::LEGACY as $name => $default ) {
			$old[ substr( $name, strlen( 'nhrrob_secure_' ) ) ] = get_option( $name, $default );
		}

		$settings = Settings::defaults();
		$notices  = [];

		$settings['limit_login']    = (bool) $old['limit_login_attempts'];
		$settings['login_attempts'] = max( 1, min( 20, (int) $old['login_attempts_limit'] ) );

		$slug                          = sanitize_title_with_dashes( trim( (string) $old['custom_login_url'], " \t\n\r\0\x0B/" ), '', 'save' );
		$settings['login_slug']        = $slug;
		$settings['login_url_enabled'] = (bool) $old['custom_login_page'] && '' !== $slug;

		$type                         = 'email' === $old['2fa_type'] ? 'email' : 'app';
		$settings['twofa_enabled']    = (bool) $old['enable_2fa'];
		$settings['twofa_methods']    = [ $type ];
		$settings['twofa_roles']      = array_values( array_filter( array_map( 'sanitize_key', (array) $old['2fa_enforced_roles'] ) ) );
		$settings['twofa_grace_days'] = 0;

		$settings['idle_timeout']        = max( 0, min( 1440, (int) $old['idle_timeout'] ) );
		$settings['retention_days']      = max( 1, min( 365, (int) $old['log_retention_days'] ) );
		$settings['disable_xmlrpc']      = (bool) $old['disable_xmlrpc'];
		$settings['disable_file_editor'] = (bool) $old['disable_file_editor'];
		$settings['hide_wp_version']     = (bool) $old['hide_wp_version'];
		$settings['hide_usernames']      = (bool) $old['disable_rest_users'];
		$settings['protect_files']       = (bool) $old['protect_debug_log'] || (bool) $old['protect_readme_files'];

		if ( $old['enable_proxy_ip'] ) {
			$settings['ip_source'] = isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ? 'cloudflare' : 'proxy';
		}

		$uas = [];
		foreach ( preg_split( '/[\r\n]+/', (string) $old['firewall_blocked_uas'] ) as $ua ) {
			$ua = trim( sanitize_text_field( $ua ) );
			if ( strlen( $ua ) >= 3 ) {
				$uas[] = $ua;
			}
		}
		$settings['blocked_uas'] = array_slice( array_values( array_unique( $uas ) ), 0, 100 );

		$rules = [];
		foreach ( [
			'allow' => 'ip_whitelist',
			'block' => 'ip_blacklist',
		] as $rule_type => $key ) {
			foreach ( preg_split( '/[\r\n]+/', (string) $old[ $key ] ) as $range ) {
				$rules[] = [
					'range' => trim( $range ),
					'type'  => $rule_type,
				];
			}
		}
		$settings['ip_rules'] = Settings::sanitize_ip_rules( $rules );

		if ( $old['enable_advanced_firewall'] ) {
			$settings['request_filter']       = 'log';
			$settings['request_filter_since'] = time();
			$notices[]                        = 'filter';
		}

		$countries = [];
		foreach ( (array) $old['blocked_countries'] as $code ) {
			$code = strtoupper( sanitize_text_field( (string) $code ) );
			if ( preg_match( '/^[A-Z]{2}$/', $code ) ) {
				$countries[] = $code;
			}
		}
		if ( $countries ) {
			$settings['country_enabled'] = true;
			$settings['country_mode']    = 'block';
			$settings['country_list']    = array_values( array_unique( $countries ) );
			$notices[]                   = 'country';
		}

		$settings['upgrade_notice'] = implode( ',', $notices );
		return $settings;
	}

	/**
	 * Whether the 1.x audit table exists.
	 *
	 * @return bool
	 */
	private static function table_exists() {
		global $wpdb;
		$table = $wpdb->prefix . self::LEGACY_TABLE;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one-time migration check.
		return $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ) === $table;
	}

	/**
	 * Copy the newest audit rows into the activity log, then drop the table.
	 *
	 * @return void
	 */
	public static function migrate_audit_table() {
		global $wpdb;
		if ( ! self::table_exists() ) {
			return;
		}
		$table = $wpdb->prefix . self::LEGACY_TABLE;

		$map = [
			'user:login'         => [ 'login', 'success' ],
			'user:logout'        => [ 'login', 'logout' ],
			'user:failed_login'  => [ 'login', 'failed' ],
			'user:registered'    => [ 'user', 'created' ],
			'user:deleted'       => [ 'user', 'deleted' ],
			'user:role_changed'  => [ 'user', 'role' ],
			'plugin:activated'   => [ 'plugin', 'activated' ],
			'plugin:deactivated' => [ 'plugin', 'deactivated' ],
			'theme:switched'     => [ 'theme', 'switched' ],
			'ip_manager:block'   => [ 'firewall', 'ip_block' ],
		];

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- one-time migration; the table name is built from $wpdb->prefix and a class constant.
		$old_rows = (array) $wpdb->get_results( "SELECT user_id, event_context, event_action, item_label, ip_address, severity, created_at FROM {$table} ORDER BY id DESC LIMIT 1000", ARRAY_A );

		$rows = [];
		foreach ( $old_rows as $old ) {
			$key = $old['event_context'] . ':' . $old['event_action'];
			if ( ! isset( $map[ $key ] ) ) {
				continue;
			}
			$time   = strtotime( get_gmt_from_date( $old['created_at'] ) . ' UTC' );
			$rows[] = [
				't' => $time ? $time : time(),
				'u' => (int) $old['user_id'],
				'k' => $map[ $key ][0],
				'a' => $map[ $key ][1],
				'l' => substr( wp_strip_all_tags( (string) $old['item_label'], true ), 0, 160 ),
				'i' => substr( sanitize_text_field( (string) $old['ip_address'] ), 0, 45 ),
				's' => max( 1, min( 3, (int) $old['severity'] ) ),
				'n' => 1,
			];
		}
		if ( $rows ) {
			Activity::save( Activity::trim( array_merge( Activity::rows(), $rows ) ) );
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- removes the table an older version of this plugin created.
		$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
	}

	/**
	 * Delete the options, transients and cron events 1.x left behind.
	 *
	 * @return void
	 */
	public static function remove_legacy() {
		global $wpdb;
		foreach ( array_keys( self::LEGACY ) as $name ) {
			delete_option( $name );
		}
		wp_clear_scheduled_hook( 'nhrrob_secure_vulnerability_scan_cron' );
		wp_clear_scheduled_hook( 'nhrrob_secure_daily_cleanup' );

		foreach ( [ 'nhrrob_secure_failed_', 'nhrrob_secure_block_', 'nhrrob_secure_geoip_', 'nhrrob_secure_vulnerability_results', 'nhrrob_2fa_' ] as $prefix ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one-time cleanup of the per-visitor transients 1.x created.
			$wpdb->query(
				$wpdb->prepare(
					"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
					$wpdb->esc_like( '_transient_' . $prefix ) . '%',
					$wpdb->esc_like( '_transient_timeout_' . $prefix ) . '%'
				)
			);
		}
	}
}
