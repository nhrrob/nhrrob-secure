<?php
/**
 * Plugin Name: NHR Secure – Security, Firewall, 2FA, Login Protection & Activity Log
 * Plugin URI: http://wordpress.org/plugins/nhrrob-secure/
 * Description: WordPress security that stays out of the way: login protection, two-factor, firewall, hardening, a scanner and an activity log.
 * Author: Nazmul Hasan Robin
 * Author URI: https://profiles.wordpress.org/nhrrob/
 * Version: 2.0.0
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Text Domain: nhrrob-secure
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package NHRRob\Secure
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

require_once __DIR__ . '/vendor/autoload.php';

/**
 * The main plugin class
 */
final class NHRRob_Secure {

	/**
	 * Plugin version
	 *
	 * @var string
	 */
	const version = '2.0.0'; // phpcs:ignore Generic.NamingConventions.UpperCaseConstantName.ClassConstantNotUpperCase -- nhrrob plugin standard.

	/**
	 * Version of the plugin's stored data (options only; it has no tables).
	 * Bump when a stored shape changes; maybe_upgrade() runs once per bump.
	 *
	 * @var string
	 */
	const DB_VERSION = '2.0.0';

	/**
	 * Class constructor
	 */
	private function __construct() {
		$this->define_constants();
		add_action( 'plugins_loaded', [ $this, 'init_plugin' ] );
		register_activation_hook( NHRROB_SECURE_FILE, [ $this, 'activate' ] );
		register_deactivation_hook( NHRROB_SECURE_FILE, [ $this, 'deactivate' ] );
	}

	/**
	 * Initialize a singleton instance
	 *
	 * @return self
	 */
	public static function init(): self {
		static $instance = false;
		if ( ! $instance ) {
			$instance = new self();
		}
		return $instance;
	}

	/**
	 * Define the required plugin constants
	 *
	 * @return void
	 */
	private function define_constants(): void {
		define( 'NHRROB_SECURE_VERSION', self::version );
		define( 'NHRROB_SECURE_FILE', __FILE__ );
		define( 'NHRROB_SECURE_PATH', __DIR__ );
		define( 'NHRROB_SECURE_PLUGIN_DIR', plugin_dir_path( NHRROB_SECURE_FILE ) );
		define( 'NHRROB_SECURE_URL', plugins_url( '', NHRROB_SECURE_FILE ) );
		define( 'NHRROB_SECURE_ASSETS', NHRROB_SECURE_URL . '/assets' );
	}

	/**
	 * Initialize the plugin
	 *
	 * @return void
	 */
	public function init_plugin(): void {
		$this->maybe_upgrade();
		if ( is_admin() || wp_doing_cron() ) {
			$this->ensure_crons();
		}

		( new \NHRRob\Secure\Core\Bootstrap() )->init();

		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			\WP_CLI::add_command( 'nhrrob-secure', '\NHRRob\Secure\Cli\Commands' );
		}
	}

	/**
	 * Activate the plugin
	 *
	 * @return void
	 */
	public function activate(): void {
		// On a network activation this runs for the main site only; every other
		// site sets itself up on its first admin or cron request.
		$this->maybe_upgrade( true );
		$this->ensure_crons();
	}

	/**
	 * Deactivate the plugin
	 *
	 * @param bool $network_wide True when deactivated for the whole network.
	 * @return void
	 */
	public function deactivate( $network_wide = false ): void {
		// Rules this plugin wrote to .htaccess must not outlive it.
		\NHRRob\Secure\Services\FileProtection::apply( false );

		$clear = function () {
			wp_clear_scheduled_hook( \NHRRob\Secure\Services\Vulnerabilities::CRON );
			wp_clear_scheduled_hook( \NHRRob\Secure\Services\Schedule::CRON );
			wp_clear_scheduled_hook( \NHRRob\Secure\Services\Summary::CRON );
		};
		if ( ! $network_wide || ! is_multisite() ) {
			$clear();
			return;
		}
		foreach ( get_sites(
			[
				'fields' => 'ids',
				'number' => 0,
			]
		) as $site_id ) {
			switch_to_blog( $site_id );
			$clear();
			restore_current_blog();
		}
	}

	/**
	 * Schedule this site's daily vulnerability check if it is missing, and keep
	 * the scheduled scan in step with its setting.
	 *
	 * @return void
	 */
	private function ensure_crons(): void {
		if ( ! wp_next_scheduled( \NHRRob\Secure\Services\Vulnerabilities::CRON ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', \NHRRob\Secure\Services\Vulnerabilities::CRON );
		}
		\NHRRob\Secure\Services\Schedule::sync();
		\NHRRob\Secure\Services\Summary::sync();
	}

	/**
	 * Migrate stored data once per DB_VERSION.
	 *
	 * An install coming from 1.x is migrated on its very first request, so a
	 * moved login address and two-factor keep working without a gap. Later
	 * version bumps wait for an admin, cron or WP-CLI request.
	 *
	 * @param bool $force Run regardless of the request type.
	 * @return void
	 */
	private function maybe_upgrade( $force = false ): void {
		if ( \NHRRob\Secure\Core\Settings::get( 'db_version' ) === self::DB_VERSION ) {
			return;
		}
		$from_legacy = ! \NHRRob\Secure\Core\Settings::exists() && \NHRRob\Secure\Core\Upgrade::is_legacy();
		if ( ! $force && ! $from_legacy && ! is_admin() && ! wp_doing_cron() && ! ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}
		\NHRRob\Secure\Core\Upgrade::run( self::DB_VERSION );
	}
}

/**
 * Initializes the main plugin
 *
 * @return NHRRob_Secure
 */
function nhrrob_secure(): NHRRob_Secure {
	return NHRRob_Secure::init();
}

// Call the plugin.
nhrrob_secure();
