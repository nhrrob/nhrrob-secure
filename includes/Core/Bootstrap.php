<?php
/**
 * Wires the plugin together.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Admin\AppPage;
use NHRRob\Secure\Rest\ScannerController;
use NHRRob\Secure\Rest\SecurityController;
use NHRRob\Secure\Rest\SettingsController;
use NHRRob\Secure\Rest\TwoFactorController;
use NHRRob\Secure\Services\Checks;
use NHRRob\Secure\Services\EventLogger;
use NHRRob\Secure\Services\Firewall;
use NHRRob\Secure\Services\Hardening;
use NHRRob\Secure\Services\LoginGuard;
use NHRRob\Secure\Services\LoginUrl;
use NHRRob\Secure\Services\Monitor;
use NHRRob\Secure\Services\Schedule;
use NHRRob\Secure\Services\Sessions;
use NHRRob\Secure\Services\BotCheck;
use NHRRob\Secure\Services\Passwords;
use NHRRob\Secure\Services\Summary;
use NHRRob\Secure\Services\TwoFactor;
use NHRRob\Secure\Services\Vulnerabilities;

/**
 * Starts the protection services on every request, and the module registry,
 * REST routes and admin screen where they are needed.
 */
class Bootstrap {

	/**
	 * Registry of the app's sections.
	 *
	 * @var ModuleRegistry
	 */
	private $registry;

	/**
	 * Create the registry.
	 */
	public function __construct() {
		$this->registry = new ModuleRegistry();
	}

	/**
	 * Wire hooks. Called once from the main plugin's init.
	 *
	 * @return void
	 */
	public function init() {
		// Address rules first: a blocked address gets nothing else.
		( new Firewall() )->hooks();
		( new LoginUrl() )->hooks();
		( new LoginGuard() )->hooks();
		( new BotCheck() )->hooks();
		( new TwoFactor() )->hooks();
		( new Sessions() )->hooks();
		( new Hardening() )->hooks();
		( new EventLogger() )->hooks();
		( new Monitor() )->hooks();
		( new Passwords() )->hooks();

		add_action( Vulnerabilities::CRON, [ Vulnerabilities::class, 'cron' ] );
		add_action( Schedule::CRON, [ Schedule::class, 'tick' ] );
		add_action( Summary::CRON, [ Summary::class, 'send' ] );
		add_filter( 'site_status_tests', [ Checks::class, 'site_health' ] );

		add_action(
			'rest_api_init',
			function () {
				$this->registry->boot( $this->core_modules() );
				$this->registry->register_routes();
				// A user's own two-factor setup: any signed-in user, not a section of the admin app.
				( new TwoFactorController() )->register();
			}
		);

		if ( is_admin() ) {
			// Built when the menu is registered; add-ons hook `nhrrob_secure_modules` on plugins_loaded.
			add_action(
				'admin_menu',
				function () {
					$this->registry->boot( $this->core_modules() );
				},
				1
			);
			( new AppPage( $this->registry ) )->init();
			if ( is_multisite() ) {
				( new \NHRRob\Secure\Admin\NetworkPage() )->init();
			}
		}
	}

	/**
	 * The built-in sections. Routes are grouped in three controllers, each
	 * registered by the first section that uses it.
	 *
	 * @return Module[]
	 */
	private function core_modules() {
		return [
			new Module( 'dashboard', __( 'Dashboard', 'nhrrob-secure' ), SettingsController::class ),
			new Module( 'login', __( 'Login', 'nhrrob-secure' ) ),
			new Module( 'users', __( 'Users & Sessions', 'nhrrob-secure' ), SecurityController::class ),
			new Module( 'firewall', __( 'Firewall', 'nhrrob-secure' ) ),
			new Module( 'hardening', __( 'Hardening', 'nhrrob-secure' ) ),
			new Module( 'scanner', __( 'Scanner', 'nhrrob-secure' ), ScannerController::class ),
			new Module( 'activity', __( 'Activity', 'nhrrob-secure' ) ),
			new Module( 'settings', __( 'Settings', 'nhrrob-secure' ) ),
		];
	}
}
