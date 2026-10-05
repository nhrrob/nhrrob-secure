<?php
/**
 * Collects and exposes the plugin's feature modules.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Interfaces\ModuleInterface;

/**
 * Core registers its own modules, then opens the list to add-ons through the
 * `nhrrob_secure_modules` filter. REST routes and the app's navigation are
 * both driven from this one collection.
 */
class ModuleRegistry {

	/**
	 * Registered modules, keyed by id.
	 *
	 * @var ModuleInterface[]
	 */
	private $modules = [];

	/**
	 * Whether boot() has run.
	 *
	 * @var bool
	 */
	private $booted = false;

	/**
	 * Build the module list once, letting add-ons extend it.
	 *
	 * @param ModuleInterface[] $core_modules Modules shipped by the plugin.
	 * @return void
	 */
	public function boot( array $core_modules ) {
		if ( $this->booted ) {
			return;
		}

		/**
		 * Filter the registered modules. The single extension point for add-ons.
		 *
		 * @param ModuleInterface[] $core_modules Modules shipped by the plugin.
		 */
		$modules = apply_filters( 'nhrrob_secure_modules', $core_modules );

		foreach ( (array) $modules as $module ) {
			if ( $module instanceof ModuleInterface ) {
				$this->modules[ $module->id() ] = $module;
			}
		}
		$this->booted = true;
	}

	/**
	 * Modules the current user may use.
	 *
	 * @return ModuleInterface[]
	 */
	public function get_modules() {
		return array_filter(
			$this->modules,
			function ( ModuleInterface $module ) {
				return current_user_can( $module->capability() );
			}
		);
	}

	/**
	 * Register REST routes for every accessible module.
	 *
	 * @return void
	 */
	public function register_routes() {
		foreach ( $this->get_modules() as $module ) {
			$module->register_routes();
		}
	}
}
