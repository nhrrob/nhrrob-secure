<?php
/**
 * Contract every feature module implements.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Interfaces;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * A module is one section of the app (Dashboard, Login, Firewall, …).
 *
 * The ModuleRegistry collects modules through the `nhrrob_secure_modules`
 * filter, which is the single extension point an add-on hooks into — core is
 * never edited to add a section.
 */
interface ModuleInterface {

	/**
	 * Stable machine id, e.g. 'firewall'. Used for routing and nav keys.
	 *
	 * @return string
	 */
	public function id();

	/**
	 * Human-readable nav label.
	 *
	 * @return string
	 */
	public function label();

	/**
	 * Capability required to see and use this module.
	 *
	 * @return string
	 */
	public function capability();

	/**
	 * Register this module's REST routes under nhrrob-secure/v1.
	 *
	 * @return void
	 */
	public function register_routes();
}
