<?php
/**
 * Registers the plugin's abilities with the WordPress Abilities API.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Services\Checks;
use NHRRob\Secure\Services\Firewall;
use NHRRob\Secure\Services\LoginGuard;
use NHRRob\Secure\Services\Sessions;
use NHRRob\Secure\Services\Vulnerabilities;

/**
 * What AI agents and MCP clients may ask the plugin (WordPress 6.9+).
 *
 * Read-only on purpose, and pinned by tests/AbilitiesTest.php: an agent can
 * see how the site scores and what is vulnerable, and nothing here changes a
 * setting, unlocks an address or touches a file. What an ability returns is
 * sent to the agent's AI provider, so nothing here returns the login address,
 * an address rule, a username, a visitor's address or the activity log.
 *
 * The two hooks below only fire when something asks for the abilities
 * registry, so a visitor request pays nothing for this class.
 */
class Abilities {

	const CATEGORY = 'nhrrob-secure';

	/**
	 * Wire hooks. Called once from Bootstrap::init().
	 *
	 * @return void
	 */
	public function hooks() {
		add_action( 'wp_abilities_api_categories_init', [ $this, 'register_category' ] );
		add_action( 'wp_abilities_api_init', [ $this, 'register' ] );
	}

	/**
	 * Register the category both abilities belong to.
	 *
	 * @return void
	 */
	public function register_category() {
		// The hook only exists on 6.9+; the check is for Plugin Check ("Requires at least" is 6.0).
		if ( function_exists( 'wp_register_ability_category' ) ) {
			wp_register_ability_category(
				self::CATEGORY,
				[
					'label'       => __( 'Secure', 'nhrrob-secure' ),
					'description' => __( 'Security score, checks and known vulnerabilities of this site.', 'nhrrob-secure' ),
				]
			);
		}
	}

	/**
	 * Register every ability.
	 *
	 * @return void
	 */
	public function register() {
		if ( function_exists( 'wp_register_ability' ) ) {
			foreach ( $this->definitions() as $name => $args ) {
				wp_register_ability( $name, $args );
			}
		}
	}

	/**
	 * Gate: administrators of this site, as for the REST routes.
	 *
	 * @return bool
	 */
	public function can_manage() {
		return current_user_can( 'manage_options' );
	}

	/**
	 * Gate of the Scanner section: on a multisite network only a super admin,
	 * because plugin, theme and core files are shared by all sites.
	 *
	 * @return bool
	 */
	public function can_manage_files() {
		return current_user_can( 'manage_options' ) && ( ! is_multisite() || is_super_admin() );
	}

	/**
	 * Every ability: name => wp_register_ability() arguments.
	 *
	 * @return array
	 */
	public function definitions() {
		$meta = [
			'annotations'  => [
				'readonly'    => true,
				'destructive' => false,
				'idempotent'  => true,
			],
			'public'       => true,
			// WordPress 6.9 has no `public` flag; the MCP Adapter reads `mcp.public`.
			'show_in_rest' => true,
			'mcp'          => [ 'public' => true ],
		];

		return [
			'nhrrob-secure/get-security-status'  => [
				'label'               => __( 'Get security status', 'nhrrob-secure' ),
				'description'         => __( 'Returns the security score (0-100), every security check with whether it passed, its severity and a plain explanation, whether safe mode is on, and counts: lockouts, addresses locked out now, administrators with and without two-factor, known vulnerabilities and requests blocked this week. Start here.', 'nhrrob-secure' ),
				'category'            => self::CATEGORY,
				'execute_callback'    => [ $this, 'get_security_status' ],
				'permission_callback' => [ $this, 'can_manage' ],
				'output_schema'       => [ 'type' => 'object' ],
				'meta'                => $meta,
			],
			'nhrrob-secure/list-vulnerabilities' => [
				'label'               => __( 'List known vulnerabilities', 'nhrrob-secure' ),
				'description'         => __( 'Returns the result of the last vulnerability check: each installed plugin, theme or WordPress version with a known vulnerability, plugins closed on WordPress.org, when the check ran and whether it was complete. It reads the stored result and does not start a new check.', 'nhrrob-secure' ),
				'category'            => self::CATEGORY,
				'execute_callback'    => [ $this, 'list_vulnerabilities' ],
				'permission_callback' => [ $this, 'can_manage_files' ],
				'output_schema'       => [ 'type' => 'object' ],
				'meta'                => $meta,
			],
		];
	}

	/**
	 * Score, checks and counts.
	 *
	 * @return array
	 */
	public function get_security_status() {
		$checks   = Checks::run();
		$coverage = Sessions::admin_coverage();
		$vuln     = Vulnerabilities::results();

		return [
			'score'     => Checks::score( $checks ),
			'safe_mode' => Settings::safe_mode(),
			'checks'    => array_map(
				function ( $check ) {
					// `fix` points at a screen of the admin app.
					unset( $check['fix'] );
					return $check;
				},
				$checks
			),
			'stats'     => [
				'lockouts'        => LoginGuard::recent_count(),
				'locked_now'      => count( LoginGuard::locked() ),
				'admins'          => $coverage['total'],
				'admins_2fa'      => $coverage['with_2fa'],
				'vulnerabilities' => count( $vuln['items'] ),
				'software'        => $vuln['total'],
				'scan_checked'    => $vuln['checked'],
				'blocked'         => Firewall::blocked_week(),
			],
		];
	}

	/**
	 * The last vulnerability check's result.
	 *
	 * @return array
	 */
	public function list_vulnerabilities() {
		return Vulnerabilities::results();
	}
}
