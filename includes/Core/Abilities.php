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

use NHRRob\Secure\Rest\SettingsController;
use NHRRob\Secure\Services\Checks;
use NHRRob\Secure\Services\FileProtection;
use NHRRob\Secure\Services\Firewall;
use NHRRob\Secure\Services\LoginGuard;
use NHRRob\Secure\Services\Sessions;
use NHRRob\Secure\Services\Vulnerabilities;

/**
 * What AI agents and MCP clients may ask the plugin (WordPress 6.9+).
 *
 * Pinned by tests/AbilitiesTest.php. An agent can see how the site scores
 * and what is vulnerable, and can switch on the setting behind a few failed
 * checks (FIXES): only settings that cannot lock anyone out or turn a visitor
 * away, never off, and through the same code as the settings screen. Nothing
 * here unlocks an address, runs a scan or takes a free path. What an ability returns is
 * sent to the agent's AI provider, so nothing here returns the login address,
 * an address rule, a username, a visitor's address or the activity log.
 *
 * The two hooks below only fire when something asks for the abilities
 * registry, so a visitor request pays nothing for this class.
 */
class Abilities {

	const CATEGORY = 'nhrrob-secure';

	/**
	 * Failed checks apply-fix can fix: check id => the settings it switches on.
	 * Each is in the recommended setup (Services\Setup) or is file protection,
	 * which is checked with a request and taken out again if the site breaks.
	 */
	const FIXES = [
		'xmlrpc'      => [ 'disable_xmlrpc' => true ],
		'usernames'   => [ 'hide_usernames' => true ],
		'file_editor' => [ 'disable_file_editor' => true ],
		'limit_login' => [ 'limit_login' => true ],
		'files'       => [ 'protect_files' => true ],
	];

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
					'description' => __( 'Security score, checks and known vulnerabilities of this site, and fixes for some failed checks.', 'nhrrob-secure' ),
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

		$write                = $meta;
		$write['annotations'] = [
			'readonly'    => false,
			'destructive' => false,
			'idempotent'  => true,
		];

		return [
			'nhrrob-secure/get-security-status'  => [
				'label'               => __( 'Get security status', 'nhrrob-secure' ),
				'description'         => __( 'Returns the security score (0-100), every security check with whether it passed, its severity and a plain explanation (a failed check the owner acknowledged, that is left on purpose, carries "acknowledged" and is not counted in the score), whether safe mode is on, and counts: lockouts, addresses locked out now, administrators with and without two-factor, known vulnerabilities and requests blocked this week. Start here.', 'nhrrob-secure' ),
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
			'nhrrob-secure/apply-fix'            => [
				'label'               => __( 'Apply a security fix', 'nhrrob-secure' ),
				'description'         => __( 'Fixes one failed check from get-security-status by switching on the Secure setting behind it, exactly as the settings screen does: xmlrpc (turn off XML-RPC; refused while Jetpack is active), usernames (hide usernames from visitors), file_editor (turn off the file editor), limit_login (lock out repeated failed sign-ins), files (write the file protection rules to .htaccess; Apache and LiteSpeed only, and on a network only for a super admin). Returns whether the check passes now.', 'nhrrob-secure' ),
				'category'            => self::CATEGORY,
				'execute_callback'    => [ $this, 'apply_fix' ],
				'permission_callback' => [ $this, 'can_manage' ],
				'input_schema'        => [
					'type'                 => 'object',
					'properties'           => [
						'check' => [
							'type' => 'string',
							'enum' => array_keys( self::FIXES ),
						],
					],
					'required'             => [ 'check' ],
					'additionalProperties' => false,
				],
				'output_schema'       => [ 'type' => 'object' ],
				'meta'                => $write,
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
					// `fix` points at a screen of the admin app; `by` names a person.
					unset( $check['fix'], $check['acknowledged']['by'] );
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

	/**
	 * Switch on the setting behind one failed check.
	 *
	 * @param array $input { check: string }.
	 * @return array|\WP_Error { check, changed, passed }
	 */
	public function apply_fix( $input ) {
		$id = isset( $input['check'] ) ? (string) $input['check'] : '';
		if ( ! isset( self::FIXES[ $id ] ) ) {
			return new \WP_Error( 'nhrrob_secure_fix', __( 'That check cannot be fixed this way.', 'nhrrob-secure' ), [ 'status' => 400 ] );
		}
		if ( 'xmlrpc' === $id && class_exists( 'Jetpack' ) ) {
			return new \WP_Error( 'nhrrob_secure_fix', __( 'Jetpack is active and needs XML-RPC, so it was left on.', 'nhrrob-secure' ), [ 'status' => 409 ] );
		}
		if ( 'files' === $id ) {
			if ( ! $this->can_manage_files() ) {
				return new \WP_Error( 'nhrrob_secure_fix', __( 'On a network only a super admin can protect files.', 'nhrrob-secure' ), [ 'status' => 403 ] );
			}
			if ( ! FileProtection::can_write() ) {
				return new \WP_Error( 'nhrrob_secure_fix', __( 'Secure cannot write the rules on this server: it is not Apache or LiteSpeed (or that is not known yet; open Hardening once in wp-admin), or .htaccess is not writable. The Hardening screen shows the lines to add by hand.', 'nhrrob-secure' ), [ 'status' => 409 ] );
			}
		}

		$patch   = array_diff_assoc( self::FIXES[ $id ], array_intersect_key( Settings::all(), self::FIXES[ $id ] ) );
		$changed = (bool) $patch;
		if ( $changed ) {
			$result = ( new SettingsController() )->apply( $patch );
			if ( is_wp_error( $result ) ) {
				return $result;
			}
		} elseif ( 'files' === $id ) {
			// The setting is on but the rules may not be there (saved where they could not be written).
			if ( ! FileProtection::apply( true ) ) {
				return new \WP_Error( 'nhrrob_secure_fix', __( 'The .htaccess file could not be changed safely, so file protection was left as it was.', 'nhrrob-secure' ), [ 'status' => 500 ] );
			}
			FileProtection::check();
			$changed = true;
		}

		$passed = false;
		foreach ( Checks::run() as $check ) {
			if ( $check['id'] === $id ) {
				$passed = (bool) $check['passed'];
			}
		}
		return [
			'check'   => $id,
			'changed' => $changed,
			'passed'  => $passed,
		];
	}
}
