<?php
/**
 * WP-CLI commands.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Cli;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Core\Settings;
use NHRRob\Secure\Services\Checks;
use NHRRob\Secure\Services\LoginGuard;
use NHRRob\Secure\Services\LoginUrl;
use NHRRob\Secure\Services\TwoFactor;

/**
 * Check on the plugin and get back in when you are locked out.
 */
class Commands {

	/**
	 * Show the score, the failed checks and what is switched on.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : json prints the same facts as one JSON object. Default is plain lines.
	 *
	 * ## EXAMPLES
	 *
	 *     wp nhrrob-secure status
	 *     wp nhrrob-secure status --format=json
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Flags.
	 * @return void
	 */
	public function status( $args = [], $assoc_args = [] ) {
		$checks = Checks::run();
		if ( isset( $assoc_args['format'] ) && 'json' === $assoc_args['format'] ) {
			\WP_CLI::line(
				(string) wp_json_encode(
					[
						'score'          => Checks::score( $checks ),
						'safe_mode'      => Settings::safe_mode(),
						'login_address'  => LoginUrl::active() ? LoginUrl::url() : 'wp-login.php',
						'request_filter' => Settings::get( 'request_filter' ),
						'locked_out'     => count( LoginGuard::locked() ),
						'failed_checks'  => array_values(
							array_filter(
								$checks,
								function ( $check ) {
									return ! $check['passed'];
								}
							)
						),
					]
				)
			);
			return;
		}
		\WP_CLI::line( sprintf( 'Score: %d / 100', Checks::score( $checks ) ) );
		\WP_CLI::line( 'Safe mode: ' . ( Settings::safe_mode() ? 'on' : 'off' ) );
		\WP_CLI::line( 'Login address: ' . ( LoginUrl::active() ? LoginUrl::url() : 'wp-login.php' ) );
		\WP_CLI::line( 'Request filter: ' . Settings::get( 'request_filter' ) );
		\WP_CLI::line( 'Locked-out addresses: ' . count( LoginGuard::locked() ) );
		foreach ( $checks as $check ) {
			if ( ! $check['passed'] ) {
				\WP_CLI::line( sprintf( '  [%s] %s', $check['severity'], $check['label'] ) );
			}
		}
	}

	/**
	 * Unlock a locked-out address.
	 *
	 * ## OPTIONS
	 *
	 * [<ip>]
	 * : The address to unlock.
	 *
	 * [--all]
	 * : Unlock every address.
	 *
	 * ## EXAMPLES
	 *
	 *     wp nhrrob-secure unlock 203.0.113.9
	 *     wp nhrrob-secure unlock --all
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Flags.
	 * @return void
	 */
	public function unlock( $args, $assoc_args ) {
		$ip = isset( $args[0] ) ? (string) $args[0] : '';
		if ( '' === $ip && empty( $assoc_args['all'] ) ) {
			\WP_CLI::error( 'Give an address, or --all.' );
		}
		\WP_CLI::success( sprintf( 'Unlocked %d address(es).', LoginGuard::unlock( $ip ) ) );
	}

	/**
	 * Turn safe mode on or off.
	 *
	 * Safe mode switches off the moved login address, the request filter,
	 * address and country rules, lockouts and the two-factor step, and leaves
	 * every setting as it is.
	 *
	 * ## OPTIONS
	 *
	 * <state>
	 * : on or off.
	 *
	 * ## EXAMPLES
	 *
	 *     wp nhrrob-secure safe-mode on
	 *
	 * @subcommand safe-mode
	 *
	 * @param array $args Positional arguments.
	 * @return void
	 */
	public function safe_mode( $args ) {
		if ( ! in_array( $args[0], [ 'on', 'off' ], true ) ) {
			\WP_CLI::error( 'Use "on" or "off".' );
		}
		Settings::set_raw( 'safe_mode', 'on' === $args[0] );
		\WP_CLI::success( 'Safe mode is ' . $args[0] . '.' );
	}

	/**
	 * Put the sign-in page back on wp-login.php.
	 *
	 * ## EXAMPLES
	 *
	 *     wp nhrrob-secure login-url reset
	 *
	 * @subcommand login-url
	 *
	 * @param array $args Positional arguments.
	 * @return void
	 */
	public function login_url( $args ) {
		if ( ! isset( $args[0] ) || 'reset' !== $args[0] ) {
			\WP_CLI::error( 'The only action is "reset".' );
		}
		Settings::set_raw( 'login_url_enabled', false );
		\WP_CLI::success( 'The sign-in page is back at ' . wp_login_url() );
	}

	/**
	 * Switch two-factor off for one user so they can sign in and set it up again.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : Username, email or id.
	 *
	 * ## EXAMPLES
	 *
	 *     wp nhrrob-secure reset-2fa robin
	 *
	 * @subcommand reset-2fa
	 *
	 * @param array $args Positional arguments.
	 * @return void
	 */
	public function reset_2fa( $args ) {
		$user = is_numeric( $args[0] ) ? get_userdata( (int) $args[0] ) : get_user_by( is_email( $args[0] ) ? 'email' : 'login', $args[0] );
		if ( ! $user ) {
			\WP_CLI::error( 'No such user.' );
		}
		TwoFactor::disable( $user );
		\WP_CLI::success( 'Two-factor is off for ' . $user->user_login . '.' );
	}
}
