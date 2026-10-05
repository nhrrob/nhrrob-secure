<?php
/**
 * Weekly summary email.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Services;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Core\Activity;
use NHRRob\Secure\Core\Alerts;
use NHRRob\Secure\Core\Settings;

/**
 * Once a week, one email with the score, what needs fixing and what happened.
 */
class Summary {

	const CRON = 'nhrrob_secure_summary';

	/**
	 * Make the cron event match the setting.
	 *
	 * @return void
	 */
	public static function sync() {
		$on        = (bool) Settings::get( 'weekly_summary' );
		$scheduled = (bool) wp_next_scheduled( self::CRON );
		if ( $on && ! $scheduled ) {
			wp_schedule_event( time() + DAY_IN_SECONDS, 'weekly', self::CRON );
		} elseif ( ! $on && $scheduled ) {
			wp_clear_scheduled_hook( self::CRON );
		}
	}

	/**
	 * The lines of the summary.
	 *
	 * @return string[]
	 */
	public static function lines() {
		$checks = Checks::run();
		$failed = array_filter(
			$checks,
			function ( $check ) {
				return ! $check['passed'];
			}
		);

		$since  = time() - WEEK_IN_SECONDS;
		$counts = [
			'signins'  => 0,
			'lockouts' => 0,
			'findings' => 0,
			'admins'   => 0,
		];
		foreach ( Activity::rows() as $row ) {
			if ( $row['t'] < $since ) {
				break;
			}
			$key = $row['k'] . ':' . $row['a'];
			if ( 'login' === $row['k'] && in_array( $row['a'], [ 'success', 'success_2fa', 'success_trusted', 'recovery', 'passkey' ], true ) ) {
				++$counts['signins'];
			} elseif ( 'login:lockout' === $key || 'firewall:probe_lock' === $key ) {
				++$counts['lockouts'];
			} elseif ( 'scan' === $row['k'] && in_array( $row['a'], [ 'vulnerability', 'finding' ], true ) ) {
				++$counts['findings'];
			} elseif ( 'user' === $row['k'] && 3 === (int) $row['s'] ) {
				++$counts['admins'];
			}
		}

		$lines = [
			/* translators: %d: score out of 100. */
			sprintf( __( 'Security score: %d out of 100', 'nhrrob-secure' ), Checks::score( $checks ) ),
			'',
			__( 'This week', 'nhrrob-secure' ),
			/* translators: %d: number. */
			'- ' . sprintf( __( 'Sign-ins: %d', 'nhrrob-secure' ), $counts['signins'] ),
			/* translators: %d: number. */
			'- ' . sprintf( __( 'Addresses locked out: %d', 'nhrrob-secure' ), $counts['lockouts'] ),
			/* translators: %d: number. */
			'- ' . sprintf( __( 'Requests refused: %d', 'nhrrob-secure' ), Firewall::blocked_week() ),
			/* translators: %d: number. */
			'- ' . sprintf( __( 'New scan findings: %d', 'nhrrob-secure' ), $counts['findings'] ),
			/* translators: %d: number. */
			'- ' . sprintf( __( 'Administrator account changes: %d', 'nhrrob-secure' ), $counts['admins'] ),
		];
		if ( $failed ) {
			$lines[] = '';
			$lines[] = __( 'To fix', 'nhrrob-secure' );
			foreach ( array_slice( $failed, 0, 8 ) as $check ) {
				$lines[] = '- ' . $check['label'];
			}
		}
		return $lines;
	}

	/**
	 * Send the summary.
	 *
	 * @return void
	 */
	public static function send() {
		Alerts::send( __( 'Your weekly security summary', 'nhrrob-secure' ), self::lines() );
	}
}
