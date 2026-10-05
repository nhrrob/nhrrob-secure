<?php
/**
 * Scheduled scans.
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
 * Runs the file checks in the background on the owner's schedule.
 *
 * One cron event walks through the phases (WordPress files, plugin files,
 * file changes, suspicious code), a few seconds per tick, and comes back a
 * minute later until the run is done. Then anything that was not there after
 * the previous run is logged and emailed once.
 */
class Schedule {

	const CRON   = 'nhrrob_secure_scan';
	const PHASES = [ 'core', 'database', 'plugins', 'themes', 'monitor', 'code' ];

	/**
	 * Make the cron event match the setting.
	 *
	 * @return void
	 */
	public static function sync() {
		$wanted = (string) Settings::get( 'scan_schedule' );
		$actual = self::recurrence( (array) _get_cron_array() );
		if ( $wanted === $actual ) {
			return;
		}
		wp_clear_scheduled_hook( self::CRON );
		Scan::set( 'scheduled', null );
		if ( 'off' !== $wanted ) {
			wp_schedule_event( time() + 2 * HOUR_IN_SECONDS, $wanted, self::CRON );
		}
	}

	/**
	 * How often the scan is set to recur, read from the cron list. Pure.
	 *
	 * A run in progress also has one-off events under the same hook (the next
	 * tick, a minute away). Those must not be mistaken for the schedule: doing
	 * so cancelled every run after its first phase.
	 *
	 * @param array $crons The cron array: time => hook => key => event.
	 * @return string daily | weekly | … | off
	 */
	public static function recurrence( array $crons ) {
		foreach ( $crons as $hooks ) {
			if ( ! is_array( $hooks ) || empty( $hooks[ self::CRON ] ) ) {
				continue;
			}
			foreach ( (array) $hooks[ self::CRON ] as $event ) {
				if ( ! empty( $event['schedule'] ) ) {
					return (string) $event['schedule'];
				}
			}
		}
		return 'off';
	}

	/**
	 * One tick of the scheduled run.
	 *
	 * @return void
	 */
	public static function tick() {
		$run = Scan::get( 'scheduled' );
		if ( ! is_array( $run ) || ! isset( self::PHASES[ $run['phase'] ] ) ) {
			$run = [
				'phase' => 0,
				'fresh' => true,
			];
		}
		// A phase that died three times in a row (out of memory, time limit) is skipped,
		// so one bad folder cannot keep the rest of the scan from ever running.
		$tries = isset( $run['tries'] ) ? (int) $run['tries'] : 0;
		if ( $tries >= 3 ) {
			++$run['phase'];
			$run['fresh'] = true;
			$tries        = 0;
			if ( ! isset( self::PHASES[ $run['phase'] ] ) ) {
				Scan::set( 'scheduled', null );
				self::report();
				return;
			}
		}
		// Noted before the work starts, with a retry a few minutes out in case this request dies.
		$retry        = time() + 5 * MINUTE_IN_SECONDS;
		$run['tries'] = $tries + 1;
		Scan::set( 'scheduled', $run );
		wp_schedule_single_event( $retry, self::CRON );

		$phase   = self::PHASES[ $run['phase'] ];
		$restart = ! empty( $run['fresh'] );
		$running = false;

		if ( 'core' === $phase ) {
			Integrity::check_core();
		} elseif ( 'database' === $phase ) {
			DatabaseScan::run();
		} elseif ( 'plugins' === $phase ) {
			if ( $restart ) {
				Integrity::start_plugins();
			}
			$step    = Integrity::step_plugins();
			$running = $step['running'];
		} elseif ( 'themes' === $phase ) {
			if ( $restart ) {
				Integrity::start_themes();
			}
			$step    = Integrity::step_themes();
			$running = $step['running'];
		} elseif ( 'monitor' === $phase ) {
			$step    = Monitor::step( $restart );
			$running = $step['running'];
		} else {
			$state   = $restart ? CodeScan::start() : CodeScan::step();
			$running = 'running' === $state['status'];
		}

		// The step came back: drop the retry and carry on.
		wp_unschedule_event( $retry, self::CRON );
		$run['tries'] = 0;
		if ( $running ) {
			$run['fresh'] = false;
		} else {
			++$run['phase'];
			$run['fresh'] = true;
		}

		if ( $run['phase'] < count( self::PHASES ) ) {
			Scan::set( 'scheduled', $run );
			wp_schedule_single_event( time() + MINUTE_IN_SECONDS, self::CRON );
			return;
		}
		Scan::set( 'scheduled', null );
		self::report();
	}

	/**
	 * Everything the checks currently report, as short strings.
	 *
	 * @return string[]
	 */
	public static function findings() {
		$out  = [];
		$core = Scan::get( 'core' );
		if ( is_array( $core ) ) {
			foreach ( [ 'modified', 'missing', 'unexpected' ] as $kind ) {
				foreach ( $core[ $kind ] as $file ) {
					/* translators: %s: file path. */
					$out[] = sprintf( __( 'WordPress file: %s', 'nhrrob-secure' ), $file );
				}
			}
		}
		foreach ( is_array( $core ) && isset( $core['config'] ) ? $core['config'] : [] as $finding ) {
			/* translators: %s: file name. */
			$out[] = sprintf( __( 'Server or configuration file: %s', 'nhrrob-secure' ), $finding['file'] );
		}
		$themes = Scan::get( 'themes' );
		foreach ( is_array( $themes ) ? $themes['changed'] : [] as $theme ) {
			/* translators: %s: theme name. */
			$out[] = sprintf( __( 'Theme differs from its WordPress.org release: %s', 'nhrrob-secure' ), $theme['name'] );
		}
		$plugins = Scan::get( 'plugins' );
		if ( is_array( $plugins ) ) {
			foreach ( $plugins['changed'] as $plugin ) {
				/* translators: %s: plugin name. */
				$out[] = sprintf( __( 'Plugin differs from its WordPress.org release: %s', 'nhrrob-secure' ), $plugin['name'] );
			}
		}
		$monitor = Monitor::for_app();
		foreach ( $monitor['changed'] as $item ) {
			/* translators: %s: plugin or theme name. */
			$out[] = sprintf( __( 'Code changed without an update: %s', 'nhrrob-secure' ), $item['name'] );
		}
		$database = Scan::get( 'database' );
		if ( is_array( $database ) ) {
			foreach ( $database['findings'] as $finding ) {
				/* translators: %s: where it was found. */
				$out[] = sprintf( __( 'Suspicious content in the database: %s', 'nhrrob-secure' ), $finding['where'] );
			}
		}
		$code = CodeScan::for_app();
		foreach ( $code['findings'] as $finding ) {
			/* translators: %s: file path. */
			$out[] = sprintf( __( 'Suspicious code: %s', 'nhrrob-secure' ), 'wp-content/' . $finding['file'] );
		}
		return $out;
	}

	/**
	 * Log and email findings that were not there after the previous run.
	 *
	 * @return void
	 */
	private static function report() {
		$all   = self::findings();
		$seen  = Scan::get( 'scheduled_seen' );
		$fresh = array_values( array_diff( $all, is_array( $seen ) ? $seen : [] ) );

		Scan::set( 'scheduled_seen', array_slice( $all, 0, 500 ) );
		Scan::set( 'scheduled_last', time() );
		if ( ! $fresh ) {
			return;
		}
		foreach ( array_slice( $fresh, 0, 20 ) as $finding ) {
			Activity::record( 'scan', 'finding', $finding, Activity::CRITICAL, [ 'user' => 0 ] );
		}
		if ( Settings::get( 'alert_scan' ) ) {
			Alerts::send(
				__( 'The scheduled scan found something new', 'nhrrob-secure' ),
				array_merge( [ __( 'New since the last scheduled scan:', 'nhrrob-secure' ), '' ], array_slice( $fresh, 0, 30 ) )
			);
		}
	}
}
