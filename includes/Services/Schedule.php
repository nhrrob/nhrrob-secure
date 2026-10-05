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
	const PHASES = [ 'core', 'database', 'plugins', 'monitor', 'code' ];

	/**
	 * Make the cron event match the setting.
	 *
	 * @return void
	 */
	public static function sync() {
		$wanted = (string) Settings::get( 'scan_schedule' );
		$event  = wp_get_scheduled_event( self::CRON );
		$actual = $event && $event->schedule ? $event->schedule : 'off';
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
	 * One tick of the scheduled run.
	 *
	 * @return void
	 */
	public static function tick() {
		$run = Scan::get( 'scheduled' );
		if ( ! is_array( $run ) ) {
			$run = [
				'phase' => 0,
				'fresh' => true,
			];
		}
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
		} elseif ( 'monitor' === $phase ) {
			$step    = Monitor::step( $restart );
			$running = $step['running'];
		} else {
			$state   = $restart ? CodeScan::start() : CodeScan::step();
			$running = 'running' === $state['status'];
		}

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
