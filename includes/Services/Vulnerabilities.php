<?php
/**
 * Known-vulnerability check.
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
 * Compares WordPress, plugins and themes with the WPVulnerability database.
 *
 * Only slugs and versions are sent. The check runs in small batches — driven
 * by the browser when the owner presses "Check now", or by a daily cron event
 * that reschedules itself — so it never holds up a page. The owner is alerted
 * once per new finding, not every day.
 */
class Vulnerabilities {

	const API   = 'https://www.wpvulnerability.net/';
	const CRON  = 'nhrrob_secure_vulnerability_check';
	const BATCH = 5;
	const LOCK  = 'nhrrob_secure_vuln_lock';

	/**
	 * Queue everything installed for checking.
	 *
	 * @return array Run state.
	 */
	public static function start() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$queue = [ [ 'core', '', get_bloginfo( 'version' ), 'WordPress' ] ];
		foreach ( get_plugins() as $file => $data ) {
			$slug    = dirname( $file );
			$queue[] = [ 'plugin', '.' === $slug ? basename( $file, '.php' ) : $slug, $data['Version'], $data['Name'] ];
		}
		foreach ( wp_get_themes() as $slug => $theme ) {
			$queue[] = [ 'theme', $slug, $theme->get( 'Version' ), $theme->get( 'Name' ) ];
		}

		$run = [
			'queue'  => $queue,
			'total'  => count( $queue ),
			'found'  => [],
			'closed' => [],
		];
		Scan::set( 'vuln_run', $run );
		return $run;
	}

	/**
	 * Check the next batch. Finishes the run when the queue is empty.
	 *
	 * @return array { running: bool, done: int, total: int }
	 */
	public static function step() {
		$run = Scan::get( 'vuln_run' );
		// The browser and the daily cron can both be stepping the same run. Whoever comes
		// second waits its turn, so no item is looked up twice or reported twice.
		if ( is_array( $run ) && get_transient( self::LOCK ) ) {
			return [
				'running' => true,
				'done'    => $run['total'] - count( $run['queue'] ),
				'total'   => $run['total'],
			];
		}
		set_transient( self::LOCK, 1, MINUTE_IN_SECONDS );
		if ( ! is_array( $run ) ) {
			$run = self::start();
		}

		for ( $i = 0; $i < self::BATCH && $run['queue']; $i++ ) {
			$item   = array_shift( $run['queue'] );
			$result = self::check_item( $item );
			if ( $result['failed'] ) {
				$run['failed'] = ( isset( $run['failed'] ) ? (int) $run['failed'] : 0 ) + 1;
			}
			if ( $result['closed'] ) {
				$run['closed'][] = $item[3];
			}
			foreach ( $result['found'] as $found ) {
				$run['found'][] = $found;
			}
		}

		delete_transient( self::LOCK );
		if ( $run['queue'] ) {
			Scan::set( 'vuln_run', $run );
			return [
				'running' => true,
				'done'    => $run['total'] - count( $run['queue'] ),
				'total'   => $run['total'],
			];
		}

		self::finish( $run );
		return [
			'running' => false,
			'done'    => $run['total'],
			'total'   => $run['total'],
		];
	}

	/**
	 * Look one item up.
	 *
	 * @param array $item [ type, slug, version, name ].
	 * @return array { found: array, closed: bool, failed: bool }
	 */
	private static function check_item( array $item ) {
		list( $type, $slug, $version, $name ) = $item;

		$url      = self::API . ( 'core' === $type ? 'core/' . rawurlencode( $version ) : $type . '/' . rawurlencode( $slug ) );
		$response = wp_remote_get( $url, [ 'timeout' => 6 ] );
		$out      = [
			'found'  => [],
			'closed' => false,
			'failed' => false,
		];
		// No answer, or a server error, is not the same as "nothing known": say so.
		if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) >= 500 ) {
			$out['failed'] = true;
			return $out;
		}
		if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return $out;
		}
		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $data['data'] ) || ! is_array( $data['data'] ) ) {
			return $out;
		}

		$out['closed'] = ! empty( $data['data']['closed'] );
		$list          = isset( $data['data']['vulnerability'] ) && is_array( $data['data']['vulnerability'] ) ? $data['data']['vulnerability'] : [];
		foreach ( $list as $vuln ) {
			$operator = isset( $vuln['operator'] ) && is_array( $vuln['operator'] ) ? $vuln['operator'] : [];
			if ( 'core' !== $type && ! self::affects( $version, $operator ) ) {
				continue;
			}
			// Prefer a source with a readable title over a bare CVE number.
			$source = [];
			foreach ( isset( $vuln['source'] ) && is_array( $vuln['source'] ) ? $vuln['source'] : [] as $candidate ) {
				if ( ! is_array( $candidate ) || empty( $candidate['name'] ) ) {
					continue;
				}
				if ( ! $source ) {
					$source = $candidate;
				}
				if ( 0 !== strpos( $candidate['name'], 'CVE-' ) ) {
					$source = $candidate;
					break;
				}
			}
			$score    = isset( $vuln['impact']['cvss']['score'] ) ? (float) $vuln['impact']['cvss']['score'] : 0.0;
			$fixed_in = '';
			if ( empty( $operator['unfixed'] ) && ! empty( $operator['max_version'] ) && isset( $operator['max_operator'] ) && 'lt' === $operator['max_operator'] ) {
				$fixed_in = (string) $operator['max_version'];
			}
			$out['found'][] = [
				'id'       => isset( $vuln['uuid'] ) ? (string) $vuln['uuid'] : md5( wp_json_encode( $vuln ) ),
				'type'     => $type,
				'name'     => $name,
				'version'  => $version,
				// The database sends titles HTML-encoded ("&lt; 5.3.2"). They are stored as plain text and escaped on output.
				'title'    => html_entity_decode( sanitize_text_field( html_entity_decode( ! empty( $source['name'] ) ? $source['name'] : ( isset( $vuln['name'] ) ? $vuln['name'] : '' ), ENT_QUOTES ) ), ENT_QUOTES ),
				'link'     => ! empty( $source['link'] ) ? esc_url_raw( $source['link'] ) : '',
				'score'    => $score,
				'fixed_in' => $fixed_in,
				'unfixed'  => ! empty( $operator['unfixed'] ),
			];
		}
		return $out;
	}

	/**
	 * Whether a version falls inside a vulnerability's affected range.
	 *
	 * @param string $version  Installed version.
	 * @param array  $operator Range from the database.
	 * @return bool
	 */
	public static function affects( $version, array $operator ) {
		$valid = [ 'lt', 'le', 'gt', 'ge', 'eq' ];
		foreach ( [ 'min', 'max' ] as $side ) {
			$bound = isset( $operator[ $side . '_version' ] ) ? (string) $operator[ $side . '_version' ] : '';
			$op    = isset( $operator[ $side . '_operator' ] ) ? (string) $operator[ $side . '_operator' ] : '';
			if ( '' !== $bound && in_array( $op, $valid, true ) && ! version_compare( $version, $bound, $op ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Store the finished run, log and alert on anything new.
	 *
	 * @param array $run Run state.
	 * @return void
	 */
	private static function finish( array $run ) {
		$previous = Scan::get( 'vuln' );
		$seen     = isset( $previous['seen'] ) && is_array( $previous['seen'] ) ? $previous['seen'] : [];
		$failed   = isset( $run['failed'] ) ? (int) $run['failed'] : 0;
		$found_id = array_values( array_unique( wp_list_pluck( $run['found'], 'id' ) ) );

		usort(
			$run['found'],
			function ( $a, $b ) {
				return $b['score'] <=> $a['score'];
			}
		);

		$fresh = [];
		foreach ( $run['found'] as $found ) {
			if ( ! in_array( $found['id'], $seen, true ) ) {
				$fresh[] = $found;
			}
		}

		Scan::set( 'vuln_run', null );
		Scan::set(
			'vuln',
			[
				'checked' => time(),
				'total'   => $run['total'],
				'items'   => array_slice( $run['found'], 0, 100 ),
				'closed'  => array_slice( $run['closed'], 0, 50 ),
				// How many lookups got no answer; the result is incomplete when this is not zero.
				'failed'  => $failed,
				// Remembered so the same finding is announced once. After an incomplete run the
				// earlier list is kept too, or the next good run would announce old findings again.
				'seen'    => array_slice( $failed ? array_values( array_unique( array_merge( $found_id, $seen ) ) ) : $found_id, 0, 300 ),
			]
		);

		if ( ! $fresh ) {
			return;
		}
		$lines = [ __( 'New known vulnerabilities were found in software installed on your site:', 'nhrrob-secure' ), '' ];
		foreach ( array_slice( $fresh, 0, 20 ) as $found ) {
			// Several findings in one plugin fold into one row with a counter.
			Activity::record(
				'scan',
				'vulnerability',
				$found['name'] . ' ' . $found['version'],
				Activity::CRITICAL,
				[
					'user'     => 0,
					'coalesce' => MINUTE_IN_SECONDS,
				]
			);
			$lines[] = '- ' . $found['name'] . ' ' . $found['version'] . ': ' . $found['title']
				/* translators: %s: version number. */
				. ( $found['fixed_in'] ? ' (' . sprintf( __( 'fixed in %s', 'nhrrob-secure' ), $found['fixed_in'] ) . ')' : '' );
		}
		if ( Settings::get( 'alert_vulnerability' ) ) {
			Alerts::send( __( 'New vulnerability found', 'nhrrob-secure' ), $lines );
		}
	}

	/**
	 * Daily cron: run a batch and come back in a minute until the run is done.
	 *
	 * @return void
	 */
	public static function cron() {
		$state = self::step();
		if ( $state['running'] ) {
			wp_schedule_single_event( time() + MINUTE_IN_SECONDS, self::CRON );
		}
	}

	/**
	 * Results for the app.
	 *
	 * @return array
	 */
	public static function results() {
		$last = Scan::get( 'vuln' );
		$run  = Scan::get( 'vuln_run' );
		return [
			'checked' => isset( $last['checked'] ) ? (int) $last['checked'] : 0,
			'total'   => isset( $last['total'] ) ? (int) $last['total'] : 0,
			'items'   => isset( $last['items'] ) ? $last['items'] : [],
			'closed'  => isset( $last['closed'] ) ? $last['closed'] : [],
			'failed'  => isset( $last['failed'] ) ? (int) $last['failed'] : 0,
			'running' => is_array( $run ),
		];
	}
}
