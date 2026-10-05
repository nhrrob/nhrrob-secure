<?php
/**
 * REST: the scanner.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Rest;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Services\CodeScan;
use NHRRob\Secure\Services\DatabaseScan;
use NHRRob\Secure\Services\Integrity;
use NHRRob\Secure\Services\Monitor;
use NHRRob\Secure\Services\Scan;
use NHRRob\Secure\Services\Vulnerabilities;

/**
 * GET  /scanner                    every part's last result
 * POST /scanner/vulnerabilities    run the next batch (restart: start over)
 * POST /scanner/core               compare WordPress core files
 * POST /scanner/core/repair        replace one core file with the official copy
 * POST /scanner/plugins            compare the next few plugins
 * POST /scanner/monitor            fingerprint the next plugins and themes
 * POST /scanner/monitor/accept     accept a changed item's code as it is now
 * POST /scanner/database           look through posts and options for injected content
 * POST /scanner/code               scan for a few seconds
 * POST /scanner/code/view          show the lines around a finding
 * POST /scanner/code/quarantine    rename a reported file so it cannot run
 * POST /scanner/code/restore       put a quarantined file back
 *
 * The long checks are stepped by the browser, a few seconds per request, so
 * none of them can time out or hold up a page.
 */
class ScannerController extends RestController {

	/**
	 * Register the routes.
	 *
	 * @return void
	 */
	public function register() {
		$restart = [
			'restart' => [
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
			],
		];
		$file    = [ 'file' => $this->text() ];

		$this->route( '/scanner', 'GET', [ $this, 'overview' ] );
		$this->route( '/scanner/vulnerabilities', 'POST', [ $this, 'vulnerabilities' ], $restart );
		$this->route( '/scanner/core', 'POST', [ $this, 'core' ] );
		$this->route( '/scanner/core/repair', 'POST', [ $this, 'repair' ], $file, 'can_repair' );
		$this->route( '/scanner/plugins', 'POST', [ $this, 'plugins' ], $restart );
		$this->route( '/scanner/monitor', 'POST', [ $this, 'monitor' ], $restart );
		$this->route( '/scanner/monitor/accept', 'POST', [ $this, 'accept' ], [ 'key' => $this->text() ], 'can_manage_files' );
		$this->route( '/scanner/database', 'POST', [ $this, 'database' ] );
		$this->route( '/scanner/code', 'POST', [ $this, 'code' ], $restart );
		$this->route( '/scanner/code/view', 'POST', [ $this, 'view' ], $file );
		$this->route( '/scanner/code/quarantine', 'POST', [ $this, 'quarantine' ], $file, 'can_manage_files' );
		$this->route( '/scanner/code/restore', 'POST', [ $this, 'restore' ], $file, 'can_manage_files' );
	}

	/**
	 * Replacing a core file needs the same right as updating WordPress.
	 *
	 * @return bool
	 */
	public function can_repair() {
		return $this->can_manage_files() && current_user_can( 'update_core' );
	}

	/**
	 * Everything the scanner screen shows.
	 *
	 * @return array
	 */
	private function data() {
		return [
			'vulnerabilities' => Vulnerabilities::results(),
			'core'            => Scan::get( 'core' ),
			'plugins'         => Scan::get( 'plugins' ),
			'plugins_running' => is_array( Scan::get( 'plugins_run' ) ),
			'code'            => CodeScan::for_app(),
			'monitor'         => Monitor::for_app(),
			'database'        => Scan::get( 'database' ),
			'scheduled_last'  => (int) Scan::get( 'scheduled_last' ),
			'can_files'       => $this->can_manage_files(),
			'can_repair'      => $this->can_repair(),
		];
	}

	/**
	 * Overview.
	 *
	 * @return \WP_REST_Response
	 */
	public function overview() {
		return rest_ensure_response( $this->data() );
	}

	/**
	 * Wrap a step's progress with the fresh screen data once it finishes.
	 *
	 * @param array $progress Step result: running, done, total.
	 * @return \WP_REST_Response
	 */
	private function progress( array $progress ) {
		if ( ! $progress['running'] ) {
			$progress['data'] = $this->data();
		}
		return rest_ensure_response( $progress );
	}

	/**
	 * Run the next vulnerability batch.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response
	 */
	public function vulnerabilities( $request ) {
		if ( $request['restart'] ) {
			Vulnerabilities::start();
		}
		return $this->progress( Vulnerabilities::step() );
	}

	/**
	 * Compare core files.
	 *
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function core() {
		$result = Integrity::check_core();
		return is_wp_error( $result ) ? $result : rest_ensure_response( $this->data() );
	}

	/**
	 * Replace one core file.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function repair( $request ) {
		$result = Integrity::repair_core_file( (string) $request['file'] );
		if ( is_wp_error( $result ) ) {
			return $result;
		}
		return $this->core();
	}

	/**
	 * Compare the next few plugins.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response
	 */
	public function plugins( $request ) {
		if ( $request['restart'] ) {
			Integrity::start_plugins();
		}
		return $this->progress( Integrity::step_plugins() );
	}

	/**
	 * Fingerprint the next plugins and themes.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response
	 */
	public function monitor( $request ) {
		return $this->progress( Monitor::step( (bool) $request['restart'] ) );
	}

	/**
	 * Accept a changed plugin or theme as it is now.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function accept( $request ) {
		if ( ! Monitor::accept( (string) $request['key'] ) ) {
			return new \WP_Error( 'nhrrob_secure_monitor', __( 'That item is not reported as changed.', 'nhrrob-secure' ), [ 'status' => 400 ] );
		}
		return rest_ensure_response( $this->data() );
	}

	/**
	 * Scan posts and options for injected content.
	 *
	 * @return \WP_REST_Response
	 */
	public function database() {
		DatabaseScan::run();
		return rest_ensure_response( $this->data() );
	}

	/**
	 * Continue (or restart) the code scan.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response
	 */
	public function code( $request ) {
		return rest_ensure_response( $request['restart'] ? CodeScan::start() : CodeScan::step() );
	}

	/**
	 * Show the lines around a finding.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function view( $request ) {
		$result = CodeScan::view( (string) $request['file'] );
		return is_wp_error( $result ) ? $result : rest_ensure_response( $result );
	}

	/**
	 * Quarantine a reported file.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function quarantine( $request ) {
		$result = CodeScan::quarantine( (string) $request['file'] );
		return is_wp_error( $result ) ? $result : rest_ensure_response( $result );
	}

	/**
	 * Restore a quarantined file.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function restore( $request ) {
		$result = CodeScan::restore( (string) $request['file'] );
		return is_wp_error( $result ) ? $result : rest_ensure_response( $result );
	}
}
