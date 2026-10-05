<?php
/**
 * REST: users and sessions, firewall, file protection and activity.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Rest;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Core\Activity;
use NHRRob\Secure\Core\Ip;
use NHRRob\Secure\Core\Settings;
use NHRRob\Secure\Services\FileProtection;
use NHRRob\Secure\Services\Firewall;
use NHRRob\Secure\Services\Passwords;
use NHRRob\Secure\Services\Sessions;
use NHRRob\Secure\Services\TwoFactor;

/**
 * GET    /users                    users with two-factor state and sessions
 * POST   /users/{id}/signout       end one user's sessions
 * POST   /users/{id}/reset-2fa     switch two-factor off for one user
 * POST   /users/signout-all        end every session but the current one
 * POST   /users/{id}/force-password  make one user choose a new password
 * POST   /users/force-password     the same for a role, or everyone
 * GET    /firewall                 rules, recent filter matches, detection
 * POST   /firewall/rules           add an address rule
 * DELETE /firewall/rules           remove an address rule
 * GET    /hardening                last file-protection check
 * POST   /hardening/check          run the file-protection check
 * GET    /activity                 a filtered page of the log
 * GET    /activity/export          the filtered log as CSV text
 */
class SecurityController extends RestController {

	/**
	 * Register the routes.
	 *
	 * @return void
	 */
	public function register() {
		$id = [
			'id' => [
				'type'              => 'integer',
				'required'          => true,
				'sanitize_callback' => 'absint',
			],
		];

		$this->route( '/users', 'GET', [ $this, 'users' ] );
		$this->route( '/users/(?P<id>\d+)/signout', 'POST', [ $this, 'signout' ], $id );
		$this->route( '/users/(?P<id>\d+)/reset-2fa', 'POST', [ $this, 'reset_2fa' ], $id );
		$this->route( '/users/signout-all', 'POST', [ $this, 'signout_all' ], [], 'can_manage_files' );
		$this->route( '/users/(?P<id>\d+)/force-password', 'POST', [ $this, 'force_password' ], $id );
		$this->route( '/users/force-password', 'POST', [ $this, 'force_password_scope' ], [ 'scope' => $this->text() ] );

		$this->route( '/firewall', 'GET', [ $this, 'firewall' ] );
		$this->route(
			'/firewall/rules',
			'POST',
			[ $this, 'add_rule' ],
			[
				'range' => $this->text(),
				'type'  => $this->text(),
				'note'  => $this->text( false ),
			]
		);
		$this->route( '/firewall/rules', 'DELETE', [ $this, 'remove_rule' ], [ 'range' => $this->text() ] );
		$this->route( '/hardening', 'GET', [ $this, 'files' ] );
		$this->route( '/hardening/check', 'POST', [ $this, 'check_files' ] );

		$this->route( '/activity', 'GET', [ $this, 'activity' ] );
		$this->route( '/activity/export', 'GET', [ $this, 'export' ] );
	}

	// ---- Users. ----

	/**
	 * A page of users.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function users( $request ) {
		if ( ! current_user_can( 'list_users' ) ) {
			return new \WP_Error( 'rest_forbidden', __( 'You are not allowed to list users.', 'nhrrob-secure' ), [ 'status' => 403 ] );
		}
		return rest_ensure_response(
			Sessions::users(
				[
					'page'   => (int) $request->get_param( 'page' ),
					'search' => sanitize_text_field( (string) $request->get_param( 'search' ) ),
					'role'   => sanitize_key( (string) $request->get_param( 'role' ) ),
				]
			)
		);
	}

	/**
	 * The user a route targets, if the current user may edit them.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_User|\WP_Error
	 */
	private function target_user( $request ) {
		$user = get_userdata( (int) $request['id'] );
		if ( ! $user || ( is_multisite() && ! is_user_member_of_blog( $user->ID ) ) ) {
			return new \WP_Error( 'nhrrob_secure_no_user', __( 'That user does not exist.', 'nhrrob-secure' ), [ 'status' => 404 ] );
		}
		if ( ! current_user_can( 'edit_user', $user->ID ) ) {
			return new \WP_Error( 'rest_forbidden', __( 'You are not allowed to manage that user.', 'nhrrob-secure' ), [ 'status' => 403 ] );
		}
		return $user;
	}

	/**
	 * End one user's sessions.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function signout( $request ) {
		$user = $this->target_user( $request );
		if ( is_wp_error( $user ) ) {
			return $user;
		}
		Sessions::sign_out( $user );
		return rest_ensure_response( [ 'done' => true ] );
	}

	/**
	 * Switch two-factor off for one user so they can set it up again.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function reset_2fa( $request ) {
		$user = $this->target_user( $request );
		if ( is_wp_error( $user ) ) {
			return $user;
		}
		// Your own second step is switched off on your profile, where it asks for your password.
		if ( get_current_user_id() === (int) $user->ID ) {
			return new \WP_Error( 'nhrrob_secure_self', __( 'To switch off your own two-factor, use your profile: it asks for your password.', 'nhrrob-secure' ), [ 'status' => 400 ] );
		}
		TwoFactor::disable( $user );
		return rest_ensure_response( [ 'done' => true ] );
	}

	/**
	 * Make one user choose a new password.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function force_password( $request ) {
		$user = $this->target_user( $request );
		if ( is_wp_error( $user ) ) {
			return $user;
		}
		Passwords::force_user( $user );
		return rest_ensure_response( [ 'done' => true ] );
	}

	/**
	 * Make a role, or everyone, choose a new password.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function force_password_scope( $request ) {
		if ( ! current_user_can( 'edit_users' ) || ! Passwords::force_scope( (string) $request['scope'] ) ) {
			return new \WP_Error( 'nhrrob_secure_scope', __( 'Choose everyone or an existing role.', 'nhrrob-secure' ), [ 'status' => 400 ] );
		}
		return rest_ensure_response( [ 'done' => true ] );
	}

	/**
	 * End every session except the current one.
	 *
	 * @return \WP_REST_Response
	 */
	public function signout_all() {
		Sessions::sign_out_everyone();
		return rest_ensure_response( [ 'done' => true ] );
	}

	// ---- Firewall. ----

	/**
	 * Firewall screen data.
	 *
	 * @return \WP_REST_Response
	 */
	public function firewall() {
		$rules = Firewall::labels();
		$rows  = [];
		foreach ( Firewall::log() as $row ) {
			$rows[] = [
				'time'    => (int) $row['t'],
				'ip'      => $row['i'],
				'rule'    => $row['r'],
				'label'   => isset( $rules[ $row['r'] ] ) ? $rules[ $row['r'] ] : $row['r'],
				'path'    => $row['p'],
				'request' => $row['u'],
				'blocked' => (bool) $row['b'],
			];
		}
		return rest_ensure_response(
			[
				'rules'   => array_values( (array) Settings::get( 'ip_rules' ) ),
				'matches' => array_slice( $rows, 0, 50 ),
				'since'   => (int) Settings::get( 'request_filter_since' ),
				'blocked' => Firewall::blocked_week(),
			]
		);
	}

	/**
	 * Add an address rule.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function add_rule( $request ) {
		$range = trim( (string) $request['range'] );
		$type  = 'allow' === $request['type'] ? 'allow' : 'block';
		if ( ! Ip::valid_range( $range ) ) {
			return new \WP_Error( 'nhrrob_secure_range', __( 'Enter an IPv4 or IPv6 address, or a range like 203.0.113.0/24.', 'nhrrob-secure' ), [ 'status' => 400 ] );
		}
		if ( 'block' === $type && ( Ip::in_range( Ip::client(), $range ) || Ip::in_range( Ip::remote(), $range ) ) ) {
			return new \WP_Error( 'nhrrob_secure_self_block', __( 'That rule would block your own connection, so it was not added.', 'nhrrob-secure' ), [ 'status' => 400 ] );
		}

		$rules   = (array) Settings::get( 'ip_rules' );
		$rules[] = [
			'range' => $range,
			'type'  => $type,
			'note'  => (string) $request['note'],
			'added' => time(),
		];
		Settings::set_raw( 'ip_rules', Settings::sanitize_ip_rules( $rules ) );
		Activity::record( 'setting', 'changed', 'ip rules (' . $type . ' ' . $range . ')', Activity::INFO );
		return $this->firewall();
	}

	/**
	 * Remove an address rule.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response
	 */
	public function remove_rule( $request ) {
		$range = (string) $request['range'];
		$rules = array_filter(
			(array) Settings::get( 'ip_rules' ),
			function ( $rule ) use ( $range ) {
				return $rule['range'] !== $range;
			}
		);
		Settings::set_raw( 'ip_rules', array_values( $rules ) );
		return $this->firewall();
	}

	// ---- File protection. ----

	/**
	 * The last file-protection check.
	 *
	 * @return \WP_REST_Response
	 */
	public function files() {
		return rest_ensure_response( FileProtection::last() );
	}

	/**
	 * Run the file-protection check now.
	 *
	 * @return \WP_REST_Response
	 */
	public function check_files() {
		return rest_ensure_response( FileProtection::check() );
	}

	// ---- Activity. ----

	/**
	 * Read the log filters from a request.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return array
	 */
	private function filters( $request ) {
		return [
			'search'   => sanitize_text_field( (string) $request->get_param( 'search' ) ),
			'type'     => sanitize_key( (string) $request->get_param( 'type' ) ),
			'severity' => (int) $request->get_param( 'severity' ),
			'page'     => (int) $request->get_param( 'page' ),
		];
	}

	/**
	 * A page of the activity log.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response
	 */
	public function activity( $request ) {
		return rest_ensure_response( Activity::query( $this->filters( $request ) ) );
	}

	/**
	 * The filtered log as CSV text (the app turns it into a download).
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response
	 */
	public function export( $request ) {
		$result = Activity::query(
			array_merge(
				$this->filters( $request ),
				[
					'page'     => 1,
					'per_page' => 1000,
				]
			)
		);
		$lines  = [ 'time,who,type,event,address,importance' ];
		$names  = [
			1 => 'info',
			2 => 'warning',
			3 => 'critical',
		];
		foreach ( $result['items'] as $item ) {
			$cells = [ gmdate( 'Y-m-d H:i:s', $item['time'] ) . ' UTC', $item['who'], $item['type'], $item['text'], $item['ip'], $names[ $item['severity'] ] ];
			foreach ( $cells as &$cell ) {
				$cell = (string) $cell;
				// A cell that starts like a formula would run in a spreadsheet.
				if ( '' !== $cell && false !== strpos( "=+-@\t\r", $cell[0] ) ) {
					$cell = "'" . $cell;
				}
				$cell = '"' . str_replace( '"', '""', $cell ) . '"';
			}
			unset( $cell );
			$lines[] = implode( ',', $cells );
		}
		return rest_ensure_response( [ 'csv' => implode( "\n", $lines ) ] );
	}
}
