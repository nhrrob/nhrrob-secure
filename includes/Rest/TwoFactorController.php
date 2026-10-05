<?php
/**
 * REST: a user's own two-factor setup.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Rest;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Core\Settings;
use NHRRob\Secure\Services\TwoFactor;

/**
 * GET  /2fa            the current user's status
 * POST /2fa/begin      start setup (creates a secret or emails a code)
 * POST /2fa/confirm    finish setup with a working code
 * POST /2fa/passkey    finish setup with a newly created passkey
 * POST /2fa/disable    switch it off (needs the account password)
 * POST /2fa/recovery   new recovery codes (needs the account password)
 * POST /2fa/forget-browsers   end "don't ask again" on every browser
 *
 * Every route acts on the signed-in user only; no route takes a user id.
 * Switching off and re-issuing codes ask for the password again, so a stolen
 * session alone cannot weaken the account.
 */
class TwoFactorController extends RestController {

	/**
	 * Register the routes.
	 *
	 * @return void
	 */
	public function register() {
		$this->route( '/2fa', 'GET', [ $this, 'status' ], [], 'is_signed_in' );
		$this->route( '/2fa/begin', 'POST', [ $this, 'begin' ], [ 'method' => $this->text() ], 'is_signed_in' );
		$this->route( '/2fa/confirm', 'POST', [ $this, 'confirm' ], [ 'code' => $this->text() ], 'is_signed_in' );
		$this->route( '/2fa/disable', 'POST', [ $this, 'disable' ], [ 'password' => [ 'required' => true ] ], 'is_signed_in' );
		$this->route(
			'/2fa/passkey',
			'POST',
			[ $this, 'passkey' ],
			[
				'client'      => $this->text(),
				'attestation' => $this->text(),
				'label'       => $this->text( false ),
			],
			'is_signed_in'
		);
		$this->route( '/2fa/forget-browsers', 'POST', [ $this, 'forget' ], [], 'is_signed_in' );
		$this->route( '/2fa/recovery', 'POST', [ $this, 'recovery' ], [ 'password' => [ 'required' => true ] ], 'is_signed_in' );
	}

	/**
	 * Gate: any signed-in user, while two-factor is available on the site.
	 *
	 * @return bool
	 */
	public function is_signed_in() {
		return is_user_logged_in() && Settings::get( 'twofa_enabled' );
	}

	/**
	 * Status.
	 *
	 * @return \WP_REST_Response
	 */
	public function status() {
		return rest_ensure_response( TwoFactor::status( wp_get_current_user() ) );
	}

	/**
	 * Start setup.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function begin( $request ) {
		$result = TwoFactor::begin( wp_get_current_user(), (string) $request['method'] );
		return is_wp_error( $result ) ? $result : rest_ensure_response( $result );
	}

	/**
	 * Finish setup.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function confirm( $request ) {
		$user   = wp_get_current_user();
		$result = TwoFactor::confirm( $user, (string) $request['code'] );
		if ( is_wp_error( $result ) ) {
			return $result;
		}
		return rest_ensure_response( array_merge( TwoFactor::status( $user ), $result ) );
	}

	/**
	 * Check the account password, allowing five tries per fifteen minutes.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return true|\WP_Error
	 */
	private function check_password( $request ) {
		$user  = wp_get_current_user();
		$key   = 'nhrrob_secure_pw_' . $user->ID;
		$tries = (int) get_transient( $key );
		if ( $tries >= 5 ) {
			return new \WP_Error( 'nhrrob_secure_wait', __( 'Too many wrong passwords. Try again in 15 minutes.', 'nhrrob-secure' ), [ 'status' => 429 ] );
		}
		if ( ! wp_check_password( (string) $request['password'], $user->user_pass, $user->ID ) ) {
			set_transient( $key, $tries + 1, 15 * MINUTE_IN_SECONDS );
			return new \WP_Error( 'nhrrob_secure_password', __( 'That is not your account password.', 'nhrrob-secure' ), [ 'status' => 403 ] );
		}
		delete_transient( $key );
		return true;
	}

	/**
	 * Switch two-factor off.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function disable( $request ) {
		$user  = wp_get_current_user();
		$check = $this->check_password( $request );
		if ( is_wp_error( $check ) ) {
			return $check;
		}
		if ( TwoFactor::is_required( $user ) ) {
			return new \WP_Error( 'nhrrob_secure_required', __( 'Your role must use two-factor, so it cannot be switched off.', 'nhrrob-secure' ), [ 'status' => 403 ] );
		}
		TwoFactor::disable( $user );
		return rest_ensure_response( TwoFactor::status( $user ) );
	}

	/**
	 * Finish passkey setup.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function passkey( $request ) {
		$user   = wp_get_current_user();
		$result = TwoFactor::confirm_passkey( $user, (string) $request['client'], (string) $request['attestation'], (string) $request['label'] );
		if ( is_wp_error( $result ) ) {
			return $result;
		}
		return rest_ensure_response( array_merge( TwoFactor::status( $user ), $result ) );
	}

	/**
	 * Forget the user's trusted browsers.
	 *
	 * @return \WP_REST_Response
	 */
	public function forget() {
		$user = wp_get_current_user();
		TwoFactor::forget_browsers( $user->ID );
		return rest_ensure_response( TwoFactor::status( $user ) );
	}

	/**
	 * Issue new recovery codes.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function recovery( $request ) {
		$user  = wp_get_current_user();
		$check = $this->check_password( $request );
		if ( is_wp_error( $check ) ) {
			return $check;
		}
		if ( ! TwoFactor::is_on( $user->ID ) ) {
			return new \WP_Error( 'nhrrob_secure_off', __( 'Two-factor is not switched on for your account.', 'nhrrob-secure' ), [ 'status' => 400 ] );
		}
		return rest_ensure_response( array_merge( TwoFactor::status( $user ), [ 'recovery_codes' => TwoFactor::new_recovery_codes( $user->ID ) ] ) );
	}
}
