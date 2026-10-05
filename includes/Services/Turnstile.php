<?php
/**
 * Cloudflare Turnstile on the sign-in screens.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Services;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Core\Ip;
use NHRRob\Secure\Core\Settings;

/**
 * Adds a Turnstile check to the WordPress sign-in, register and lost-password
 * forms. Off unless the owner supplied their own keys. Only the core
 * wp-login.php screens are checked, so sign-in forms of other plugins keep
 * working.
 */
class Turnstile {

	// The address of Cloudflare's verification API (a service call, not a hosted asset).
	const VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'; // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent

	/**
	 * Register the hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		if ( ! Settings::get( 'turnstile_enabled' ) || Settings::safe_mode() ) {
			return;
		}
		add_action( 'login_enqueue_scripts', [ $this, 'enqueue' ] );
		foreach ( [ 'login_form', 'register_form', 'lostpassword_form' ] as $hook ) {
			add_action( $hook, [ $this, 'render' ] );
		}
		add_filter( 'authenticate', [ $this, 'check_login' ], 99 );
		add_filter( 'registration_errors', [ $this, 'check_form' ] );
		add_action( 'lostpassword_post', [ $this, 'check_lost_password' ] );
	}

	/**
	 * Load Cloudflare's widget script on the sign-in screens.
	 *
	 * @return void
	 */
	public function enqueue() {
		// Turnstile is a service: Cloudflare requires its widget to be loaded from Cloudflare and it cannot be bundled. Off unless the owner enters their own keys; disclosed in the readme.
		// phpcs:ignore WordPress.WP.EnqueuedResourceParameters.MissingVersion, PluginCheck.CodeAnalysis.EnqueuedResourceOffloading.OffloadedContent
		wp_enqueue_script( 'nhrrob-secure-turnstile', 'https://challenges.cloudflare.com/turnstile/v0/api.js', [], null, true );
	}

	/**
	 * Print the widget.
	 *
	 * @return void
	 */
	public function render() {
		printf(
			'<div class="cf-turnstile" data-sitekey="%s" data-size="flexible" style="margin-bottom:16px"></div>',
			esc_attr( (string) Settings::get( 'turnstile_site_key' ) )
		);
	}

	/**
	 * Check the token on a wp-login.php sign-in.
	 *
	 * @param mixed $user Result of earlier authenticate filters.
	 * @return mixed
	 */
	public function check_login( $user ) {
		global $pagenow;
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- sign-in form of a visitor who is not signed in; the Turnstile token is the check.
		if ( 'wp-login.php' !== $pagenow || ! isset( $_POST['log'] ) || is_wp_error( $user ) ) {
			return $user;
		}
		return $this->passes() ? $user : $this->error();
	}

	/**
	 * Check the token on the register form.
	 *
	 * @param \WP_Error $errors Form errors.
	 * @return \WP_Error
	 */
	public function check_form( $errors ) {
		if ( $errors instanceof \WP_Error && ! $this->passes() ) {
			$errors->add( 'nhrrob_secure_turnstile', $this->error()->get_error_message() );
		}
		return $errors;
	}

	/**
	 * Check the token on the lost-password form.
	 *
	 * @param \WP_Error $errors Form errors.
	 * @return void
	 */
	public function check_lost_password( $errors ) {
		$this->check_form( $errors );
	}

	/**
	 * The error shown when the check fails.
	 *
	 * @return \WP_Error
	 */
	private function error() {
		return new \WP_Error( 'nhrrob_secure_turnstile', __( 'Please complete the "I am human" check and try again.', 'nhrrob-secure' ) );
	}

	/**
	 * Ask Cloudflare whether the submitted token is valid.
	 *
	 * If Cloudflare cannot be reached the form is let through: an outage of a
	 * third party must not lock the owner out of their own site.
	 *
	 * @return bool
	 */
	private function passes() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- the Turnstile token is the anti-forgery check here.
		$token = isset( $_POST['cf-turnstile-response'] ) ? sanitize_text_field( wp_unslash( $_POST['cf-turnstile-response'] ) ) : '';
		if ( '' === $token ) {
			return false;
		}
		$response = wp_remote_post(
			self::VERIFY_URL,
			[
				'timeout' => 8,
				'body'    => [
					'secret'   => (string) Settings::get( 'turnstile_secret' ),
					'response' => $token,
					'remoteip' => Ip::client(),
				],
			]
		);
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return true;
		}
		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		return ! empty( $data['success'] );
	}
}
