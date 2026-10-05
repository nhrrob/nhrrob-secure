<?php
/**
 * Bot check on the sign-in screens.
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
 * Adds Cloudflare Turnstile, Google reCAPTCHA v2 or hCaptcha to the WordPress
 * sign-in, register and lost-password forms. Off unless the owner supplied
 * their own keys. Only the core wp-login.php screens are checked, so sign-in
 * forms of other plugins keep working.
 *
 * These are services: each provider requires its widget script to be loaded
 * from its own servers and it cannot be bundled. All three are disclosed in
 * the readme.
 */
class BotCheck {

	/**
	 * The supported providers: widget script, widget class, form field, verification API.
	 *
	 * @return array
	 */
	public static function providers() {
		// phpcs:disable PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- service endpoints, not hosted assets.
		return [
			'turnstile' => [
				'script' => 'https://challenges.cloudflare.com/turnstile/v0/api.js',
				'class'  => 'cf-turnstile',
				'field'  => 'cf-turnstile-response',
				'verify' => 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
			],
			'recaptcha' => [
				'script' => 'https://www.google.com/recaptcha/api.js',
				'class'  => 'g-recaptcha',
				'field'  => 'g-recaptcha-response',
				'verify' => 'https://www.google.com/recaptcha/api/siteverify',
			],
			'hcaptcha'  => [
				'script' => 'https://js.hcaptcha.com/1/api.js',
				'class'  => 'h-captcha',
				'field'  => 'h-captcha-response',
				'verify' => 'https://api.hcaptcha.com/siteverify',
			],
		];
		// phpcs:enable
	}

	/**
	 * The provider the owner chose.
	 *
	 * @return array
	 */
	private function provider() {
		$all = self::providers();
		$key = (string) Settings::get( 'captcha_provider' );
		return isset( $all[ $key ] ) ? $all[ $key ] : $all['turnstile'];
	}

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
	 * Load the provider's widget script on the sign-in screens.
	 *
	 * @return void
	 */
	public function enqueue() {
		$provider = $this->provider();
		// phpcs:ignore WordPress.WP.EnqueuedResourceParameters.MissingVersion, PluginCheck.CodeAnalysis.EnqueuedResourceOffloading.OffloadedContent -- a service script that must come from the provider and must not be pinned.
		wp_enqueue_script( 'nhrrob-secure-bot-check', $provider['script'], [], null, true );
	}

	/**
	 * Print the widget.
	 *
	 * @return void
	 */
	public function render() {
		$provider = $this->provider();
		printf(
			'<div class="%s" data-sitekey="%s" style="margin-bottom:16px"></div>',
			esc_attr( $provider['class'] ),
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
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- sign-in form of a visitor who is not signed in; the provider's token is the check.
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
			$errors->add( 'nhrrob_secure_bot_check', $this->error()->get_error_message() );
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
		return new \WP_Error( 'nhrrob_secure_bot_check', __( 'Please complete the "I am human" check and try again.', 'nhrrob-secure' ) );
	}

	/**
	 * Ask the provider whether the submitted token is valid.
	 *
	 * If the provider cannot be reached the form is let through: an outage of
	 * a third party must not lock the owner out of their own site.
	 *
	 * @return bool
	 */
	private function passes() {
		$provider = $this->provider();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- the provider's token is the anti-forgery check here.
		$token = isset( $_POST[ $provider['field'] ] ) ? sanitize_text_field( wp_unslash( $_POST[ $provider['field'] ] ) ) : '';
		if ( '' === $token ) {
			return false;
		}
		$response = wp_remote_post(
			$provider['verify'],
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
