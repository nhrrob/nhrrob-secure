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
 * Adds Cloudflare Turnstile, Google reCAPTCHA (v2 or v3) or hCaptcha to the
 * WordPress sign-in, register and lost-password forms and, when asked, to the
 * comment form for visitors. Off unless the owner supplied their own keys.
 * Only the core wp-login.php screens and the core comment form are checked,
 * so forms of other plugins keep working.
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
			'turnstile'  => [
				'script' => 'https://challenges.cloudflare.com/turnstile/v0/api.js',
				'class'  => 'cf-turnstile',
				'field'  => 'cf-turnstile-response',
				'verify' => 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
			],
			'recaptcha'  => [
				'script' => 'https://www.google.com/recaptcha/api.js',
				'class'  => 'g-recaptcha',
				'field'  => 'g-recaptcha-response',
				'verify' => 'https://www.google.com/recaptcha/api/siteverify',
			],
			// v3 shows nothing: the page asks for a token when the form is sent and Google answers with a score.
			'recaptcha3' => [
				'script' => 'https://www.google.com/recaptcha/api.js',
				'class'  => '',
				'field'  => 'g-recaptcha-response',
				'verify' => 'https://www.google.com/recaptcha/api/siteverify',
			],
			'hcaptcha'   => [
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
		// After core has looked at the password (20–30) and before the two-factor step (50). The answer
		// is the same whether the password was right or wrong, so the check cannot be used to test passwords.
		add_filter( 'authenticate', [ $this, 'check_login' ], 45 );
		add_filter( 'registration_errors', [ $this, 'check_form' ] );
		add_action( 'lostpassword_post', [ $this, 'check_lost_password' ] );

		if ( Settings::get( 'captcha_comments' ) ) {
			add_action( 'wp_enqueue_scripts', [ $this, 'enqueue_comments' ] );
			// Printed for visitors only: core does not run this hook for signed-in users.
			add_action( 'comment_form_after_fields', [ $this, 'render' ] );
			add_filter( 'preprocess_comment', [ $this, 'check_comment' ], 1 );
		}
	}

	/**
	 * Load the widget script on pages that show a comment form to a visitor.
	 *
	 * @return void
	 */
	public function enqueue_comments() {
		if ( is_singular() && comments_open() && ! is_user_logged_in() ) {
			$this->enqueue();
		}
	}

	/**
	 * Check the token on a comment a visitor sends through the comment form.
	 *
	 * @param array $comment Comment data.
	 * @return array
	 */
	public function check_comment( $comment ) {
		global $pagenow;
		if ( 'wp-comments-post.php' === $pagenow && ! is_user_logged_in() && ! $this->passes() ) {
			wp_die( esc_html( $this->error()->get_error_message() ), '', [ 'response' => 403, 'back_link' => true ] ); // phpcs:ignore WordPress.Arrays.ArrayDeclarationSpacing.AssociativeArrayFound
		}
		return $comment;
	}

	/**
	 * Load the provider's widget script on the sign-in screens.
	 *
	 * @return void
	 */
	public function enqueue() {
		$provider  = $this->provider();
		$key       = (string) Settings::get( 'turnstile_site_key' );
		$invisible = '' === $provider['class'];
		// phpcs:ignore WordPress.WP.EnqueuedResourceParameters.MissingVersion, PluginCheck.CodeAnalysis.EnqueuedResourceOffloading.OffloadedContent -- a service script that must come from the provider and must not be pinned.
		wp_enqueue_script( 'nhrrob-secure-bot-check', $invisible ? add_query_arg( 'render', rawurlencode( $key ), $provider['script'] ) : $provider['script'], [], null, true );
		if ( $invisible ) {
			// Ask for the token when the form is sent, then send the form. A field named "submit" (the comment form has one) hides form.submit(), hence the prototype call.
			wp_add_inline_script(
				'nhrrob-secure-bot-check',
				'document.addEventListener("submit",function(e){var f=e.target,i=f.querySelector(".nhrrob-secure-token");if(!i||i.value||!window.grecaptcha){return;}e.preventDefault();grecaptcha.ready(function(){grecaptcha.execute(' . wp_json_encode( $key ) . ',{action:"submit"}).then(function(t){i.value=t;HTMLFormElement.prototype.submit.call(f);});});},true);'
			);
		}
	}

	/**
	 * Print the widget.
	 *
	 * @return void
	 */
	public function render() {
		$provider = $this->provider();
		if ( '' === $provider['class'] ) {
			printf( '<input type="hidden" class="nhrrob-secure-token" name="%s" value="">', esc_attr( $provider['field'] ) );
			return;
		}
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
		if ( 'wp-login.php' !== $pagenow || ! isset( $_POST['log'] ) ) {
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
		global $pagenow;
		// Only the forms on wp-login.php carry the widget. A reset email sent from the Users screen,
		// or another plugin's own account form, runs the same hooks without it.
		if ( 'wp-login.php' !== $pagenow ) {
			return $errors;
		}
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
		static $result = null;
		if ( null === $result ) {
			$result = $this->ask();
		}
		return $result;
	}

	/**
	 * One request to the provider.
	 *
	 * @return bool
	 */
	private function ask() {
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
		return self::verdict( json_decode( wp_remote_retrieve_body( $response ), true ) );
	}

	/**
	 * Whether a provider's answer lets the form through. Pure.
	 *
	 * Version 3 of reCAPTCHA adds a score from 0.0 (a bot) to 1.0 (a person); Google's
	 * own suggested threshold is used. The other providers send no score.
	 *
	 * @param mixed $data Decoded answer.
	 * @return bool
	 */
	public static function verdict( $data ) {
		if ( ! is_array( $data ) || empty( $data['success'] ) ) {
			return false;
		}
		return ! isset( $data['score'] ) || (float) $data['score'] >= 0.5;
	}
}
