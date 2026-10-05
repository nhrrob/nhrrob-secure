<?php
/**
 * Honeypot field on the registration and comment forms.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Services;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Core\Activity;
use NHRRob\Secure\Core\Settings;

/**
 * Adds a field that people never see and that programs filling in every
 * field of a form do fill in. A form that arrives with it filled in is
 * refused. No outside service and nothing for a visitor to do.
 */
class Honeypot {

	const FIELD = 'nhrrob_secure_hp';

	/**
	 * Register the hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		if ( ! Settings::get( 'honeypot' ) || Settings::safe_mode() ) {
			return;
		}
		foreach ( [ 'register_form', 'comment_form_after_fields', 'woocommerce_register_form' ] as $hook ) {
			add_action( $hook, [ $this, 'render' ] );
		}
		add_filter( 'registration_errors', [ $this, 'check_registration' ] );
		add_filter( 'woocommerce_process_registration_errors', [ $this, 'check_registration' ] );
		add_filter( 'preprocess_comment', [ $this, 'check_comment' ], 0 );
	}

	/**
	 * Print the field, moved off the screen and out of the tab order.
	 *
	 * @return void
	 */
	public function render() {
		printf(
			'<p style="position:absolute;left:-9999px;height:0;overflow:hidden" aria-hidden="true"><label>%s <input type="text" name="%s" value="" tabindex="-1" autocomplete="off"></label></p>',
			esc_html__( 'Leave this field empty', 'nhrrob-secure' ),
			esc_attr( self::FIELD )
		);
	}

	/**
	 * Whether the submitted form has the hidden field filled in.
	 *
	 * @return bool
	 */
	private static function caught() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- a visitor's form; only whether the trap field is empty is looked at.
		if ( empty( $_POST[ self::FIELD ] ) ) {
			return false;
		}
		Activity::record(
			'firewall',
			'honeypot',
			'',
			Activity::INFO,
			[
				'user'     => 0,
				'coalesce' => DAY_IN_SECONDS,
			]
		);
		return true;
	}

	/**
	 * Refuse a registration that filled the field in.
	 *
	 * @param \WP_Error $errors Form errors.
	 * @return \WP_Error
	 */
	public function check_registration( $errors ) {
		if ( $errors instanceof \WP_Error && self::caught() ) {
			$errors->add( 'nhrrob_secure_honeypot', __( 'Your registration could not be completed. Reload the page and try again.', 'nhrrob-secure' ) );
		}
		return $errors;
	}

	/**
	 * Refuse a comment that filled the field in.
	 *
	 * @param array $comment Comment data.
	 * @return array
	 */
	public function check_comment( $comment ) {
		if ( ! is_user_logged_in() && self::caught() ) {
			wp_die( esc_html__( 'Your comment could not be posted. Go back, reload the page and try again.', 'nhrrob-secure' ), '', [ 'response' => 403 ] );
		}
		return $comment;
	}
}
