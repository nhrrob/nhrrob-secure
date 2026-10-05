<?php
/**
 * Temporary access and sign-in notifications.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Services;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Core\Activity;
use NHRRob\Secure\Core\Ip;
use NHRRob\Secure\Core\Settings;

/**
 * Two things about who gets in:
 *
 * - An account can be given an end date (support staff, a contractor). After
 *   it the account cannot sign in, its sessions end and its application
 *   passwords stop working. Nothing is deleted.
 * - A user who can edit the site is emailed when their account signs in on a
 *   browser it has not used before. A cookie marks a known browser, so a new
 *   address or a browser update does not cause mail.
 */
class Access {

	const META_EXPIRES = 'nhrrob_secure_expires';
	const META_KNOWN   = 'nhrrob_secure_known';

	/**
	 * Register the hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		// After core has checked the password (20–30) and before the two-factor step (50).
		add_filter( 'authenticate', [ $this, 'refuse_expired' ], 40 );
		add_action( 'init', [ $this, 'end_expired' ], 1 );
		add_filter( 'wp_is_application_passwords_available_for_user', [ $this, 'app_passwords' ], 10, 2 );
		if ( Settings::get( 'login_notify' ) ) {
			add_action( 'wp_login', [ $this, 'notify' ], 20, 2 );
		}
	}

	// ---- Temporary access. ----

	/**
	 * When a user's access ends (0 for never).
	 *
	 * @param int $user_id User id.
	 * @return int Unix time.
	 */
	public static function expires( $user_id ) {
		return (int) get_user_meta( $user_id, self::META_EXPIRES, true );
	}

	/**
	 * Whether an end date has passed. Pure.
	 *
	 * @param int $expires End date (0 for none).
	 * @param int $now     Current time.
	 * @return bool
	 */
	public static function is_over( $expires, $now ) {
		return $expires > 0 && $expires <= $now;
	}

	/**
	 * Give an account an end date, or take it away.
	 *
	 * @param \WP_User $user User.
	 * @param int      $days Days from now; 0 removes the end date.
	 * @return int The new end date (0 for none).
	 */
	public static function set_expiry( $user, $days ) {
		$days = max( 0, min( 365, (int) $days ) );
		if ( 0 === $days ) {
			delete_user_meta( $user->ID, self::META_EXPIRES );
			Activity::record( 'user', 'expiry_off', $user->user_login, Activity::WARNING );
			return 0;
		}
		$until = time() + $days * DAY_IN_SECONDS;
		update_user_meta( $user->ID, self::META_EXPIRES, $until );
		Activity::record( 'user', 'expiry', $user->user_login, Activity::WARNING, [ 'detail' => wp_date( get_option( 'date_format' ), $until ) ] );
		return $until;
	}

	/**
	 * Refuse a correct password for an account whose access has ended.
	 *
	 * @param mixed $user Result of earlier authenticate filters.
	 * @return mixed
	 */
	public function refuse_expired( $user ) {
		if ( $user instanceof \WP_User && self::is_over( self::expires( $user->ID ), time() ) ) {
			return new \WP_Error( 'nhrrob_secure_expired', __( 'Access for this account has ended. Ask an administrator of the site to extend it.', 'nhrrob-secure' ) );
		}
		return $user;
	}

	/**
	 * End the sessions of a signed-in user whose access has just run out.
	 *
	 * @return void
	 */
	public function end_expired() {
		$user_id = get_current_user_id();
		if ( ! $user_id || ! self::is_over( self::expires( $user_id ), time() ) ) {
			return;
		}
		\WP_Session_Tokens::get_instance( $user_id )->destroy_all();
		wp_clear_auth_cookie();
		wp_set_current_user( 0 );
	}

	/**
	 * No application passwords for an account whose access has ended.
	 *
	 * @param bool     $available Whether they are available.
	 * @param \WP_User $user      User.
	 * @return bool
	 */
	public function app_passwords( $available, $user ) {
		return $user instanceof \WP_User && self::is_over( self::expires( $user->ID ), time() ) ? false : $available;
	}

	// ---- Sign-in notifications. ----

	/**
	 * Name of the cookie that marks a browser the account has used.
	 *
	 * @return string
	 */
	private static function cookie() {
		return 'nhrrob_secure_known_' . COOKIEHASH;
	}

	/**
	 * After a sign-in: mark the browser as known, and email the user when it was not.
	 *
	 * @param string   $login Username.
	 * @param \WP_User $user  User.
	 * @return void
	 */
	public function notify( $login, $user ) {
		if ( ! $user instanceof \WP_User || ! $user->has_cap( 'edit_posts' ) ) {
			return;
		}
		$stored = get_user_meta( $user->ID, self::META_KNOWN, true );
		$known  = is_array( $stored ) ? $stored : [];
		$name   = self::cookie();
		$parts  = isset( $_COOKIE[ $name ] ) ? explode( '|', sanitize_text_field( wp_unslash( $_COOKIE[ $name ] ) ), 2 ) : [];
		if ( 2 === count( $parts ) && (int) $parts[0] === (int) $user->ID && in_array( hash( 'sha256', $parts[1] ), $known, true ) ) {
			return;
		}

		$token   = wp_generate_password( 40, false );
		$known[] = hash( 'sha256', $token );
		// Ten browsers per account is plenty; the oldest go first.
		update_user_meta( $user->ID, self::META_KNOWN, array_slice( $known, -10 ) );
		if ( ! headers_sent() ) {
			setcookie( $name, $user->ID . '|' . $token, time() + YEAR_IN_SECONDS, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true );
		}

		// The first sign-in after the feature is switched on only teaches it the browser.
		if ( ! is_array( $stored ) ) {
			return;
		}
		$agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 160 ) : '';
		wp_mail(
			$user->user_email,
			/* translators: %s: site name. */
			sprintf( __( '[%s] New sign-in to your account', 'nhrrob-secure' ), wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ),
			implode(
				"\n",
				[
					/* translators: %s: username. */
					sprintf( __( 'Your account %s was just signed in to on a browser it has not used before.', 'nhrrob-secure' ), $user->user_login ),
					'',
					/* translators: %s: date and time. */
					sprintf( __( 'When: %s', 'nhrrob-secure' ), wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) ) ),
					/* translators: %s: IP address. */
					sprintf( __( 'Address: %s', 'nhrrob-secure' ), Ip::client() ),
					/* translators: %s: browser user agent. */
					sprintf( __( 'Browser: %s', 'nhrrob-secure' ), $agent ),
					'',
					__( 'If this was you, there is nothing to do. If it was not, change your password now:', 'nhrrob-secure' ),
					wp_lostpassword_url(),
				]
			)
		);
	}
}
