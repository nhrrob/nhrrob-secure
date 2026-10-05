<?php
/**
 * Password expiry and forced password changes.
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
 * Makes a user choose a new password: because theirs is older than the
 * owner's limit (administrators and editors), or because the owner asked for
 * it — for one user, a role, or everyone.
 *
 * A user who must change is kept on their profile screen in wp-admin until
 * they have. Accounts that never open wp-admin are not interrupted.
 */
class Passwords {

	const META_CHANGED = 'nhrrob_secure_pw_changed';
	const META_MUST    = 'nhrrob_secure_pw_must';

	/**
	 * Register the hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		add_action( 'profile_update', [ $this, 'on_profile_update' ], 10, 2 );
		add_action( 'after_password_reset', [ $this, 'mark_changed' ] );
		add_action( 'user_register', [ $this, 'mark_changed' ] );
		if ( ! Settings::safe_mode() ) {
			add_action( 'admin_init', [ $this, 'enforce' ] );
		}
	}

	/**
	 * Note a password change made on a profile screen.
	 *
	 * @param int      $user_id  User id.
	 * @param \WP_User $old_user User before the update.
	 * @return void
	 */
	public function on_profile_update( $user_id, $old_user ) {
		$user = get_userdata( $user_id );
		if ( $user && $old_user instanceof \WP_User && $user->user_pass !== $old_user->user_pass ) {
			$this->mark_changed( $user );
		}
	}

	/**
	 * Record that a user has a new password.
	 *
	 * @param \WP_User|int $user User or id.
	 * @return void
	 */
	public function mark_changed( $user ) {
		$user_id = $user instanceof \WP_User ? $user->ID : (int) $user;
		if ( $user_id ) {
			update_user_meta( $user_id, self::META_CHANGED, time() );
			delete_user_meta( $user_id, self::META_MUST );
			// A new password also ends "don't ask again on this browser".
			delete_user_meta( $user_id, TwoFactor::META_TRUSTED );
		}
	}

	/**
	 * Pure decision: must this password be changed?
	 *
	 * @param int      $changed    When the password was last changed.
	 * @param bool     $flagged    Whether this user was asked individually.
	 * @param string[] $roles      The user's roles.
	 * @param array    $force      Forced-change times by role ('*' for everyone).
	 * @param int      $expiry     Days until a password expires (0 = never).
	 * @param bool     $privileged Whether the expiry applies to this user.
	 * @param int      $now        Current time.
	 * @return bool
	 */
	public static function must_change( $changed, $flagged, array $roles, array $force, $expiry, $privileged, $now ) {
		if ( $flagged ) {
			return true;
		}
		foreach ( array_merge( [ '*' ], $roles ) as $role ) {
			if ( isset( $force[ $role ] ) && $changed < (int) $force[ $role ] ) {
				return true;
			}
		}
		return $expiry > 0 && $privileged && $now - $changed > $expiry * DAY_IN_SECONDS;
	}

	/**
	 * Whether a user currently has to choose a new password.
	 *
	 * @param \WP_User $user User.
	 * @return bool
	 */
	public static function user_must_change( $user ) {
		$changed = (int) get_user_meta( $user->ID, self::META_CHANGED, true );
		if ( ! $changed ) {
			// First sight of this account: the clock starts now, so switching expiry on does not expire everyone at once.
			$changed = time();
			update_user_meta( $user->ID, self::META_CHANGED, $changed );
		}
		return self::must_change(
			$changed,
			(bool) get_user_meta( $user->ID, self::META_MUST, true ),
			(array) $user->roles,
			(array) Settings::get( 'password_force' ),
			(int) Settings::get( 'password_expiry_days' ),
			$user->has_cap( 'manage_options' ) || $user->has_cap( 'edit_others_posts' ),
			time()
		);
	}

	/**
	 * Keep a user who must change their password on their profile screen.
	 *
	 * @return void
	 */
	public function enforce() {
		global $pagenow;
		$user = wp_get_current_user();
		if ( ! $user->exists() || wp_doing_ajax() || ! self::user_must_change( $user ) ) {
			return;
		}
		add_action(
			'admin_notices',
			function () {
				echo '<div class="notice notice-error"><p><strong>' . esc_html__( 'Choose a new password.', 'nhrrob-secure' ) . '</strong> ' . esc_html__( 'Your password has to be changed before you can use the dashboard. Use "Set New Password" below, then "Update Profile".', 'nhrrob-secure' ) . '</p></div>';
			}
		);
		if ( 'profile.php' !== $pagenow ) {
			wp_safe_redirect( admin_url( 'profile.php#password' ) );
			exit;
		}
	}

	/**
	 * Ask one user to choose a new password.
	 *
	 * @param \WP_User $user User.
	 * @return void
	 */
	public static function force_user( $user ) {
		update_user_meta( $user->ID, self::META_MUST, 1 );
		Activity::record( 'user', 'force_password', $user->user_login, Activity::WARNING );
	}

	/**
	 * Ask a role, or everyone ('*'), to choose a new password. Stored as one
	 * timestamp per scope, so no user rows are touched.
	 *
	 * @param string $scope Role key, or '*'.
	 * @return bool
	 */
	public static function force_scope( $scope ) {
		if ( '*' !== $scope && ! isset( wp_roles()->roles[ $scope ] ) ) {
			return false;
		}
		$force           = (array) Settings::get( 'password_force' );
		$force[ $scope ] = time();
		Settings::set_raw( 'password_force', $force );
		// The person asking keeps working; their own clock restarts.
		update_user_meta( get_current_user_id(), self::META_CHANGED, time() + 1 );
		Activity::record( 'user', 'force_password', '*' === $scope ? __( 'everyone', 'nhrrob-secure' ) : translate_user_role( wp_roles()->roles[ $scope ]['name'] ), Activity::WARNING );
		return true;
	}
}
