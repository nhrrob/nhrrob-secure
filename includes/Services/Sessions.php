<?php
/**
 * Users, their sessions and the idle timeout.
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
 * Lists every user with their two-factor state and active sessions, ends
 * sessions, and signs out users who have been idle.
 */
class Sessions {

	const META_ACTIVITY = 'nhrrob_secure_last_activity';

	/**
	 * Register the idle-timeout hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		if ( (int) Settings::get( 'idle_timeout' ) <= 0 ) {
			return;
		}
		// Real page loads and REST calls count as activity; Heartbeat does not,
		// so a tab left open in the background still times out.
		add_action( 'admin_init', [ $this, 'tick' ] );
		add_filter( 'rest_pre_dispatch', [ $this, 'tick_rest' ] );
		add_filter( 'wp_login_errors', [ $this, 'idle_notice' ] );
	}

	/**
	 * REST variant of tick().
	 *
	 * @param mixed $result Dispatch result (passed through).
	 * @return mixed
	 */
	public function tick_rest( $result ) {
		$this->tick();
		return $result;
	}

	/**
	 * Sign the user out if they were idle too long; otherwise note the activity.
	 *
	 * @return void
	 */
	public function tick() {
		$user_id = get_current_user_id();
		if ( ! $user_id ) {
			return;
		}
		$now  = time();
		$last = (int) get_user_meta( $user_id, self::META_ACTIVITY, true );

		if ( $last && $now - $last > (int) Settings::get( 'idle_timeout' ) * MINUTE_IN_SECONDS ) {
			Activity::record( 'login', 'idle', '', Activity::INFO );
			delete_user_meta( $user_id, self::META_ACTIVITY );
			wp_destroy_current_session();
			wp_clear_auth_cookie();
			if ( wp_doing_ajax() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
				return;
			}
			wp_safe_redirect( add_query_arg( 'nhrrob_secure_idle', 1, wp_login_url() ) );
			exit;
		}

		if ( wp_doing_ajax() ) {
			return;
		}
		// One write a minute is enough to measure idleness in minutes.
		if ( $now - $last >= MINUTE_IN_SECONDS ) {
			update_user_meta( $user_id, self::META_ACTIVITY, $now );
		}
	}

	/**
	 * Explain an idle sign-out on the sign-in screen.
	 *
	 * @param \WP_Error $errors Sign-in screen messages.
	 * @return \WP_Error
	 */
	public function idle_notice( $errors ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- a flag that only selects a message.
		if ( isset( $_GET['nhrrob_secure_idle'] ) && $errors instanceof \WP_Error ) {
			$errors->add( 'nhrrob_secure_idle', __( 'You were signed out because you were idle. Sign in again to continue.', 'nhrrob-secure' ), 'message' );
		}
		return $errors;
	}

	/**
	 * A page of users for the app.
	 *
	 * @param array $args search, role, page.
	 * @return array { items: array, total: int }
	 */
	public static function users( array $args ) {
		$per_page = 20;
		$query    = new \WP_User_Query(
			[
				'number'      => $per_page,
				'offset'      => ( max( 1, (int) $args['page'] ) - 1 ) * $per_page,
				'search'      => '' !== $args['search'] ? '*' . $args['search'] . '*' : '',
				'role'        => $args['role'],
				'orderby'     => 'login',
				'count_total' => true,
			]
		);

		$now   = time();
		$items = [];
		foreach ( $query->get_results() as $user ) {
			$sessions = [];
			foreach ( \WP_Session_Tokens::get_instance( $user->ID )->get_all() as $session ) {
				if ( isset( $session['expiration'] ) && (int) $session['expiration'] < $now ) {
					continue;
				}
				$sessions[] = [
					'ip'    => isset( $session['ip'] ) ? $session['ip'] : '',
					'ua'    => isset( $session['ua'] ) ? $session['ua'] : '',
					'login' => isset( $session['login'] ) ? (int) $session['login'] : 0,
				];
			}
			$status  = TwoFactor::status( $user );
			$items[] = [
				'id'          => $user->ID,
				'login'       => $user->user_login,
				'email'       => $user->user_email,
				'roles'       => array_values( array_map( 'translate_user_role', array_intersect_key( wp_list_pluck( wp_roles()->roles, 'name' ), array_flip( (array) $user->roles ) ) ) ),
				'twofa'       => $status['enabled'] ? $status['method'] : '',
				'required'    => $status['required'],
				'due'         => $status['due'],
				'last_login'  => (int) get_user_meta( $user->ID, 'nhrrob_secure_last_login', true ),
				'sessions'    => $sessions,
				'must_change' => Passwords::user_must_change( $user ),
				'is_you'      => get_current_user_id() === $user->ID,
				'can_edit'    => current_user_can( 'edit_user', $user->ID ),
			];
		}

		return [
			'items' => $items,
			'total' => (int) $query->get_total(),
		];
	}

	/**
	 * End a user's sessions. For the current user their own session is kept.
	 *
	 * @param \WP_User $user User.
	 * @return void
	 */
	public static function sign_out( $user ) {
		$manager = \WP_Session_Tokens::get_instance( $user->ID );
		if ( get_current_user_id() === $user->ID ) {
			$manager->destroy_others( wp_get_session_token() );
		} else {
			$manager->destroy_all();
		}
		Activity::record( 'user', 'signout', $user->user_login, Activity::WARNING );
	}

	/**
	 * End every session on the site except the current one.
	 *
	 * @return void
	 */
	public static function sign_out_everyone() {
		$token   = wp_get_session_token();
		$manager = \WP_Session_Tokens::get_instance( get_current_user_id() );
		$session = $manager->get( $token );

		\WP_Session_Tokens::destroy_all_for_all_users();
		if ( $session ) {
			$manager->update( $token, $session );
		}
		Activity::record( 'user', 'signout', __( 'everyone else', 'nhrrob-secure' ), Activity::WARNING );
	}

	/**
	 * How many administrators there are, and how many use two-factor.
	 *
	 * @return array { total: int, with_2fa: int, without: string[] }
	 */
	public static function admin_coverage() {
		$admins  = get_users(
			[
				'role'   => 'administrator',
				'number' => 200,
				'fields' => [ 'ID', 'user_login' ],
			]
		);
		$without = [];
		foreach ( $admins as $admin ) {
			if ( ! TwoFactor::is_on( $admin->ID ) ) {
				$without[] = $admin->user_login;
			}
		}
		return [
			'total'    => count( $admins ),
			'with_2fa' => count( $admins ) - count( $without ),
			'without'  => $without,
		];
	}
}
