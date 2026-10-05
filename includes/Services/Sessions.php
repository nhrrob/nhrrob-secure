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
		if ( (int) Settings::get( 'max_sessions' ) > 0 ) {
			add_action( 'set_logged_in_cookie', [ $this, 'limit_sessions' ], 10, 6 );
		}
		if ( (int) Settings::get( 'idle_timeout' ) <= 0 ) {
			return;
		}
		// Real page loads (dashboard or site) and REST calls count as activity;
		// Heartbeat does not, so a tab left open in the background still times out.
		add_action( 'admin_init', [ $this, 'tick' ] );
		add_action( 'template_redirect', [ $this, 'tick' ] );
		add_filter( 'rest_pre_dispatch', [ $this, 'tick_rest' ] );
		add_filter( 'wp_login_errors', [ $this, 'idle_notice' ] );
	}

	/**
	 * The newest sessions of a user, up to a limit. Pure.
	 *
	 * Sessions that started in the same second are told apart by their place
	 * in the list (WordPress appends), and the session named in $keep always
	 * stays: it is the one that was just created.
	 *
	 * @param array  $sessions Session list: token hash => session.
	 * @param int    $max      How many to keep.
	 * @param string $keep     Token hash that must stay ('' for none).
	 * @return array
	 */
	public static function newest( array $sessions, $max, $keep = '' ) {
		$order = [];
		$place = 0;
		foreach ( $sessions as $hash => $session ) {
			$order[ $hash ] = [ (string) $hash === (string) $keep ? PHP_INT_MAX : ( isset( $session['login'] ) ? (int) $session['login'] : 0 ), ++$place ];
		}
		uasort(
			$order,
			function ( $a, $b ) {
				return $a[0] === $b[0] ? $b[1] - $a[1] : ( $b[0] > $a[0] ? 1 : -1 );
			}
		);
		return array_intersect_key( $sessions, array_slice( $order, 0, max( 1, (int) $max ), true ) );
	}

	/**
	 * A new session was just created: end the oldest ones beyond the limit.
	 * The new sign-in is never the one refused, so a lost device cannot keep
	 * its owner out.
	 *
	 * @param string $cookie     Cookie value (unused).
	 * @param int    $expire     Cookie expiry (unused).
	 * @param int    $expiration Session expiry (unused).
	 * @param int    $user_id    User id.
	 * @param string $scheme     Cookie scheme (unused).
	 * @param string $token      The new session's token.
	 * @return void
	 */
	public function limit_sessions( $cookie, $expire, $expiration, $user_id, $scheme = '', $token = '' ) {
		// Only WordPress's own session store keeps the list where it can be trimmed.
		if ( ! \WP_Session_Tokens::get_instance( $user_id ) instanceof \WP_User_Meta_Session_Tokens ) {
			return;
		}
		$sessions = get_user_meta( $user_id, 'session_tokens', true );
		$max      = (int) Settings::get( 'max_sessions' );
		if ( is_array( $sessions ) && count( $sessions ) > $max ) {
			// WordPress stores a session under the SHA-256 of its token.
			update_user_meta( $user_id, 'session_tokens', self::newest( $sessions, $max, hash( 'sha256', (string) $token ) ) );
		}
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
		// The timeout protects accounts that can work in the dashboard. Customers and
		// subscribers are left alone: signing a shopper out mid-visit helps nobody.
		if ( ! $user_id || ! current_user_can( 'edit_posts' ) ) {
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
				'expires'     => Access::expires( $user->ID ),
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
