<?php
/**
 * Limit login attempts.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Services;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Core\Activity;
use NHRRob\Secure\Core\Alerts;
use NHRRob\Secure\Core\Ip;
use NHRRob\Secure\Core\Settings;
use NHRRob\Secure\Core\State;

/**
 * Counts failed sign-ins per address and locks an address out after too many.
 *
 * State is one capped part of the `nhrrob_secure_state` option, so a
 * failed sign-in costs one small write and an attack cannot fill the options
 * table. An address is locked when one username fails `login_attempts` times,
 * or when it has tried many different usernames.
 */
class LoginGuard {

	const MAX_ENTRIES = 300;
	const WINDOW      = HOUR_IN_SECONDS;
	const ERROR_CODE  = 'nhrrob_secure_locked';
	const PROBE_LIMIT = 10;

	/**
	 * Register the hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		if ( Settings::get( 'generic_login_errors' ) ) {
			add_filter( 'authenticate', [ $this, 'generic_error' ], 101 );
			add_filter( 'shake_error_codes', [ $this, 'shake_codes' ] );
		}
		if ( ! Settings::get( 'limit_login' ) || Settings::safe_mode() ) {
			return;
		}
		// After core's own checks (20–99): a locked address is refused even with the right password.
		add_filter( 'authenticate', [ $this, 'refuse_locked' ], 100 );
		add_action( 'wp_login_failed', [ $this, 'on_failed' ], 10, 2 );
		add_action( 'wp_login', [ $this, 'on_success' ] );
	}

	/**
	 * Stored entries keyed by address.
	 *
	 * Each entry: c = failures in the window, u = failures per username,
	 * l = last failure, x = locked until, v = lockout level.
	 *
	 * @return array
	 */
	public static function entries() {
		return State::get( 'lockouts' );
	}

	/**
	 * Refuse a sign-in from a locked address.
	 *
	 * @param mixed $user Result of earlier authenticate filters.
	 * @return mixed
	 */
	public function refuse_locked( $user ) {
		$left = self::locked_for( Ip::client() );
		if ( $left <= 0 ) {
			return $user;
		}
		return new \WP_Error(
			self::ERROR_CODE,
			sprintf(
				/* translators: %s: time left, e.g. "18 mins". */
				__( 'Too many failed sign-in attempts from your address. Try again in %s.', 'nhrrob-secure' ),
				human_time_diff( time(), time() + $left )
			)
		);
	}

	/**
	 * Seconds an address stays locked (0 when it is not).
	 *
	 * @param string $ip Address.
	 * @return int
	 */
	public static function locked_for( $ip ) {
		$entries = self::entries();
		if ( empty( $entries[ $ip ]['x'] ) ) {
			return 0;
		}
		return max( 0, (int) $entries[ $ip ]['x'] - time() );
	}

	/**
	 * Count a failed sign-in.
	 *
	 * @param string         $username Username that was tried.
	 * @param \WP_Error|null $error    Why it failed (WordPress 5.4+).
	 * @return void
	 */
	public function on_failed( $username, $error = null ) {
		// A refusal of an already locked address is not a new attempt.
		if ( is_wp_error( $error ) && self::ERROR_CODE === $error->get_error_code() ) {
			return;
		}
		self::register_failure( (string) $username );
	}

	/**
	 * Count a failure for the current visitor and lock the address if needed.
	 *
	 * @param string $username Username that was tried.
	 * @return void
	 */
	public static function register_failure( $username ) {
		$ip = Ip::client();
		if ( 'allow' === Ip::rule_for( $ip ) ) {
			return;
		}

		$now     = time();
		$entries = self::entries();
		$entry   = isset( $entries[ $ip ] ) ? $entries[ $ip ] : [
			'c' => 0,
			'u' => [],
			'l' => 0,
			'x' => 0,
			'v' => 0,
		];
		$result  = self::count_failure( $entry, strtolower( sanitize_user( $username, true ) ), $now, self::policy() );
		$entry   = $result['entry'];

		$entries[ $ip ] = $entry;
		State::set( 'lockouts', self::prune( $entries, $now ) );

		if ( $result['locked'] ) {
			$duration = human_time_diff( $now, (int) $entry['x'] );
			Activity::record(
				'login',
				'lockout',
				(string) $entry['c'],
				Activity::WARNING,
				[
					'user'   => 0,
					'detail' => $duration,
				]
			);
			self::notify( $ip, $entry, $duration, $entries );
		} elseif ( 1 === (int) $entry['c'] ) {
			// Only the first failure in a window gets its own row; the rest show up in the lockout.
			Activity::record( 'login', 'failed', $username, Activity::WARNING, [ 'user' => 0 ] );
		}
	}

	/**
	 * Count a request that probed for a file which does not exist. Ten within
	 * ten minutes lock the address out of the whole site.
	 *
	 * @return void
	 */
	public static function register_probe() {
		$ip = Ip::client();
		if ( 'allow' === Ip::rule_for( $ip ) ) {
			return;
		}
		$now     = time();
		$entries = self::entries();
		$entry   = isset( $entries[ $ip ] ) ? $entries[ $ip ] : [
			'c' => 0,
			'u' => [],
			'l' => 0,
			'x' => 0,
			'v' => 0,
		];
		$result  = self::count_probe( $entry, $now );

		$entries[ $ip ] = $result['entry'];
		State::set( 'lockouts', self::prune( $entries, $now ) );

		if ( $result['locked'] ) {
			Activity::record(
				'firewall',
				'probe_lock',
				(string) self::PROBE_LIMIT,
				Activity::WARNING,
				[
					'user'   => 0,
					'detail' => human_time_diff( $now, (int) $result['entry']['x'] ),
				]
			);
		}
	}

	/**
	 * Pure counting step for probes.
	 *
	 * @param array $entry Current entry for the address.
	 * @param int   $now   Current time.
	 * @return array { entry: array, locked: bool }
	 */
	public static function count_probe( array $entry, $now ) {
		$last  = isset( $entry['ql'] ) ? (int) $entry['ql'] : 0;
		$count = $now - $last > 10 * MINUTE_IN_SECONDS ? 0 : ( isset( $entry['q'] ) ? (int) $entry['q'] : 0 );

		$entry['q']  = $count + 1;
		$entry['ql'] = $now;
		$entry['l']  = $now;
		$locked      = $entry['q'] >= self::PROBE_LIMIT;
		if ( $locked ) {
			$entry['x'] = $now + HOUR_IN_SECONDS * min( 24, pow( 2, (int) $entry['v'] ) );
			$entry['v'] = (int) $entry['v'] + 1;
			$entry['p'] = 1;
			$entry['q'] = 0;
		}
		return [
			'entry'  => $entry,
			'locked' => $locked,
		];
	}

	/**
	 * Whether an address is locked out of the whole site for probing.
	 *
	 * @param string $ip Address.
	 * @return bool
	 */
	public static function probe_locked( $ip ) {
		$entries = self::entries();
		return ! empty( $entries[ $ip ]['p'] ) && (int) $entries[ $ip ]['x'] > time();
	}

	/**
	 * The lockout rules from settings.
	 *
	 * @return array
	 */
	public static function policy() {
		return [
			'limit'       => max( 1, (int) Settings::get( 'login_attempts' ) ),
			'minutes'     => max( 1, (int) Settings::get( 'lockout_minutes' ) ),
			'progressive' => (bool) Settings::get( 'lockout_progressive' ),
		];
	}

	/**
	 * Pure counting step, so the rules can be unit tested.
	 *
	 * @param array  $entry    Current entry for the address.
	 * @param string $username Normalized username.
	 * @param int    $now      Current time.
	 * @param array  $policy   limit, minutes, progressive.
	 * @return array { entry: array, locked: bool }
	 */
	public static function count_failure( array $entry, $username, $now, array $policy ) {
		// A quiet hour forgives earlier failures; a quiet day forgives earlier lockouts.
		if ( $now - (int) $entry['l'] > self::WINDOW ) {
			$entry['c'] = 0;
			$entry['u'] = [];
		}
		if ( $now - (int) $entry['l'] > DAY_IN_SECONDS ) {
			$entry['v'] = 0;
		}

		++$entry['c'];
		$entry['l'] = $now;
		if ( '' !== $username && ( isset( $entry['u'][ $username ] ) || count( $entry['u'] ) < 10 ) ) {
			$entry['u'][ $username ] = isset( $entry['u'][ $username ] ) ? $entry['u'][ $username ] + 1 : 1;
		}

		$per_user = '' !== $username && isset( $entry['u'][ $username ] ) ? $entry['u'][ $username ] : 0;
		$locked   = $per_user >= $policy['limit'] || $entry['c'] >= $policy['limit'] * 3;

		if ( $locked ) {
			$minutes = $policy['minutes'];
			if ( $policy['progressive'] ) {
				$minutes = min( 1440, $minutes * pow( 2, (int) $entry['v'] ) );
			}
			$entry['x'] = $now + (int) $minutes * MINUTE_IN_SECONDS;
			$entry['v'] = (int) $entry['v'] + 1;
			unset( $entry['p'] );
		}

		return [
			'entry'  => $entry,
			'locked' => $locked,
		];
	}

	/**
	 * Drop entries that no longer matter and enforce the cap.
	 *
	 * @param array $entries Entries keyed by address.
	 * @param int   $now     Current time.
	 * @return array
	 */
	public static function prune( array $entries, $now ) {
		foreach ( $entries as $ip => $entry ) {
			if ( (int) $entry['x'] < $now && $now - (int) $entry['l'] > DAY_IN_SECONDS ) {
				unset( $entries[ $ip ] );
			}
		}
		if ( count( $entries ) > self::MAX_ENTRIES ) {
			uasort(
				$entries,
				function ( $a, $b ) {
					return (int) $b['l'] - (int) $a['l'];
				}
			);
			$entries = array_slice( $entries, 0, self::MAX_ENTRIES, true );
		}
		return $entries;
	}

	/**
	 * A successful sign-in clears that address's failures.
	 *
	 * @return void
	 */
	public function on_success() {
		$ip      = Ip::client();
		$entries = self::entries();
		if ( isset( $entries[ $ip ] ) ) {
			unset( $entries[ $ip ] );
			State::set( 'lockouts', $entries );
		}
	}

	/**
	 * Addresses locked out right now, for the app.
	 *
	 * @return array
	 */
	public static function locked() {
		$now = time();
		$out = [];
		foreach ( self::entries() as $ip => $entry ) {
			if ( (int) $entry['x'] > $now ) {
				$out[] = [
					'ip'       => (string) $ip,
					'users'    => array_keys( (array) $entry['u'] ),
					'attempts' => (int) $entry['c'],
					'probing'  => ! empty( $entry['p'] ),
					'until'    => (int) $entry['x'],
				];
			}
		}
		usort(
			$out,
			function ( $a, $b ) {
				return $b['until'] - $a['until'];
			}
		);
		return $out;
	}

	/**
	 * How many lockouts started in the last 24 hours.
	 *
	 * @return int
	 */
	public static function recent_count() {
		$count = 0;
		foreach ( self::entries() as $entry ) {
			if ( (int) $entry['x'] && time() - (int) $entry['l'] < DAY_IN_SECONDS ) {
				++$count;
			}
		}
		return $count;
	}

	/**
	 * Unlock one address, or all of them.
	 *
	 * @param string $ip Address, or '' for all.
	 * @return int Number of addresses unlocked.
	 */
	public static function unlock( $ip = '' ) {
		$entries = self::entries();
		$count   = 0;
		foreach ( array_keys( $entries ) as $key ) {
			if ( '' === $ip || (string) $key === $ip ) {
				unset( $entries[ $key ] );
				++$count;
			}
		}
		if ( $count ) {
			State::set( 'lockouts', $entries );
		}
		return $count;
	}

	/**
	 * Replace the specific sign-in errors with one that does not say which
	 * part was wrong.
	 *
	 * @param mixed $user Result of earlier authenticate filters.
	 * @return mixed
	 */
	public function generic_error( $user ) {
		if ( is_wp_error( $user ) && in_array( $user->get_error_code(), [ 'invalid_username', 'incorrect_password', 'invalid_email' ], true ) ) {
			return new \WP_Error( 'nhrrob_secure_invalid', __( 'The username or password is incorrect.', 'nhrrob-secure' ) );
		}
		return $user;
	}

	/**
	 * Keep the login form's shake for our error codes.
	 *
	 * @param string[] $codes Error codes.
	 * @return string[]
	 */
	public function shake_codes( $codes ) {
		$codes[] = 'nhrrob_secure_invalid';
		$codes[] = self::ERROR_CODE;
		return $codes;
	}

	/**
	 * Email the owner about a lockout, if they asked for it.
	 *
	 * @param string $ip       Locked address.
	 * @param array  $entry    Its entry.
	 * @param string $duration Readable lockout length.
	 * @param array  $entries  All entries (to spot a burst).
	 * @return void
	 */
	private static function notify( $ip, array $entry, $duration, array $entries ) {
		$lines = [
			/* translators: 1: IP address, 2: number of attempts, 3: lockout length. */
			sprintf( __( '%1$s was locked out for %3$s after %2$d failed sign-in attempts.', 'nhrrob-secure' ), $ip, (int) $entry['c'], $duration ),
			/* translators: %s: comma-separated usernames. */
			sprintf( __( 'Usernames tried: %s', 'nhrrob-secure' ), implode( ', ', array_keys( (array) $entry['u'] ) ) ),
		];

		if ( Settings::get( 'lockout_email' ) ) {
			Alerts::send( __( 'An address was locked out', 'nhrrob-secure' ), $lines, 'lockout', 15 * MINUTE_IN_SECONDS );
			return;
		}
		if ( Settings::get( 'alert_lockouts' ) ) {
			$recent = 0;
			foreach ( $entries as $other ) {
				if ( (int) $other['x'] && time() - (int) $other['l'] < HOUR_IN_SECONDS ) {
					++$recent;
				}
			}
			if ( $recent >= 5 ) {
				/* translators: %d: number of addresses. */
				array_unshift( $lines, sprintf( __( '%d addresses were locked out in the last hour. The most recent:', 'nhrrob-secure' ), $recent ) );
				Alerts::send( __( 'A burst of lockouts', 'nhrrob-secure' ), $lines, 'lockout_burst', HOUR_IN_SECONDS );
			}
		}
	}
}
