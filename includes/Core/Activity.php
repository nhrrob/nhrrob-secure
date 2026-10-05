<?php
/**
 * Activity log stored in one capped option.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Records security events without a database table.
 *
 * Rows live newest-first in the non-autoloaded option
 * `nhrrob_secure_activity`, capped by row count and by bytes. Repeated events
 * (a burst of blocked requests from one address) are folded into one row with
 * a counter, so an attack cannot grow the log or cost one write per request.
 */
class Activity {

	const OPTION    = 'nhrrob_secure_activity';
	const MAX_ROWS  = 1000;
	const MAX_BYTES = 262144;

	// Refused-request rows may take at most this many of the rows.
	const MAX_FIREWALL = 200;

	const INFO     = 1;
	const WARNING  = 2;
	const CRITICAL = 3;

	/**
	 * All stored rows, newest first.
	 *
	 * @return array
	 */
	public static function rows() {
		$rows = get_option( self::OPTION, [] );
		return is_array( $rows ) ? $rows : [];
	}

	/**
	 * Record an event.
	 *
	 * @param string $type     Event group: login, user, plugin, theme, core, setting, firewall, scan, option.
	 * @param string $action   Event within the group.
	 * @param string $label    What it happened to (username, plugin name, address…).
	 * @param int    $severity One of the severity constants.
	 * @param array  $args     Optional: 'user' (id), 'ip', 'detail' (short text), 'coalesce' (seconds).
	 * @return void
	 */
	public static function record( $type, $action, $label = '', $severity = self::INFO, array $args = [] ) {
		$now = time();
		$row = [
			't' => $now,
			'u' => isset( $args['user'] ) ? (int) $args['user'] : get_current_user_id(),
			'k' => (string) $type,
			'a' => (string) $action,
			'l' => self::clip( $label, 160 ),
			'i' => isset( $args['ip'] ) ? (string) $args['ip'] : Ip::client(),
			's' => (int) $severity,
			'n' => 1,
		];
		if ( ! empty( $args['detail'] ) ) {
			$row['d'] = self::clip( $args['detail'], 240 );
		}
		$window = empty( $args['coalesce'] ) ? 0 : (int) $args['coalesce'];

		// Under a flood, one write a minute per source is enough; the counter may run slightly low.
		// Checked on the cached copy first, so a refused request that changes nothing costs no write.
		if ( $window && 'firewall' === $row['k'] ) {
			$index = self::find( self::rows(), $row, $window, $now );
			if ( null !== $index && $now - self::rows()[ $index ]['t'] < MINUTE_IN_SECONDS && (int) self::rows()[ $index ]['n'] > 1 ) {
				return;
			}
		}

		Store::mutate(
			self::OPTION,
			function ( $rows ) use ( $row, $window, $now ) {
				// Fold a repeat of the same event into the existing row.
				$index = $window ? self::find( $rows, $row, $window, $now ) : null;
				if ( null !== $index ) {
					$row['n'] = (int) $rows[ $index ]['n'] + 1;
					$row['s'] = max( $row['s'], (int) $rows[ $index ]['s'] );
					unset( $rows[ $index ] );
				}
				array_unshift( $rows, $row );
				return self::trim( array_values( $rows ) );
			}
		);
	}

	/**
	 * Index of a recent row for the same event from the same address.
	 *
	 * @param array $rows   Rows, newest first.
	 * @param array $row    The new row.
	 * @param int   $window Seconds to look back.
	 * @param int   $now    Current time.
	 * @return int|null
	 */
	private static function find( array $rows, array $row, $window, $now ) {
		foreach ( $rows as $index => $old ) {
			if ( $now - $old['t'] > $window ) {
				break;
			}
			if ( $old['k'] === $row['k'] && $old['a'] === $row['a'] && $old['l'] === $row['l'] && $old['i'] === $row['i'] ) {
				return $index;
			}
		}
		return null;
	}

	/**
	 * Apply the retention period and the size caps.
	 *
	 * What goes first when the log is full is chosen so an attacker, or a busy
	 * shop, cannot push the important rows out: refused-request rows are kept
	 * to MAX_FIREWALL, then routine (info) rows go before warnings and
	 * criticals, oldest first.
	 *
	 * @param array $rows Rows, newest first.
	 * @return array
	 */
	public static function trim( array $rows ) {
		$cutoff = time() - DAY_IN_SECONDS * max( 1, (int) Settings::get( 'retention_days' ) );
		$count  = count( $rows );
		while ( $count && $rows[ $count - 1 ]['t'] < $cutoff ) {
			array_pop( $rows );
			--$count;
		}

		$firewall = 0;
		foreach ( $rows as $index => $row ) {
			if ( 'firewall' === $row['k'] && ++$firewall > self::MAX_FIREWALL ) {
				unset( $rows[ $index ] );
			}
		}
		$rows = self::drop_oldest( array_values( $rows ), count( $rows ) - self::MAX_ROWS );

		// The byte check is only worth doing once the log has some size.
		for ( $pass = 0; $pass < 20; $pass++ ) {
			if ( count( $rows ) <= 100 || strlen( maybe_serialize( $rows ) ) <= self::MAX_BYTES ) {
				break;
			}
			$rows = self::drop_oldest( $rows, 50 );
		}
		return $rows;
	}

	/**
	 * Remove a number of rows: the oldest routine rows first, then the oldest of the rest.
	 *
	 * @param array $rows   Rows, newest first.
	 * @param int   $excess How many to remove.
	 * @return array
	 */
	private static function drop_oldest( array $rows, $excess ) {
		if ( $excess <= 0 ) {
			return $rows;
		}
		for ( $index = count( $rows ) - 1; $index >= 0 && $excess > 0; $index-- ) {
			if ( (int) $rows[ $index ]['s'] <= self::INFO ) {
				unset( $rows[ $index ] );
				--$excess;
			}
		}
		$rows = array_values( $rows );
		return $excess > 0 ? array_slice( $rows, 0, count( $rows ) - $excess ) : $rows;
	}

	/**
	 * Store rows (never autoloaded).
	 *
	 * @param array $rows Rows.
	 * @return void
	 */
	public static function save( array $rows ) {
		update_option( self::OPTION, $rows, false );
	}

	/**
	 * Size of the log.
	 *
	 * @return array { rows: int, bytes: int }
	 */
	public static function stats() {
		$rows = self::rows();
		return [
			'rows'  => count( $rows ),
			'bytes' => strlen( maybe_serialize( $rows ) ),
		];
	}

	/**
	 * A filtered page of the log, ready for the app.
	 *
	 * @param array $args search, type, severity, page, per_page.
	 * @return array { items: array, total: int }
	 */
	public static function query( array $args = [] ) {
		$search   = isset( $args['search'] ) ? strtolower( trim( (string) $args['search'] ) ) : '';
		$type     = isset( $args['type'] ) ? (string) $args['type'] : '';
		$severity = isset( $args['severity'] ) ? (int) $args['severity'] : 0;
		$per_page = isset( $args['per_page'] ) ? max( 1, min( 1000, (int) $args['per_page'] ) ) : 20;
		$page     = isset( $args['page'] ) ? max( 1, (int) $args['page'] ) : 1;

		$items = [];
		foreach ( self::rows() as $row ) {
			if ( '' !== $type && $row['k'] !== $type ) {
				continue;
			}
			if ( $severity && (int) $row['s'] !== $severity ) {
				continue;
			}
			$item = self::present( $row );
			if ( '' !== $search && false === strpos( strtolower( $item['who'] . ' ' . $item['text'] . ' ' . $item['ip'] ), $search ) ) {
				continue;
			}
			$items[] = $item;
		}

		return [
			'total' => count( $items ),
			'items' => array_slice( $items, ( $page - 1 ) * $per_page, $per_page ),
		];
	}

	/**
	 * Turn a stored row into what the app shows.
	 *
	 * @param array $row Stored row.
	 * @return array
	 */
	public static function present( array $row ) {
		static $names = [];
		$uid          = (int) $row['u'];
		if ( $uid && ! isset( $names[ $uid ] ) ) {
			$user          = get_userdata( $uid );
			$names[ $uid ] = $user ? $user->user_login : __( 'Deleted user', 'nhrrob-secure' );
		}
		if ( $uid ) {
			$who = $names[ $uid ];
		} elseif ( 'login' === $row['k'] && in_array( $row['a'], [ 'success', 'logout' ], true ) && '' !== $row['l'] ) {
			// Rows copied from 1.x carry the username but no user id.
			$who = $row['l'];
		} else {
			$who = in_array( $row['k'], [ 'scan', 'core', 'plugin', 'theme' ], true ) ? __( 'System', 'nhrrob-secure' ) : __( 'Visitor', 'nhrrob-secure' );
		}

		return [
			'time'     => (int) $row['t'],
			'who'      => $who,
			'type'     => $row['k'],
			'text'     => self::describe( $row ),
			'ip'       => $row['i'],
			'severity' => (int) $row['s'],
		];
	}

	/**
	 * One plain sentence for an event.
	 *
	 * @param array $row Stored row.
	 * @return string
	 */
	public static function describe( array $row ) {
		$label  = $row['l'];
		$detail = isset( $row['d'] ) ? $row['d'] : '';
		$count  = (int) $row['n'];
		$key    = $row['k'] . ':' . $row['a'];

		switch ( $key ) {
			case 'login:success':
				$text = __( 'Signed in', 'nhrrob-secure' );
				break;
			case 'login:passkey':
				$text = __( 'Signed in with a passkey', 'nhrrob-secure' );
				break;
			case 'login:success_trusted':
				$text = __( 'Signed in on a trusted browser', 'nhrrob-secure' );
				break;
			case 'login:success_2fa':
				$text = __( 'Signed in with two-factor', 'nhrrob-secure' );
				break;
			case 'login:recovery':
				$text = __( 'Signed in with a recovery code', 'nhrrob-secure' );
				break;
			case 'login:logout':
				$text = __( 'Signed out', 'nhrrob-secure' );
				break;
			case 'login:failed':
				/* translators: %s: username that was tried. */
				$text = sprintf( __( 'Failed sign-in as "%s"', 'nhrrob-secure' ), $label );
				break;
			case 'login:lockout':
				/* translators: 1: number of failed attempts, 2: how long the address is locked out. */
				$text = sprintf( __( '%1$s failed sign-ins; address locked out for %2$s', 'nhrrob-secure' ), $label, $detail );
				break;
			case 'login:unlock':
				/* translators: %s: IP address. */
				$text = sprintf( __( 'Unlocked %s', 'nhrrob-secure' ), $label );
				break;
			case 'login:2fa_failed':
				/* translators: %s: username. */
				$text = '' !== $detail
					/* translators: 1: username, 2: how long the second step is paused. */
					? sprintf( __( 'Correct password but too many wrong two-factor codes for %1$s; second step paused for %2$s', 'nhrrob-secure' ), $label, $detail )
					/* translators: %s: username. */
					: sprintf( __( 'Too many wrong two-factor codes for %s', 'nhrrob-secure' ), $label );
				break;
			case 'login:idle':
				$text = __( 'Signed out after being idle', 'nhrrob-secure' );
				break;
			case 'user:created':
				if ( '' !== $detail ) {
					/* translators: 1: username, 2: role. */
					$text = sprintf( __( 'Created the user %1$s (%2$s)', 'nhrrob-secure' ), $label, $detail );
				} else {
					/* translators: %s: username. */
					$text = sprintf( __( 'Created the user %s', 'nhrrob-secure' ), $label );
				}
				break;
			case 'user:deleted':
				/* translators: %s: username. */
				$text = sprintf( __( 'Deleted the user %s', 'nhrrob-secure' ), $label );
				break;
			case 'user:role':
				if ( '' !== $detail ) {
					/* translators: 1: username, 2: old and new role. */
					$text = sprintf( __( 'Changed the role of %1$s: %2$s', 'nhrrob-secure' ), $label, $detail );
				} else {
					/* translators: %s: username. */
					$text = sprintf( __( 'Changed the role of %s', 'nhrrob-secure' ), $label );
				}
				break;
			case 'user:password':
				/* translators: %s: username. */
				$text = sprintf( __( 'Password changed for %s', 'nhrrob-secure' ), $label );
				break;
			case 'user:email':
				/* translators: %s: username. */
				$text = sprintf( __( 'Email address changed for %s', 'nhrrob-secure' ), $label );
				break;
			case 'user:2fa_on':
				/* translators: %s: username. */
				$text = sprintf( __( 'Two-factor turned on for %s', 'nhrrob-secure' ), $label );
				break;
			case 'user:2fa_off':
				/* translators: %s: username. */
				$text = sprintf( __( 'Two-factor turned off for %s', 'nhrrob-secure' ), $label );
				break;
			case 'user:force_password':
				/* translators: %s: username, role or "everyone". */
				$text = sprintf( __( 'Required a new password for %s', 'nhrrob-secure' ), $label );
				break;
			case 'user:signout':
				/* translators: %s: username. */
				$text = sprintf( __( 'Ended the sessions of %s', 'nhrrob-secure' ), $label );
				break;
			case 'plugin:activated':
			case 'plugin:deactivated':
			case 'plugin:installed':
			case 'plugin:updated':
			case 'plugin:deleted':
			case 'theme:installed':
			case 'theme:updated':
			case 'theme:deleted':
			case 'theme:switched':
				$sentences = [
					/* translators: %s: plugin name. */
					'plugin:activated'   => __( 'Activated the plugin %s', 'nhrrob-secure' ),
					/* translators: %s: plugin name. */
					'plugin:deactivated' => __( 'Deactivated the plugin %s', 'nhrrob-secure' ),
					/* translators: %s: plugin name. */
					'plugin:installed'   => __( 'Installed the plugin %s', 'nhrrob-secure' ),
					/* translators: %s: plugin name. */
					'plugin:updated'     => __( 'Updated the plugin %s', 'nhrrob-secure' ),
					/* translators: %s: plugin name. */
					'plugin:deleted'     => __( 'Deleted the plugin %s', 'nhrrob-secure' ),
					/* translators: %s: theme name. */
					'theme:installed'    => __( 'Installed the theme %s', 'nhrrob-secure' ),
					/* translators: %s: theme name. */
					'theme:updated'      => __( 'Updated the theme %s', 'nhrrob-secure' ),
					/* translators: %s: theme name. */
					'theme:deleted'      => __( 'Deleted the theme %s', 'nhrrob-secure' ),
					/* translators: %s: theme name. */
					'theme:switched'     => __( 'Switched to the theme %s', 'nhrrob-secure' ),
				];
				$text      = sprintf( $sentences[ $key ], $label );
				break;
			case 'core:updated':
				/* translators: %s: WordPress version. */
				$text = sprintf( __( 'WordPress updated to %s', 'nhrrob-secure' ), $label );
				break;
			case 'setting:changed':
				/* translators: %s: comma-separated setting names. */
				$text = sprintf( __( 'Secure settings changed: %s', 'nhrrob-secure' ), $label );
				break;
			case 'option:changed':
				/* translators: 1: option name, 2: old and new value. */
				$text = sprintf( __( 'Site setting "%1$s" changed: %2$s', 'nhrrob-secure' ), $label, $detail );
				break;
			case 'firewall:filter_block':
			case 'firewall:filter_log':
				$rules = \NHRRob\Secure\Services\Firewall::labels();
				$rule  = isset( $rules[ $label ] ) ? $rules[ $label ] : $label;
				$text  = 'firewall:filter_block' === $key
					/* translators: 1: rule name, 2: request path. */
					? sprintf( __( 'Blocked a request (%1$s): %2$s', 'nhrrob-secure' ), $rule, $detail )
					/* translators: 1: rule name, 2: request path. */
					: sprintf( __( 'Would have blocked a request (%1$s): %2$s', 'nhrrob-secure' ), $rule, $detail );
				break;
			case 'firewall:probe_lock':
				/* translators: 1: number of requests, 2: how long the address is locked out. */
				$text = sprintf( __( '%1$s requests for files that do not exist; address locked out of the site for %2$s', 'nhrrob-secure' ), $label, $detail );
				break;
			case 'firewall:probe_block':
				$text = __( 'Refused: address is locked out for probing', 'nhrrob-secure' );
				break;
			case 'firewall:ip_block':
				$text = __( 'Blocked by an address rule', 'nhrrob-secure' );
				break;
			case 'firewall:ua_block':
				/* translators: %s: matched user-agent fragment. */
				$text = sprintf( __( 'Blocked user agent "%s"', 'nhrrob-secure' ), $label );
				break;
			case 'firewall:country_block':
				/* translators: %s: two-letter country code. */
				$text = sprintf( __( 'Sign-in page refused for country %s', 'nhrrob-secure' ), $label );
				break;
			case 'scan:vulnerability':
				/* translators: %s: software name and version. */
				$text = sprintf( __( 'Vulnerability check: %s is affected', 'nhrrob-secure' ), $label );
				break;
			case 'scan:finding':
				/* translators: %s: what the scan found. */
				$text = sprintf( __( 'Scheduled scan: %s', 'nhrrob-secure' ), $label );
				break;
			case 'scan:quarantine':
				/* translators: %s: file path. */
				$text = sprintf( __( 'Quarantined %s', 'nhrrob-secure' ), $label );
				break;
			case 'scan:restore':
				/* translators: %s: file path. */
				$text = sprintf( __( 'Restored %s from quarantine', 'nhrrob-secure' ), $label );
				break;
			case 'scan:repair_plugin':
			case 'scan:repair_theme':
				/* translators: %s: file path. */
				$text = sprintf( __( 'Replaced %s with the copy from its WordPress.org release', 'nhrrob-secure' ), $label );
				break;
			case 'firewall:rate_limit':
				$text = __( 'Slowed down: too many requests in a minute', 'nhrrob-secure' );
				break;
			case 'firewall:honeypot':
				$text = __( 'Refused a form filled in by a bot', 'nhrrob-secure' );
				break;
			case 'setting:keys':
				$text = __( 'Replaced the secret keys in wp-config.php; everyone was signed out', 'nhrrob-secure' );
				break;
			case 'setting:permissions':
				/* translators: %s: file or folder name. */
				$text = sprintf( __( 'Removed "everyone may write" from %s', 'nhrrob-secure' ), $label );
				break;
			case 'user:expiry':
				/* translators: 1: username, 2: date. */
				$text = sprintf( __( 'Access of %1$s set to end on %2$s', 'nhrrob-secure' ), $label, $detail );
				break;
			case 'user:expiry_off':
				/* translators: %s: username. */
				$text = sprintf( __( 'Removed the end date of %s', 'nhrrob-secure' ), $label );
				break;
			case 'content:published':
			case 'content:updated':
			case 'content:trashed':
			case 'content:restored':
			case 'content:deleted':
				$sentences = [
					/* translators: 1: post type, 2: title. */
					'content:published' => __( 'Published the %1$s "%2$s"', 'nhrrob-secure' ),
					/* translators: 1: post type, 2: title. */
					'content:updated'   => __( 'Changed the %1$s "%2$s"', 'nhrrob-secure' ),
					/* translators: 1: post type, 2: title. */
					'content:trashed'   => __( 'Moved the %1$s "%2$s" to the trash', 'nhrrob-secure' ),
					/* translators: 1: post type, 2: title. */
					'content:restored'  => __( 'Restored the %1$s "%2$s" from the trash', 'nhrrob-secure' ),
					/* translators: 1: post type, 2: title. */
					'content:deleted'   => __( 'Deleted the %1$s "%2$s" for good', 'nhrrob-secure' ),
				];
				$text      = sprintf( $sentences[ $key ], $detail, $label );
				break;
			case 'content:media_added':
				$text = __( 'Uploaded a media file', 'nhrrob-secure' );
				break;
			case 'content:media_deleted':
				$text = __( 'Deleted a media file', 'nhrrob-secure' );
				break;
			case 'content:menu':
				/* translators: %s: menu name. */
				$text = sprintf( __( 'Changed the menu "%s"', 'nhrrob-secure' ), $label );
				break;
			case 'content:widgets':
				$text = __( 'Changed the widgets', 'nhrrob-secure' );
				break;
			case 'content:comment':
				/* translators: %s: new comment status. */
				$text = sprintf( __( 'Moderated a comment: %s', 'nhrrob-secure' ), $label );
				break;
			case 'content:order':
				/* translators: 1: order number, 2: old and new status. */
				$text = sprintf( __( 'Changed order %1$s: %2$s', 'nhrrob-secure' ), $label, $detail );
				break;
			case 'content:shop_settings':
				$text = __( 'Changed the shop settings', 'nhrrob-secure' );
				break;
			case 'scan:repair':
				/* translators: %s: file path. */
				$text = sprintf( __( 'Replaced %s with the official WordPress copy', 'nhrrob-secure' ), $label );
				break;
			default:
				$text = trim( $row['a'] . ' ' . $label );
		}

		/**
		 * Filter the sentence shown for an activity row.
		 *
		 * @param string $text Sentence.
		 * @param array  $row  Stored row.
		 */
		$text = (string) apply_filters( 'nhrrob_secure_activity_describe', $text, $row );

		if ( $count > 1 && 'login:lockout' !== $key ) {
			/* translators: 1: event sentence, 2: number of times it happened. */
			$text = sprintf( __( '%1$s (%2$d times)', 'nhrrob-secure' ), $text, $count );
		}
		return $text;
	}

	/**
	 * Shorten a value for storage.
	 *
	 * @param string $text Text.
	 * @param int    $max  Maximum length.
	 * @return string
	 */
	private static function clip( $text, $max ) {
		$text = wp_strip_all_tags( (string) $text, true );
		return strlen( $text ) > $max ? substr( $text, 0, $max - 1 ) . '…' : $text;
	}
}
