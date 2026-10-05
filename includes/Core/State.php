<?php
/**
 * Small, frequently written working state.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * One non-autoloaded option (`nhrrob_secure_state`) for the data that
 * changes while the site is under attack: lockouts, the request-filter log
 * and the refused-requests counter.
 *
 * It is kept apart from the scan results on purpose. A failed sign-in or a
 * refused request rewrites this option, so it has to stay small; scan
 * results are large and written rarely.
 */
class State {

	const OPTION = 'nhrrob_secure_state';

	/**
	 * Everything stored.
	 *
	 * @return array
	 */
	private static function all() {
		$data = get_option( self::OPTION, [] );
		return is_array( $data ) ? $data : [];
	}

	/**
	 * One part of the state.
	 *
	 * @param string $part Part key: lockouts | filter_log | blocked.
	 * @return array
	 */
	public static function get( $part ) {
		$data = self::all();
		return isset( $data[ $part ] ) && is_array( $data[ $part ] ) ? $data[ $part ] : [];
	}

	/**
	 * Store one part.
	 *
	 * @param string $part  Part key.
	 * @param array  $value Value.
	 * @return void
	 */
	public static function set( $part, array $value ) {
		$data = self::all();
		if ( $value ) {
			$data[ $part ] = $value;
		} else {
			unset( $data[ $part ] );
		}
		update_option( self::OPTION, $data, false );
	}
}
