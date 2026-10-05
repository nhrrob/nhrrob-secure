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
 * results are large and written rarely. Every change goes through
 * Store::mutate(), so parallel requests cannot undo each other's counts.
 */
class State {

	const OPTION = 'nhrrob_secure_state';

	/**
	 * One part of the state.
	 *
	 * @param string $part Part key: lockouts | filter_log | blocked | denied.
	 * @return array
	 */
	public static function get( $part ) {
		$data = get_option( self::OPTION, [] );
		return is_array( $data ) && isset( $data[ $part ] ) && is_array( $data[ $part ] ) ? $data[ $part ] : [];
	}

	/**
	 * Change several parts in one write.
	 *
	 * @param callable $change Receives the whole state array, returns the new one.
	 * @return array The stored state.
	 */
	public static function mutate( callable $change ) {
		return Store::mutate(
			self::OPTION,
			function ( $data ) use ( $change ) {
				// Empty parts are dropped so the option stays as small as it can be.
				return array_filter( (array) $change( $data ) );
			}
		);
	}

	/**
	 * Change one part.
	 *
	 * @param string   $part   Part key.
	 * @param callable $change Receives the part's array, returns the new one.
	 * @return array The stored part.
	 */
	public static function mutate_part( $part, callable $change ) {
		$data = self::mutate(
			function ( $data ) use ( $part, $change ) {
				$data[ $part ] = (array) $change( isset( $data[ $part ] ) && is_array( $data[ $part ] ) ? $data[ $part ] : [] );
				return $data;
			}
		);
		return isset( $data[ $part ] ) ? $data[ $part ] : [];
	}

	/**
	 * Replace one part.
	 *
	 * @param string $part  Part key.
	 * @param array  $value Value.
	 * @return void
	 */
	public static function set( $part, array $value ) {
		self::mutate_part(
			$part,
			function () use ( $value ) {
				return $value;
			}
		);
	}
}
