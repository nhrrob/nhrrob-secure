<?php
/**
 * Stored scanner results.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Services;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * One non-autoloaded option (`nhrrob_secure_scan`) holding the last result of
 * each check, keyed by part.
 */
class Scan {

	const OPTION = 'nhrrob_secure_scan';

	/**
	 * Everything stored.
	 *
	 * @return array
	 */
	public static function all() {
		$data = get_option( self::OPTION, [] );
		return is_array( $data ) ? $data : [];
	}

	/**
	 * One part of the results.
	 *
	 * @param string $part Part key.
	 * @return mixed Null when the part has never been stored.
	 */
	public static function get( $part ) {
		$data = self::all();
		return isset( $data[ $part ] ) ? $data[ $part ] : null;
	}

	/**
	 * Store one part (null removes it).
	 *
	 * @param string $part  Part key.
	 * @param mixed  $value Value.
	 * @return void
	 */
	public static function set( $part, $value ) {
		$data = self::all();
		if ( null === $value ) {
			unset( $data[ $part ] );
		} else {
			$data[ $part ] = $value;
		}
		update_option( self::OPTION, $data, false );
	}
}
