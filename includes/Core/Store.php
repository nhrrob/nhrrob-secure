<?php
/**
 * Safe read-modify-write for an option.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Changes an option without losing a change made by a request running at the
 * same moment.
 *
 * A counter kept in an option is read, changed and written back. Two failed
 * sign-ins handled in parallel would both read "3" and both write "4", so a
 * burst of parallel guesses could stay under the lockout limit. Here the write
 * only succeeds if the stored value is still the one that was read; otherwise
 * the change is applied again to the fresh value.
 */
class Store {

	/**
	 * Apply a change to an option's array value.
	 *
	 * @param string   $option Option name (never autoloaded).
	 * @param callable $change Receives the current array, returns the new one.
	 * @return array The stored value.
	 */
	public static function mutate( $option, callable $change ) {
		global $wpdb;
		$next = [];

		for ( $attempt = 0; $attempt < 5; $attempt++ ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- must be the stored value, not a cached copy, for the compare-and-swap below.
			$raw     = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $option ) );
			$current = null === $raw ? [] : maybe_unserialize( $raw );
			$current = is_array( $current ) ? $current : [];
			$next    = (array) $change( $current );

			if ( null === $raw ) {
				// add_option() cannot overwrite a row another request just created.
				if ( add_option( $option, $next, '', false ) ) {
					return $next;
				}
				wp_cache_delete( $option, 'options' );
				wp_cache_delete( 'notoptions', 'options' );
				continue;
			}
			if ( $next === $current ) {
				return $next;
			}
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- compare-and-swap: update_option() cannot make the write conditional on the old value.
			$updated = $wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s AND option_value = %s", maybe_serialize( $next ), $option, $raw ) );
			if ( $updated ) {
				wp_cache_delete( $option, 'options' );
				return $next;
			}
		}

		// Still contended after five tries: write anyway rather than drop the change.
		update_option( $option, $next, false );
		return $next;
	}
}
