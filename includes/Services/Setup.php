<?php
/**
 * One-click recommended setup.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Services;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Core\Settings;

/**
 * The settings every site can switch on without risk: none of them can lock
 * the owner out or turn a visitor away. The Dashboard offers the ones that
 * are still off, and remembers what was there so the step can be undone.
 */
class Setup {

	const PART = 'setup';

	/**
	 * The recommended value of each setting, with what it does.
	 *
	 * @return array key => [ value, label, help ]
	 */
	public static function recommended() {
		$items = [
			'limit_login'          => [ true, __( 'Limit login attempts', 'nhrrob-secure' ), __( 'Locks an address out after repeated failed sign-ins.', 'nhrrob-secure' ) ],
			'generic_login_errors' => [ true, __( 'Do not say which part of a sign-in was wrong', 'nhrrob-secure' ), __( 'The sign-in form no longer confirms that a username exists.', 'nhrrob-secure' ) ],
			'strong_passwords'     => [ true, __( 'Require strong passwords for administrators and editors', 'nhrrob-secure' ), __( 'Checked the next time one of them sets a password.', 'nhrrob-secure' ) ],
			'disable_file_editor'  => [ true, __( 'Turn off the theme and plugin file editor', 'nhrrob-secure' ), __( 'Nobody can edit PHP files from wp-admin.', 'nhrrob-secure' ) ],
			'hide_usernames'       => [ true, __( 'Hide usernames from visitors', 'nhrrob-secure' ), __( 'Covers the REST users list, /?author=1 probes and the users sitemap.', 'nhrrob-secure' ) ],
			'disable_xmlrpc'       => [ true, __( 'Turn off XML-RPC', 'nhrrob-secure' ), __( 'Closes the old remote API. Left out when Jetpack is active, which needs it.', 'nhrrob-secure' ) ],
			'honeypot'             => [ true, __( 'Trap form-filling bots', 'nhrrob-secure' ), __( 'A hidden field on the registration and comment forms that people never see.', 'nhrrob-secure' ) ],
			'scan_schedule'        => [ 'weekly', __( 'Scan files every week', 'nhrrob-secure' ), __( 'Runs in the background and emails you only when something new turns up.', 'nhrrob-secure' ) ],
		];
		if ( class_exists( 'Jetpack' ) ) {
			unset( $items['disable_xmlrpc'] );
		}
		return $items;
	}

	/**
	 * The recommended settings this site does not have yet. Pure.
	 *
	 * @param array $recommended key => [ value, label, help ].
	 * @param array $settings    Current settings.
	 * @return array[] Each: key, label, help.
	 */
	public static function pending( array $recommended, array $settings ) {
		$out = [];
		foreach ( $recommended as $key => $item ) {
			$current = isset( $settings[ $key ] ) ? $settings[ $key ] : null;
			// A schedule the owner chose (daily) is as good as the recommended one.
			$done = 'scan_schedule' === $key ? 'off' !== $current : $current === $item[0];
			if ( ! $done ) {
				$out[] = [
					'key'   => $key,
					'label' => $item[1],
					'help'  => $item[2],
				];
			}
		}
		return $out;
	}

	/**
	 * What the Dashboard needs to show the setup card.
	 *
	 * @return array { items: array[], undo: bool, dismissed: bool }
	 */
	public static function for_app() {
		$state = Scan::get( self::PART );
		return [
			'items'     => self::pending( self::recommended(), Settings::all() ),
			'undo'      => ! empty( $state['undo'] ),
			'dismissed' => ! empty( $state['dismissed'] ),
		];
	}

	/**
	 * The settings change for the chosen keys.
	 *
	 * @param string[] $keys Keys the owner left ticked.
	 * @return array key => value
	 */
	public static function patch( array $keys ) {
		$patch       = [];
		$recommended = self::recommended();
		foreach ( self::pending( $recommended, Settings::all() ) as $item ) {
			if ( in_array( $item['key'], $keys, true ) ) {
				$patch[ $item['key'] ] = $recommended[ $item['key'] ][0];
			}
		}
		return $patch;
	}

	/**
	 * Remember what the changed settings were, so the step can be undone.
	 *
	 * @param array $previous key => value before the change.
	 * @return void
	 */
	public static function remember( array $previous ) {
		Scan::set( self::PART, [ 'undo' => $previous ] );
	}

	/**
	 * The values to put back (empty when there is nothing to undo).
	 *
	 * @return array
	 */
	public static function undo_values() {
		$state = Scan::get( self::PART );
		return isset( $state['undo'] ) && is_array( $state['undo'] ) ? array_intersect_key( $state['undo'], self::recommended() ) : [];
	}

	/**
	 * Close the card: keep what was applied, or stop offering what is left.
	 *
	 * @param bool $dismissed Whether the remaining items should no longer be offered.
	 * @return void
	 */
	public static function close( $dismissed ) {
		Scan::set( self::PART, $dismissed ? [ 'dismissed' => true ] : null );
	}
}
