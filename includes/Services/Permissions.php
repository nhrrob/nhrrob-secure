<?php
/**
 * File permissions of the key files and folders.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Services;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Core\Activity;

/**
 * Lists the files and folders that matter most with their permissions, and
 * flags the ones every account on the server may write to. The fix removes
 * that one permission bit and nothing else, so what the site's own account
 * can read and write stays as it is.
 */
class Permissions {

	/**
	 * The paths that are checked: id => absolute path.
	 *
	 * @return array
	 */
	public static function paths() {
		require_once ABSPATH . 'wp-admin/includes/file.php';
		$uploads = wp_get_upload_dir();
		return [
			'root'     => untrailingslashit( ABSPATH ),
			'config'   => file_exists( ABSPATH . 'wp-config.php' ) ? ABSPATH . 'wp-config.php' : dirname( ABSPATH ) . '/wp-config.php',
			'htaccess' => get_home_path() . '.htaccess',
			'admin'    => ABSPATH . 'wp-admin',
			'includes' => ABSPATH . WPINC,
			'content'  => WP_CONTENT_DIR,
			'plugins'  => WP_PLUGIN_DIR,
			'themes'   => get_theme_root(),
			'uploads'  => $uploads['basedir'],
		];
	}

	/**
	 * Whether a mode lets every account on the server write. Pure.
	 *
	 * @param int $mode Permission bits.
	 * @return bool
	 */
	public static function is_open( $mode ) {
		return (bool) ( $mode & 0002 );
	}

	/**
	 * The mode without the "everyone may write" bit. Pure.
	 *
	 * @param int $mode Permission bits.
	 * @return int
	 */
	public static function closed( $mode ) {
		return $mode & 0777 & ~0002;
	}

	/**
	 * Each path with its permissions. Empty on Windows, where these bits mean nothing.
	 *
	 * @return array[] Each: id, path, mode, open.
	 */
	public static function items() {
		$out = [];
		if ( 'WIN' === strtoupper( substr( PHP_OS, 0, 3 ) ) ) {
			return $out;
		}
		$root = wp_normalize_path( untrailingslashit( ABSPATH ) );
		clearstatcache();
		foreach ( self::paths() as $id => $path ) {
			if ( ! file_exists( $path ) ) {
				continue;
			}
			$mode  = (int) fileperms( $path ) & 0777;
			$shown = ltrim( str_replace( $root, '', wp_normalize_path( $path ) ), '/' );
			$out[] = [
				'id'   => $id,
				'path' => '' === $shown ? '/' : $shown . ( is_dir( $path ) ? '/' : '' ),
				'mode' => sprintf( '%04o', $mode ),
				'open' => self::is_open( $mode ),
			];
		}
		return $out;
	}

	/**
	 * Take the "everyone may write" bit off one of the listed paths.
	 *
	 * @param string $id Path id from paths().
	 * @return bool Whether the path is no longer open.
	 */
	public static function fix( $id ) {
		$paths = self::paths();
		if ( ! isset( $paths[ $id ] ) || ! file_exists( $paths[ $id ] ) ) {
			return false;
		}
		$mode = (int) fileperms( $paths[ $id ] ) & 0777;
		if ( ! self::is_open( $mode ) ) {
			return true;
		}
		// Only the owner of a file may change its mode; when PHP is not the owner this fails and the screen says so.
		$done = @chmod( $paths[ $id ], self::closed( $mode ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- a failure is the expected answer on some hosts and is reported to the owner.
		if ( $done ) {
			Activity::record( 'setting', 'permissions', basename( $paths[ $id ] ), Activity::INFO );
		}
		return $done;
	}
}
