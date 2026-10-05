<?php
/**
 * File integrity checks against official checksums.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Services;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Core\Activity;

/**
 * Compares WordPress core and WordPress.org plugins with the checksums
 * published by WordPress.org.
 */
class Integrity {

	const CORE_API   = 'https://api.wordpress.org/core/checksums/1.0/';
	const CORE_FILES = 'https://core.svn.wordpress.org/tags/';
	const PLUGIN_API = 'https://downloads.wordpress.org/plugin-checksums/';
	const BATCH      = 3;
	const LIST_CAP   = 50;

	/**
	 * Official checksums for the installed WordPress version, limited to core's
	 * own files. Bundled themes and plugins under wp-content are left out: an
	 * owner removing Hello Dolly is not damage.
	 *
	 * @return array|\WP_Error path => md5.
	 */
	public static function core_checksums() {
		$response = wp_remote_get(
			add_query_arg(
				[
					'version' => get_bloginfo( 'version' ),
					'locale'  => get_locale(),
				],
				self::CORE_API
			),
			[ 'timeout' => 15 ]
		);
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $data['checksums'] ) || ! is_array( $data['checksums'] ) ) {
			return new \WP_Error( 'nhrrob_secure_checksums', __( 'WordPress.org has no checksums for this WordPress version.', 'nhrrob-secure' ), [ 'status' => 502 ] );
		}
		$out = [];
		foreach ( $data['checksums'] as $file => $md5 ) {
			if ( 0 !== strpos( $file, 'wp-content/' ) ) {
				$out[ $file ] = $md5;
			}
		}
		return $out;
	}

	/**
	 * Compare core files with the official release.
	 *
	 * @return array|\WP_Error
	 */
	public static function check_core() {
		$checksums = self::core_checksums();
		if ( is_wp_error( $checksums ) ) {
			return $checksums;
		}

		$modified = [];
		$missing  = [];
		foreach ( $checksums as $file => $md5 ) {
			$path = ABSPATH . $file;
			if ( ! file_exists( $path ) ) {
				$missing[] = $file;
			} elseif ( md5_file( $path ) !== $md5 ) {
				$modified[] = $file;
			}
		}

		// Code inside the core folders that is not part of the release is the strongest sign of tampering.
		// Stray non-code files (.DS_Store, error logs) are left out: they cannot run.
		$unexpected = [];
		$root       = wp_normalize_path( ABSPATH );
		foreach ( [ 'wp-admin', 'wp-includes' ] as $dir ) {
			foreach ( self::files_in( ABSPATH . $dir ) as $path ) {
				$file = ltrim( substr( $path, strlen( $root ) ), '/' );
				if ( ! isset( $checksums[ $file ] ) && preg_match( '/\.(?:php\d?|phtml|phar|htaccess|user\.ini)$/i', $file ) ) {
					$unexpected[] = $file;
				}
			}
		}
		foreach ( (array) glob( ABSPATH . '*.php' ) as $path ) {
			$file = basename( $path );
			if ( ! isset( $checksums[ $file ] ) && 'wp-config.php' !== $file ) {
				$unexpected[] = $file;
			}
		}

		$result = [
			'checked'    => time(),
			'version'    => get_bloginfo( 'version' ),
			'total'      => count( $checksums ),
			'modified'   => array_slice( $modified, 0, self::LIST_CAP ),
			'missing'    => array_slice( $missing, 0, self::LIST_CAP ),
			'unexpected' => array_slice( $unexpected, 0, self::LIST_CAP ),
		];
		Scan::set( 'core', $result );
		return $result;
	}

	/**
	 * Every file under a directory.
	 *
	 * @param string $dir Directory.
	 * @return string[] Absolute paths.
	 */
	private static function files_in( $dir ) {
		$out = [];
		if ( ! is_dir( $dir ) ) {
			return $out;
		}
		$iterator = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ) );
		foreach ( $iterator as $file ) {
			if ( $file->isFile() ) {
				$out[] = wp_normalize_path( $file->getPathname() );
			}
		}
		return $out;
	}

	/**
	 * Replace one changed or missing core file with the official copy.
	 *
	 * The file must be in the official list, and the download must match its
	 * checksum before anything is written.
	 *
	 * @param string $file Path relative to the WordPress folder.
	 * @return true|\WP_Error
	 */
	public static function repair_core_file( $file ) {
		$checksums = self::core_checksums();
		if ( is_wp_error( $checksums ) ) {
			return $checksums;
		}
		if ( ! isset( $checksums[ $file ] ) ) {
			return new \WP_Error( 'nhrrob_secure_not_core', __( 'That is not a WordPress core file.', 'nhrrob-secure' ), [ 'status' => 400 ] );
		}

		$response = wp_remote_get( self::CORE_FILES . rawurlencode( get_bloginfo( 'version' ) ) . '/' . str_replace( '%2F', '/', rawurlencode( $file ) ), [ 'timeout' => 15 ] );
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return new \WP_Error( 'nhrrob_secure_download', __( 'The official copy could not be downloaded. Reinstall WordPress from Dashboard → Updates instead.', 'nhrrob-secure' ), [ 'status' => 502 ] );
		}
		$body = wp_remote_retrieve_body( $response );
		if ( md5( $body ) !== $checksums[ $file ] ) {
			return new \WP_Error( 'nhrrob_secure_mismatch', __( 'The downloaded copy does not match the official checksum for your language version. Reinstall WordPress from Dashboard → Updates instead.', 'nhrrob-secure' ), [ 'status' => 409 ] );
		}

		$filesystem = self::filesystem();
		if ( is_wp_error( $filesystem ) ) {
			return $filesystem;
		}
		$target = ABSPATH . $file;
		if ( ! $filesystem->is_dir( dirname( $target ) ) || ! $filesystem->put_contents( $target, $body, FS_CHMOD_FILE ) ) {
			return new \WP_Error( 'nhrrob_secure_write', __( 'The file could not be written. Check the file permissions.', 'nhrrob-secure' ), [ 'status' => 500 ] );
		}
		Activity::record( 'scan', 'repair', $file, Activity::WARNING );
		return true;
	}

	/**
	 * Direct filesystem access, or an error when the server needs FTP details
	 * or file changes are switched off.
	 *
	 * @return \WP_Filesystem_Base|\WP_Error
	 */
	public static function filesystem() {
		global $wp_filesystem;
		if ( ! wp_is_file_mod_allowed( 'nhrrob_secure' ) ) {
			return new \WP_Error( 'nhrrob_secure_file_mods', __( 'File changes are switched off on this site (DISALLOW_FILE_MODS).', 'nhrrob-secure' ), [ 'status' => 403 ] );
		}
		require_once ABSPATH . 'wp-admin/includes/file.php';
		if ( 'direct' !== get_filesystem_method() || ! WP_Filesystem() || ! $wp_filesystem ) {
			return new \WP_Error( 'nhrrob_secure_filesystem', __( 'This server does not let plugins change files directly.', 'nhrrob-secure' ), [ 'status' => 500 ] );
		}
		return $wp_filesystem;
	}

	/**
	 * Queue every installed plugin for comparison.
	 *
	 * @return array Run state.
	 */
	public static function start_plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$queue = [];
		foreach ( get_plugins() as $file => $data ) {
			$slug = dirname( $file );
			if ( '.' !== $slug ) {
				$queue[] = [ $slug, $data['Version'], $data['Name'] ];
			}
		}
		$run = [
			'queue'   => $queue,
			'total'   => count( $queue ),
			'ok'      => 0,
			'unknown' => [],
			'changed' => [],
		];
		Scan::set( 'plugins_run', $run );
		return $run;
	}

	/**
	 * Compare the next few plugins.
	 *
	 * @return array { running: bool, done: int, total: int }
	 */
	public static function step_plugins() {
		$run = Scan::get( 'plugins_run' );
		if ( ! is_array( $run ) ) {
			$run = self::start_plugins();
		}

		for ( $i = 0; $i < self::BATCH && $run['queue']; $i++ ) {
			list( $slug, $version, $name ) = array_shift( $run['queue'] );
			$diff                          = self::compare_plugin( $slug, $version );
			if ( null === $diff ) {
				$run['unknown'][] = $name;
			} elseif ( $diff['files'] || $diff['extra'] ) {
				$run['changed'][] = [
					'name'    => $name,
					'slug'    => $slug,
					'version' => $version,
					'files'   => $diff['files'],
					'extra'   => $diff['extra'],
				];
			} else {
				++$run['ok'];
			}
		}

		$running = (bool) $run['queue'];
		if ( $running ) {
			Scan::set( 'plugins_run', $run );
		} else {
			Scan::set( 'plugins_run', null );
			Scan::set(
				'plugins',
				[
					'checked' => time(),
					'total'   => $run['total'],
					'ok'      => $run['ok'],
					'unknown' => $run['unknown'],
					'changed' => $run['changed'],
				]
			);
		}
		return [
			'running' => $running,
			'done'    => $run['total'] - count( $run['queue'] ),
			'total'   => $run['total'],
		];
	}

	/**
	 * Compare one plugin's files with its WordPress.org release.
	 *
	 * @param string $slug    Plugin folder.
	 * @param string $version Installed version.
	 * @return array|null { files: changed files, extra: PHP files that are not in the release }, or null when WordPress.org has no checksums for it.
	 */
	private static function compare_plugin( $slug, $version ) {
		$response = wp_remote_get( self::PLUGIN_API . rawurlencode( $slug ) . '/' . rawurlencode( $version ) . '.json', [ 'timeout' => 8 ] );
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}
		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $data['files'] ) || ! is_array( $data['files'] ) ) {
			return null;
		}

		$root    = wp_normalize_path( WP_PLUGIN_DIR . '/' . $slug . '/' );
		$changed = [];
		foreach ( $data['files'] as $file => $sums ) {
			$path = $root . $file;
			if ( ! isset( $sums['md5'] ) || ! is_file( $path ) ) {
				continue;
			}
			if ( ! in_array( md5_file( $path ), (array) $sums['md5'], true ) ) {
				$changed[] = $file;
			}
		}

		$extra = [];
		foreach ( self::files_in( $root ) as $path ) {
			$file = substr( $path, strlen( $root ) );
			if ( ! isset( $data['files'][ $file ] ) && preg_match( '/\.(php\d?|phtml|phar)$/i', $file ) ) {
				$extra[] = $file;
			}
		}

		return [
			'files' => array_slice( $changed, 0, 20 ),
			'extra' => array_slice( $extra, 0, 20 ),
		];
	}
}
