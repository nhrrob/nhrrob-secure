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
	const PLUGIN_SVN = 'https://plugins.svn.wordpress.org/';
	const THEME_ZIP  = 'https://downloads.wordpress.org/theme/';
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
			'config'     => self::config_findings(),
			'loaders'    => self::loaders(),
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
		try {
			// A folder that cannot be read is skipped rather than ending the scan.
			$iterator = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ), \RecursiveIteratorIterator::LEAVES_ONLY, \RecursiveIteratorIterator::CATCH_GET_CHILD );
			foreach ( $iterator as $file ) {
				if ( $file->isFile() ) {
					$out[] = wp_normalize_path( $file->getPathname() );
				}
			}
		} catch ( \Exception $e ) {
			unset( $e );
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

		$result = self::write( ABSPATH . $file, $body );
		if ( true !== $result ) {
			return $result;
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
	 * The checksum list WordPress.org publishes for one plugin release.
	 *
	 * @param string $slug    Plugin folder.
	 * @param string $version Version.
	 * @return array|null { files: path => { md5, sha256 } }, or null when there is none.
	 */
	private static function plugin_checksums( $slug, $version ) {
		$response = wp_remote_get( self::PLUGIN_API . rawurlencode( $slug ) . '/' . rawurlencode( $version ) . '.json', [ 'timeout' => 8 ] );
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}
		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		return empty( $data['files'] ) || ! is_array( $data['files'] ) ? null : $data;
	}

	/**
	 * Replace one changed plugin file with the copy from its WordPress.org release.
	 *
	 * The plugin must be installed, the file must be in the checksum list of
	 * the installed version, and the download must match that checksum before
	 * anything is written.
	 *
	 * @param string $slug Plugin folder.
	 * @param string $file Path inside the plugin folder.
	 * @return true|\WP_Error
	 */
	public static function repair_plugin_file( $slug, $file ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$version = '';
		foreach ( get_plugins() as $path => $plugin ) {
			if ( dirname( $path ) === $slug ) {
				$version = (string) $plugin['Version'];
			}
		}
		$data = '' !== $version ? self::plugin_checksums( $slug, $version ) : null;
		if ( null === $data || ! isset( $data['files'][ $file ]['md5'] ) || 0 !== validate_file( $file ) ) {
			return new \WP_Error( 'nhrrob_secure_not_plugin', __( 'That file is not part of the plugin\'s WordPress.org release.', 'nhrrob-secure' ), [ 'status' => 400 ] );
		}

		$url      = self::PLUGIN_SVN . rawurlencode( $slug ) . '/tags/' . rawurlencode( $version ) . '/' . str_replace( '%2F', '/', rawurlencode( $file ) );
		$response = wp_remote_get( $url, [ 'timeout' => 15 ] );
		$body     = is_wp_error( $response ) ? '' : wp_remote_retrieve_body( $response );
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) || ! in_array( md5( $body ), (array) $data['files'][ $file ]['md5'], true ) ) {
			return new \WP_Error( 'nhrrob_secure_download', __( 'A copy that matches the official checksum could not be downloaded. Reinstall the plugin from the Plugins screen instead.', 'nhrrob-secure' ), [ 'status' => 502 ] );
		}

		$result = self::write( WP_PLUGIN_DIR . '/' . $slug . '/' . $file, $body );
		if ( true !== $result ) {
			return $result;
		}
		Activity::record( 'scan', 'repair_plugin', $slug . '/' . $file, Activity::WARNING );

		// Bring the stored result in line without comparing every plugin again.
		$stored = Scan::get( 'plugins' );
		if ( is_array( $stored ) ) {
			$diff = self::compare_plugin( $slug, $version );
			foreach ( $stored['changed'] as $index => $plugin ) {
				if ( $plugin['slug'] !== $slug || null === $diff ) {
					continue;
				}
				if ( $diff['files'] || $diff['extra'] ) {
					$stored['changed'][ $index ]['files'] = $diff['files'];
					$stored['changed'][ $index ]['extra'] = $diff['extra'];
				} else {
					unset( $stored['changed'][ $index ] );
					++$stored['ok'];
				}
			}
			$stored['changed'] = array_values( $stored['changed'] );
			Scan::set( 'plugins', $stored );
		}
		return true;
	}

	/**
	 * Write an official copy over a file in a folder that already exists.
	 *
	 * @param string $target Absolute path.
	 * @param string $body   New contents.
	 * @return true|\WP_Error
	 */
	private static function write( $target, $body ) {
		$filesystem = self::filesystem();
		if ( is_wp_error( $filesystem ) ) {
			return $filesystem;
		}
		if ( ! $filesystem->is_dir( dirname( $target ) ) || ! $filesystem->put_contents( $target, $body, FS_CHMOD_FILE ) ) {
			return new \WP_Error( 'nhrrob_secure_write', __( 'The file could not be written. Check the file permissions.', 'nhrrob-secure' ), [ 'status' => 500 ] );
		}
		return true;
	}

	// ---- Themes. ----

	/**
	 * Queue every installed theme for comparison.
	 *
	 * @return array Run state.
	 */
	public static function start_themes() {
		$queue = [];
		foreach ( wp_get_themes() as $slug => $theme ) {
			$queue[] = [ (string) $slug, (string) $theme->get( 'Version' ), (string) $theme->get( 'Name' ) ];
		}
		$last = Scan::get( 'themes' );
		$run  = [
			'queue'   => $queue,
			'total'   => count( $queue ),
			'ok'      => 0,
			'unknown' => [],
			'changed' => [],
			// Themes that matched last time, by version and fingerprint: they are not downloaded again.
			'clean'   => isset( $last['clean'] ) && is_array( $last['clean'] ) ? $last['clean'] : [],
			'matched' => [],
		];
		Scan::set( 'themes_run', $run );
		return $run;
	}

	/**
	 * Compare the next theme. One per step: each needs its release downloaded.
	 *
	 * @return array { running: bool, done: int, total: int }
	 */
	public static function step_themes() {
		$run = Scan::get( 'themes_run' );
		if ( ! is_array( $run ) ) {
			$run = self::start_themes();
		}

		if ( $run['queue'] ) {
			list( $slug, $version, $name ) = array_shift( $run['queue'] );
			$stamp                         = $version . '|' . Monitor::fingerprint( get_theme_root( $slug ) . '/' . $slug );
			$diff                          = isset( $run['clean'][ $slug ] ) && $run['clean'][ $slug ] === $stamp ? [] : self::compare_theme( $slug, $version );
			if ( null === $diff ) {
				$run['unknown'][] = $name;
			} elseif ( ! empty( $diff['files'] ) || ! empty( $diff['extra'] ) ) {
				$run['changed'][] = [
					'name'    => $name,
					'slug'    => $slug,
					'version' => $version,
					'files'   => $diff['files'],
					'extra'   => $diff['extra'],
				];
			} else {
				++$run['ok'];
				$run['matched'][ $slug ] = $stamp;
			}
		}

		$running = (bool) $run['queue'];
		if ( $running ) {
			Scan::set( 'themes_run', $run );
		} else {
			Scan::set( 'themes_run', null );
			Scan::set(
				'themes',
				[
					'checked' => time(),
					'total'   => $run['total'],
					'ok'      => $run['ok'],
					'unknown' => $run['unknown'],
					'changed' => $run['changed'],
					'clean'   => $run['matched'],
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
	 * Download a theme's WordPress.org release and open it.
	 *
	 * @param string $slug    Theme folder.
	 * @param string $version Installed version.
	 * @return array|null [ ZipArchive, temp file ], or null when the release cannot be had.
	 */
	private static function theme_release( $slug, $version ) {
		if ( ! class_exists( '\ZipArchive' ) || ! preg_match( '/^[\w.-]+$/', $slug ) || ! preg_match( '/^[\w.-]+$/', $version ) ) {
			return null;
		}
		require_once ABSPATH . 'wp-admin/includes/file.php';
		$tmp = download_url( self::THEME_ZIP . $slug . '.' . $version . '.zip', 30 );
		if ( is_wp_error( $tmp ) ) {
			return null;
		}
		$zip = new \ZipArchive();
		if ( true !== $zip->open( $tmp ) ) {
			wp_delete_file( $tmp );
			return null;
		}
		return [ $zip, $tmp ];
	}

	/**
	 * Compare one theme's files with its WordPress.org release.
	 *
	 * WordPress.org publishes no checksums for themes, so the release itself
	 * is downloaded and its code files compared with the ones on disk.
	 *
	 * @param string $slug    Theme folder.
	 * @param string $version Installed version.
	 * @return array|null { files, extra }, or null when it cannot be compared.
	 */
	private static function compare_theme( $slug, $version ) {
		$release = self::theme_release( $slug, $version );
		if ( null === $release ) {
			return null;
		}
		list( $zip, $tmp ) = $release;

		$root     = wp_normalize_path( get_theme_root( $slug ) . '/' . $slug . '/' );
		$changed  = [];
		$official = [];
		for ( $i = 0; $i < $zip->numFiles; $i++ ) { // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- ZipArchive property.
			$name = (string) $zip->getNameIndex( $i );
			if ( 0 !== strpos( $name, $slug . '/' ) || '/' === substr( $name, -1 ) ) {
				continue;
			}
			$file              = substr( $name, strlen( $slug ) + 1 );
			$official[ $file ] = true;
			$stream            = self::is_theme_code( $file ) && is_file( $root . $file ) ? $zip->getStream( $name ) : false;
			if ( ! $stream ) {
				continue;
			}
			$hash = hash_init( 'md5' );
			hash_update_stream( $hash, $stream );
			fclose( $stream ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- a stream out of the zip, not a file.
			if ( hash_final( $hash ) !== md5_file( $root . $file ) ) {
				$changed[] = $file;
			}
		}
		$zip->close();
		wp_delete_file( $tmp );

		$extra = [];
		foreach ( self::files_in( $root ) as $path ) {
			$file = substr( $path, strlen( $root ) );
			if ( ! isset( $official[ $file ] ) && preg_match( '/\.(php\d?|phtml|phar)$/i', $file ) ) {
				$extra[] = $file;
			}
		}
		return [
			'files' => array_slice( $changed, 0, 20 ),
			'extra' => array_slice( $extra, 0, 20 ),
		];
	}

	/**
	 * Whether a theme file is code: PHP, JavaScript or a template. Pure.
	 *
	 * Only these are compared. The copy of a default theme that ships inside
	 * WordPress differs from the same version on WordPress.org in its readme,
	 * its stylesheet header and its fonts, and none of those can run.
	 *
	 * @param string $file Path inside the theme.
	 * @return bool
	 */
	public static function is_theme_code( $file ) {
		return (bool) preg_match( '/\.(?:php\d?|phtml|phar|js|mjs|html?)$/i', $file );
	}

	/**
	 * Replace one changed theme file with the copy from its WordPress.org release.
	 *
	 * @param string $slug Theme folder.
	 * @param string $file Path inside the theme folder.
	 * @return true|\WP_Error
	 */
	public static function repair_theme_file( $slug, $file ) {
		$theme   = wp_get_theme( $slug );
		$release = $theme->exists() && 0 === validate_file( $file ) ? self::theme_release( $slug, (string) $theme->get( 'Version' ) ) : null;
		if ( null === $release ) {
			return new \WP_Error( 'nhrrob_secure_download', __( 'The official release could not be downloaded. Reinstall the theme from the Themes screen instead.', 'nhrrob-secure' ), [ 'status' => 502 ] );
		}
		list( $zip, $tmp ) = $release;
		$body              = $zip->getFromName( $slug . '/' . $file );
		$zip->close();
		wp_delete_file( $tmp );
		if ( false === $body ) {
			return new \WP_Error( 'nhrrob_secure_not_theme', __( 'That file is not part of the theme\'s WordPress.org release.', 'nhrrob-secure' ), [ 'status' => 400 ] );
		}

		$result = self::write( get_theme_root( $slug ) . '/' . $slug . '/' . $file, $body );
		if ( true !== $result ) {
			return $result;
		}
		Activity::record( 'scan', 'repair_theme', $slug . '/' . $file, Activity::WARNING );

		$stored = Scan::get( 'themes' );
		if ( is_array( $stored ) ) {
			foreach ( $stored['changed'] as $index => $item ) {
				if ( $item['slug'] !== $slug ) {
					continue;
				}
				$stored['changed'][ $index ]['files'] = array_values( array_diff( $item['files'], [ $file ] ) );
				if ( ! $stored['changed'][ $index ]['files'] && ! $item['extra'] ) {
					unset( $stored['changed'][ $index ] );
					++$stored['ok'];
				}
			}
			$stored['changed'] = array_values( $stored['changed'] );
			Scan::set( 'themes', $stored );
		}
		return true;
	}

	// ---- Server and configuration files. ----

	/**
	 * What is wrong with a server configuration file ('' for nothing). Pure.
	 *
	 * These are the changes an attacker makes to keep a way in or to send
	 * visitors elsewhere; none of them is something WordPress writes.
	 *
	 * @param string $contents File contents.
	 * @param string $host     This site's host name.
	 * @return string prepend | handler | redirect | ''
	 */
	public static function server_file_reason( $contents, $host ) {
		$active = (string) preg_replace( '/^\s*[#;].*$/m', '', $contents );
		if ( preg_match( '/auto_(?:prepend|append)_file\s*[= ]\s*\S/i', $active ) ) {
			return 'prepend';
		}
		if ( preg_match( '/^\s*(?:AddHandler|AddType|SetHandler)\b[^\n]*php[^\n]*\.(?:jpe?g|png|gif|ico|css|js|txt|html?)\b/mi', $active ) ) {
			return 'handler';
		}
		if ( preg_match( '/RewriteCond\s+%\{HTTP_(?:USER_AGENT|REFERER)\}[^\n]*(?:google|bing|yahoo|yandex|baidu|duckduck|facebook)/i', $active )
			&& preg_match_all( '~RewriteRule\s+\S+\s+https?://([^/\s:$%]+)~i', $active, $targets ) ) {
			$own = preg_replace( '/^www\./', '', strtolower( $host ) );
			foreach ( $targets[1] as $target ) {
				if ( preg_replace( '/^www\./', '', strtolower( $target ) ) !== $own ) {
					return 'redirect';
				}
			}
		}
		return '';
	}

	/**
	 * Readable reasons for the configuration findings.
	 *
	 * @return array id => text
	 */
	public static function config_reasons() {
		$reasons = [
			'prepend'  => __( 'Loads a PHP file before or after every page. A firewall plugin does this on purpose; anything else should not.', 'nhrrob-secure' ),
			'handler'  => __( 'Makes the server run images or text files as PHP.', 'nhrrob-secure' ),
			'redirect' => __( 'Sends visitors who come from a search engine to another site.', 'nhrrob-secure' ),
			'include'  => __( 'Loads an image or text file as PHP code.', 'nhrrob-secure' ),
		];
		foreach ( CodeScan::signatures() as $id => $signature ) {
			$reasons[ $id ] = $signature[0];
		}
		return $reasons;
	}

	/**
	 * Check .htaccess, .user.ini and wp-config.php for injected rules and code.
	 *
	 * @return array[] Each: file, reason.
	 */
	public static function config_findings() {
		require_once ABSPATH . 'wp-admin/includes/file.php';
		$uploads = wp_get_upload_dir();
		$host    = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$reasons = self::config_reasons();
		$out     = [];

		$server = array_unique( [ get_home_path() . '.htaccess', ABSPATH . '.htaccess', ABSPATH . '.user.ini', WP_CONTENT_DIR . '/.htaccess', $uploads['basedir'] . '/.htaccess' ] );
		foreach ( $server as $path ) {
			$reason = is_readable( $path ) ? self::server_file_reason( (string) file_get_contents( $path ), $host ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file read.
			if ( '' !== $reason ) {
				$out[] = [
					'file'   => ltrim( str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( $path ) ), '/' ),
					'reason' => $reasons[ $reason ],
				];
			}
		}

		$config = file_exists( ABSPATH . 'wp-config.php' ) ? ABSPATH . 'wp-config.php' : dirname( ABSPATH ) . '/wp-config.php';
		if ( is_readable( $config ) ) {
			$contents = (string) file_get_contents( $config ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file read.
			$reason   = CodeScan::match( $contents );
			if ( '' === $reason && preg_match( '/\b(?:include|require)(?:_once)?\b[^;]*\.(?:jpe?g|png|gif|ico|css|txt)[\'"]/i', $contents ) ) {
				$reason = 'include';
			}
			if ( '' !== $reason ) {
				$out[] = [
					'file'   => 'wp-config.php',
					'reason' => $reasons[ $reason ],
				];
			}
		}
		return $out;
	}

	/**
	 * Code that WordPress loads without it appearing on the Plugins screen:
	 * must-use plugins and drop-ins. Listed so the owner can see what is there.
	 *
	 * @return array[] Each: kind (mu | dropin), file, name.
	 */
	public static function loaders() {
		if ( ! function_exists( 'get_mu_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$out = [];
		foreach ( get_mu_plugins() as $file => $data ) {
			$out[] = [
				'kind' => 'mu',
				'file' => $file,
				'name' => $data['Name'],
			];
		}
		foreach ( get_dropins() as $file => $data ) {
			$out[] = [
				'kind' => 'dropin',
				'file' => $file,
				'name' => $data['Name'],
			];
		}
		return array_slice( $out, 0, self::LIST_CAP );
	}

	/**
	 * Compare one plugin's files with its WordPress.org release.
	 *
	 * @param string $slug    Plugin folder.
	 * @param string $version Installed version.
	 * @return array|null { files: changed files, extra: PHP files that are not in the release }, or null when WordPress.org has no checksums for it.
	 */
	private static function compare_plugin( $slug, $version ) {
		$data = self::plugin_checksums( $slug, $version );
		if ( null === $data ) {
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
