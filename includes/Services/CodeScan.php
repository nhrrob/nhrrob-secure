<?php
/**
 * Suspicious-code review.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Services;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Core\Activity;

/**
 * Walks wp-content for PHP files that contain patterns typical of backdoors.
 *
 * This is a list of files for a person to review — not a malware cleaner and
 * not a guarantee. It works through the folders a few seconds at a time and
 * picks up where it left off, so it covers every file instead of stopping at
 * a limit. A finding can be quarantined (renamed so it cannot run) and
 * restored; nothing is deleted.
 */
class CodeScan {

	const BUDGET       = 4;
	const MAX_FINDINGS = 200;
	const SUFFIX       = '.suspected';

	/**
	 * Patterns and what they mean.
	 *
	 * @return array id => [ label, pattern ]
	 */
	public static function signatures() {
		return [
			'obfuscated_eval' => [
				__( 'Decodes hidden text and runs it as code.', 'nhrrob-secure' ),
				'~\beval\s*\(\s*@?\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin|urldecode|rawurldecode)\s*\(~i',
			],
			'input_eval'      => [
				__( 'Runs whatever a visitor sends as code or as a system command.', 'nhrrob-secure' ),
				'~(?<![\w>$:\\\\])(?:eval|assert|system|passthru|shell_exec|exec|popen|proc_open|create_function)\s*\(\s*@?\s*(?:stripslashes\s*\(\s*)?\$_(?:POST|GET|REQUEST|COOKIE|FILES)\b~i',
			],
			'variable_call'   => [
				__( 'Lets a visitor choose which PHP function is called.', 'nhrrob-secure' ),
				'~\$_(?:POST|GET|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)~i',
			],
			'long_payload'    => [
				__( 'Runs a very long encoded block of text as code.', 'nhrrob-secure' ),
				'~\b(?:eval|assert)\s*\(.{0,80}[\'"][A-Za-z0-9+/=]{800,}[\'"]~s',
			],
			'shell_marker'    => [
				__( 'Contains the name of a well-known web shell.', 'nhrrob-secure' ),
				'~\b(?:FilesMan|c99shell|r57shell|b374k|IndoXploit|AnonymousFox|WSO\s+\d\.\d)\b~',
			],
		];
	}

	/**
	 * Which signature a file's contents match ('' for none). Pure.
	 *
	 * @param string $contents File contents.
	 * @return string Signature id or ''.
	 */
	public static function match( $contents ) {
		foreach ( self::signatures() as $id => $signature ) {
			if ( preg_match( $signature[1], $contents ) ) {
				return $id;
			}
		}
		return '';
	}

	/**
	 * Stored state.
	 *
	 * @return array
	 */
	public static function state() {
		$state = Scan::get( 'code' );
		return array_merge(
			[
				'status'      => 'idle',
				'dirs'        => [],
				'files'       => 0,
				'findings'    => [],
				'quarantined' => [],
				'started'     => 0,
				'finished'    => 0,
			],
			is_array( $state ) ? $state : []
		);
	}

	/**
	 * Store the state.
	 *
	 * @param array $state State.
	 * @return void
	 */
	private static function save( array $state ) {
		Scan::set( 'code', $state );
	}

	/**
	 * Start a new scan.
	 *
	 * @return array State for the app.
	 */
	public static function start() {
		$state             = self::state();
		$state['status']   = 'running';
		$state['dirs']     = [ '' ];
		$state['files']    = 0;
		$state['findings'] = [];
		$state['started']  = time();
		$state['finished'] = 0;
		self::save( $state );
		return self::step();
	}

	/**
	 * Scan for a few seconds, then save where to continue.
	 *
	 * @return array State for the app.
	 */
	public static function step() {
		$state = self::state();
		if ( 'running' !== $state['status'] ) {
			return self::for_app( $state );
		}

		$root    = wp_normalize_path( WP_CONTENT_DIR );
		$uploads = wp_get_upload_dir();
		$uploads = trailingslashit( wp_normalize_path( $uploads['basedir'] ) );
		$own     = trailingslashit( wp_normalize_path( NHRROB_SECURE_PATH ) );
		$stop_at = microtime( true ) + self::BUDGET;

		$found = count( $state['findings'] );

		while ( $state['dirs'] && microtime( true ) < $stop_at && $found < self::MAX_FINDINGS ) {
			$relative = array_pop( $state['dirs'] );
			$dir      = '' === $relative ? $root : $root . '/' . $relative;
			$entries  = is_readable( $dir ) ? scandir( $dir ) : false;
			if ( false === $entries ) {
				continue;
			}
			foreach ( $entries as $entry ) {
				if ( '.' === $entry || '..' === $entry ) {
					continue;
				}
				$path = $dir . '/' . $entry;
				$rel  = '' === $relative ? $entry : $relative . '/' . $entry;
				if ( is_link( $path ) ) {
					continue;
				}
				if ( is_dir( $path ) ) {
					if ( ! in_array( $entry, [ 'node_modules', '.git' ], true ) && trailingslashit( $path ) !== $own ) {
						$state['dirs'][] = $rel;
					}
					continue;
				}
				if ( ! preg_match( '/\.(?:php\d?|phtml|phar)$/i', $entry ) ) {
					continue;
				}
				++$state['files'];
				$in_uploads = 0 === strpos( $path, $uploads );
				$reason     = self::inspect( $path, $in_uploads );
				if ( '' !== $reason && $found < self::MAX_FINDINGS ) {
					++$found;
					$state['findings'][] = [
						'file'   => $rel,
						'reason' => $reason,
					];
				}
			}
		}

		if ( ! $state['dirs'] || count( $state['findings'] ) >= self::MAX_FINDINGS ) {
			$state['status']   = 'done';
			$state['dirs']     = [];
			$state['finished'] = time();
		}
		self::save( $state );
		return self::for_app( $state );
	}

	/**
	 * Look at one PHP file.
	 *
	 * @param string $path       Absolute path.
	 * @param bool   $in_uploads Whether the file is in the uploads folder.
	 * @return string Reason id, or ''.
	 */
	private static function inspect( $path, $in_uploads ) {
		$size = (int) filesize( $path );
		if ( $size <= 0 || ! is_readable( $path ) ) {
			return '';
		}
		// Large files: injected code sits at the top or the bottom, so both ends are read.
		if ( $size > 1048576 ) {
			$handle   = fopen( $path, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- read-only partial read of a local file; WP_Filesystem has no ranged read.
			$contents = (string) fread( $handle, 262144 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
			fseek( $handle, -262144, SEEK_END );
			$contents .= (string) fread( $handle, 262144 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
			fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		} else {
			$contents = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file read.
		}

		$reason = self::match( $contents );
		if ( '' !== $reason ) {
			return $reason;
		}
		// PHP has no business in uploads; the usual empty index.php guard is the exception.
		if ( $in_uploads && ! ( 'index.php' === basename( $path ) && $size < 200 ) ) {
			return 'uploads_php';
		}
		return '';
	}

	/**
	 * State as the app shows it.
	 *
	 * @param array|null $state Stored state (read when omitted).
	 * @return array
	 */
	public static function for_app( $state = null ) {
		$state  = is_array( $state ) ? $state : self::state();
		$labels = wp_list_pluck( self::signatures(), 0 );

		$labels['uploads_php'] = __( 'A PHP file in the uploads folder, where only media belongs.', 'nhrrob-secure' );

		$findings = [];
		foreach ( $state['findings'] as $finding ) {
			$parts      = explode( '/', $finding['file'] );
			$findings[] = [
				'file'   => $finding['file'],
				'reason' => isset( $labels[ $finding['reason'] ] ) ? $labels[ $finding['reason'] ] : $finding['reason'],
				'plugin' => 'plugins' === $parts[0] && isset( $parts[2] ) ? $parts[1] : '',
			];
		}

		return [
			'status'      => $state['status'],
			'files'       => (int) $state['files'],
			'folders'     => count( $state['dirs'] ),
			'findings'    => $findings,
			'quarantined' => array_values( $state['quarantined'] ),
			'finished'    => (int) $state['finished'],
			'capped'      => count( $state['findings'] ) >= self::MAX_FINDINGS,
		];
	}

	/**
	 * Resolve a listed file to a real path inside wp-content.
	 *
	 * Only files the scan itself reported (or quarantined) can be acted on, so
	 * these actions can never be pointed at an arbitrary path.
	 *
	 * @param string $file Path relative to wp-content.
	 * @param string $source 'findings' or 'quarantined'.
	 * @return string|\WP_Error Absolute path.
	 */
	private static function resolve( $file, $source ) {
		$state = self::state();
		$known = 'findings' === $source ? wp_list_pluck( $state['findings'], 'file' ) : $state['quarantined'];
		if ( ! in_array( $file, $known, true ) ) {
			return new \WP_Error( 'nhrrob_secure_unknown_file', __( 'That file is not in the scan results. Run the scan again.', 'nhrrob-secure' ), [ 'status' => 400 ] );
		}
		$root = trailingslashit( wp_normalize_path( (string) realpath( WP_CONTENT_DIR ) ) );
		$real = realpath( WP_CONTENT_DIR . '/' . $file . ( 'quarantined' === $source ? self::SUFFIX : '' ) );
		if ( false === $real || 0 !== strpos( wp_normalize_path( $real ), $root ) || ! is_file( $real ) ) {
			return new \WP_Error( 'nhrrob_secure_missing_file', __( 'That file no longer exists.', 'nhrrob-secure' ), [ 'status' => 404 ] );
		}
		return wp_normalize_path( $real );
	}

	/**
	 * The lines around the first match in a reported file.
	 *
	 * @param string $file Path relative to wp-content.
	 * @return array|\WP_Error { file, start, lines }
	 */
	public static function view( $file ) {
		$path = self::resolve( $file, 'findings' );
		if ( is_wp_error( $path ) ) {
			return $path;
		}
		$contents = (string) file_get_contents( $path, false, null, 0, 1048576 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local file read.
		$offset   = 0;
		foreach ( self::signatures() as $signature ) {
			if ( preg_match( $signature[1], $contents, $found, PREG_OFFSET_CAPTURE ) ) {
				$offset = $found[0][1];
				break;
			}
		}
		$line  = substr_count( $contents, "\n", 0, $offset );
		$lines = explode( "\n", $contents );
		$start = max( 0, $line - 6 );
		$out   = [];
		foreach ( array_slice( $lines, $start, 16 ) as $text ) {
			// A single obfuscated line can be megabytes long.
			$out[] = strlen( $text ) > 400 ? substr( $text, 0, 400 ) . ' …' : $text;
		}
		return [
			'file'  => $file,
			'start' => $start + 1,
			'lines' => $out,
		];
	}

	/**
	 * Rename a reported file so it cannot run.
	 *
	 * @param string $file Path relative to wp-content.
	 * @return array|\WP_Error State for the app.
	 */
	public static function quarantine( $file ) {
		$path = self::resolve( $file, 'findings' );
		if ( is_wp_error( $path ) ) {
			return $path;
		}
		$filesystem = Integrity::filesystem();
		if ( is_wp_error( $filesystem ) ) {
			return $filesystem;
		}
		if ( ! $filesystem->move( $path, $path . self::SUFFIX, false ) ) {
			return new \WP_Error( 'nhrrob_secure_write', __( 'The file could not be renamed. Check the file permissions.', 'nhrrob-secure' ), [ 'status' => 500 ] );
		}

		$state                  = self::state();
		$state['findings']      = array_values(
			array_filter(
				$state['findings'],
				function ( $finding ) use ( $file ) {
					return $finding['file'] !== $file;
				}
			)
		);
		$state['quarantined'][] = $file;
		$state['quarantined']   = array_slice( array_values( array_unique( $state['quarantined'] ) ), -200 );
		self::save( $state );
		Activity::record( 'scan', 'quarantine', $file, Activity::WARNING );
		return self::for_app( $state );
	}

	/**
	 * Put a quarantined file back.
	 *
	 * @param string $file Path relative to wp-content (its original name).
	 * @return array|\WP_Error State for the app.
	 */
	public static function restore( $file ) {
		$path = self::resolve( $file, 'quarantined' );
		if ( is_wp_error( $path ) ) {
			return $path;
		}
		$filesystem = Integrity::filesystem();
		if ( is_wp_error( $filesystem ) ) {
			return $filesystem;
		}
		$original = substr( $path, 0, -strlen( self::SUFFIX ) );
		if ( ! $filesystem->move( $path, $original, false ) ) {
			return new \WP_Error( 'nhrrob_secure_write', __( 'The file could not be renamed. Check the file permissions.', 'nhrrob-secure' ), [ 'status' => 500 ] );
		}

		$state                = self::state();
		$state['quarantined'] = array_values( array_diff( $state['quarantined'], [ $file ] ) );
		self::save( $state );
		Activity::record( 'scan', 'restore', $file, Activity::WARNING );
		return self::for_app( $state );
	}
}
