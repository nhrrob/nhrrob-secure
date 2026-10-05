<?php
/**
 * File change monitoring.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Services;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Keeps one fingerprint per plugin and theme and reports when the code of
 * one changes without its version changing — which is what an injected file
 * or an edited plugin looks like.
 *
 * It covers what the WordPress.org comparison cannot: themes, and plugins
 * that are not published there. Storage is one short hash per item, not one
 * per file.
 */
class Monitor {

	const BUDGET = 4;

	/**
	 * Register the hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		add_action( 'upgrader_process_complete', [ __CLASS__, 'on_upgrade' ], 10, 2 );
	}

	/**
	 * Which watched items an install or update touched. Pure.
	 *
	 * Only those are forgotten. A translation or core update, or an update of
	 * another plugin, says nothing about the rest — forgetting everything would
	 * let any update hide a change made somewhere else.
	 *
	 * @param array  $data        What the upgrader reports (type, plugins, plugin, themes, theme).
	 * @param string $destination Folder name the upgrader wrote to ('' when unknown).
	 * @return string[] Item keys.
	 */
	public static function touched( array $data, $destination = '' ) {
		$type = isset( $data['type'] ) ? $data['type'] : '';
		if ( 'plugin' !== $type && 'theme' !== $type ) {
			return [];
		}
		$names = [];
		foreach ( [ $type . 's', $type ] as $field ) {
			if ( ! empty( $data[ $field ] ) ) {
				$names = array_merge( $names, (array) $data[ $field ] );
			}
		}
		if ( '' !== $destination ) {
			$names[] = $destination;
		}
		$keys = [];
		foreach ( $names as $name ) {
			// Plugins are reported as "folder/file.php", themes as their folder.
			$slug = 'plugin' === $type && false !== strpos( (string) $name, '/' ) ? dirname( (string) $name ) : (string) $name;
			if ( '' !== $slug && '.' !== $slug ) {
				$keys[] = $type . ':' . $slug;
			}
		}
		return array_values( array_unique( $keys ) );
	}

	/**
	 * After an install or update, the fingerprint of what was installed is
	 * stale; the next run records a fresh one. Items already reported as
	 * changed stay reported.
	 *
	 * @param object $upgrader The upgrader.
	 * @param array  $data     What it did.
	 * @return void
	 */
	public static function on_upgrade( $upgrader = null, $data = [] ) {
		$destination = is_object( $upgrader ) && isset( $upgrader->result ) && is_array( $upgrader->result ) && ! empty( $upgrader->result['destination_name'] ) ? (string) $upgrader->result['destination_name'] : '';
		$keys        = self::touched( (array) $data, $destination );
		$state       = self::state();
		if ( $keys && array_intersect_key( $state['items'], array_flip( $keys ) ) ) {
			$state['items'] = array_diff_key( $state['items'], array_flip( $keys ) );
			Scan::set( 'monitor', $state );
		}
	}

	/**
	 * Stored state.
	 *
	 * @return array { items: key => [ name, hash, version ], changed: key => [ name, since ], checked: int, queue: array|null }
	 */
	public static function state() {
		$state = Scan::get( 'monitor' );
		return array_merge(
			[
				'items'   => [],
				'changed' => [],
				'checked' => 0,
				'queue'   => null,
			],
			is_array( $state ) ? $state : []
		);
	}

	/**
	 * Everything that is watched: key => [ name, version, directory ].
	 *
	 * @return array
	 */
	public static function targets() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$targets = [];
		foreach ( get_plugins() as $file => $data ) {
			$slug = dirname( $file );
			if ( '.' !== $slug ) {
				$targets[ 'plugin:' . $slug ] = [ $data['Name'], $data['Version'], WP_PLUGIN_DIR . '/' . $slug ];
			}
		}
		foreach ( wp_get_themes() as $slug => $theme ) {
			$targets[ 'theme:' . $slug ] = [ $theme->get( 'Name' ), (string) $theme->get( 'Version' ), $theme->get_stylesheet_directory() ];
		}
		return $targets;
	}

	/**
	 * One hash over the contents of every PHP file in a directory.
	 *
	 * @param string $dir Directory.
	 * @return string
	 */
	public static function fingerprint( $dir ) {
		$hashes = [];
		if ( is_dir( $dir ) ) {
			try {
				// A folder that cannot be read is skipped rather than ending the scan.
				$iterator = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ), \RecursiveIteratorIterator::LEAVES_ONLY, \RecursiveIteratorIterator::CATCH_GET_CHILD );
				foreach ( $iterator as $file ) {
					if ( $file->isFile() && preg_match( '/\.(?:php\d?|phtml|phar)$/i', $file->getFilename() ) ) {
						$hashes[ substr( $file->getPathname(), strlen( $dir ) ) ] = md5_file( $file->getPathname() );
					}
				}
			} catch ( \Exception $e ) {
				unset( $e );
			}
		}
		ksort( $hashes );
		return md5( wp_json_encode( $hashes ) );
	}

	/**
	 * Pure decision for one item, so it can be unit tested.
	 *
	 * @param array|null $known   Stored [ name, hash, version ] or null.
	 * @param string     $hash    Current fingerprint.
	 * @param string     $version Current version.
	 * @return string new | same | updated | changed
	 */
	public static function compare( $known, $hash, $version ) {
		if ( ! is_array( $known ) ) {
			return 'new';
		}
		if ( $known[1] === $hash ) {
			return 'same';
		}
		// A different version explains different code: someone updated it (possibly by FTP or WP-CLI).
		return $known[2] !== $version ? 'updated' : 'changed';
	}

	/**
	 * Check as many items as fit in a few seconds.
	 *
	 * @param bool $restart Start a new run.
	 * @return array { running: bool, done: int, total: int }
	 */
	public static function step( $restart = false ) {
		$state   = self::state();
		$targets = self::targets();
		if ( $restart || ! is_array( $state['queue'] ) ) {
			$state['queue'] = array_keys( $targets );
			// Items that no longer exist are not watched any more.
			$state['items']   = array_intersect_key( $state['items'], $targets );
			$state['changed'] = array_intersect_key( $state['changed'], $targets );
		}

		$stop_at = microtime( true ) + self::BUDGET;
		while ( $state['queue'] && microtime( true ) < $stop_at ) {
			$key = array_shift( $state['queue'] );
			if ( ! isset( $targets[ $key ] ) ) {
				continue;
			}
			list( $name, $version, $dir ) = $targets[ $key ];
			$hash                         = self::fingerprint( $dir );
			$known                        = isset( $state['items'][ $key ] ) ? $state['items'][ $key ] : null;

			if ( 'changed' === self::compare( $known, $hash, $version ) ) {
				// The old fingerprint is kept until the owner accepts the change.
				if ( ! isset( $state['changed'][ $key ] ) ) {
					$state['changed'][ $key ] = [ $name, time() ];
				}
				continue;
			}
			// Back to the known code, or explained by a new version: no longer reported.
			unset( $state['changed'][ $key ] );
			$state['items'][ $key ] = [ $name, $hash, $version ];
		}

		$total   = count( $targets );
		$running = (bool) $state['queue'];
		if ( ! $running ) {
			$state['queue']   = null;
			$state['checked'] = time();
		}
		Scan::set( 'monitor', $state );

		return [
			'running' => $running,
			'done'    => $total - ( $running ? count( $state['queue'] ) : 0 ),
			'total'   => $total,
		];
	}

	/**
	 * Accept an item's current code as the new baseline.
	 *
	 * @param string $key Item key.
	 * @return bool
	 */
	public static function accept( $key ) {
		$state   = self::state();
		$targets = self::targets();
		if ( ! isset( $state['changed'][ $key ], $targets[ $key ] ) ) {
			return false;
		}
		list( $name, $version, $dir ) = $targets[ $key ];
		$state['items'][ $key ]       = [ $name, self::fingerprint( $dir ), $version ];
		unset( $state['changed'][ $key ] );
		Scan::set( 'monitor', $state );
		return true;
	}

	/**
	 * State as the app shows it.
	 *
	 * @return array
	 */
	public static function for_app() {
		$state   = self::state();
		$changed = [];
		foreach ( $state['changed'] as $key => $item ) {
			$parts     = explode( ':', $key, 2 );
			$changed[] = [
				'key'   => $key,
				'type'  => $parts[0],
				'name'  => $item[0],
				'since' => (int) $item[1],
			];
		}
		return [
			'checked' => (int) $state['checked'],
			'watched' => count( $state['items'] ) + count( $state['changed'] ),
			'changed' => $changed,
			'running' => is_array( $state['queue'] ),
		];
	}
}
