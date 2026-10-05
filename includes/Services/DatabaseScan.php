<?php
/**
 * Database scan for injected content.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Services;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Looks through posts and options for the two things injected content
 * usually contains: iframes made invisible, and JavaScript that hides what it
 * does. A list for a person to review — an ordinary script or embed is not
 * reported, and nothing is changed.
 */
class DatabaseScan {

	const CAP       = 100;
	const PAGE      = 50;
	const BUDGET    = 10;
	const MAX_VALUE = 500000;

	/**
	 * Patterns and what they mean.
	 *
	 * @return array id => [ label, pattern ]
	 */
	public static function signatures() {
		return [
			'hidden_iframe' => [
				__( 'An iframe that is made invisible.', 'nhrrob-secure' ),
				'~<iframe\b[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|\b(?:width|height)\s*=\s*["\']?[01](?:px)?["\'\s>])~i',
			],
			'obfuscated_js' => [
				__( 'JavaScript that decodes hidden text and runs it.', 'nhrrob-secure' ),
				'~\beval\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\(|document\.write\s*\(\s*(?:unescape|atob)\s*\(|String\.fromCharCode\s*\((?:\s*\d+\s*,){20,}~i',
			],
		];
	}

	/**
	 * Which signature a text matches ('' for none). Pure.
	 *
	 * @param string $text Stored content.
	 * @return string Signature id or ''.
	 */
	public static function match( $text ) {
		foreach ( self::signatures() as $id => $signature ) {
			if ( preg_match( $signature[1], $text ) ) {
				return $id;
			}
		}
		return '';
	}

	/**
	 * Run the scan.
	 *
	 * @return array { checked: int, findings: [ where, reason, link ] }
	 */
	public static function run() {
		global $wpdb;
		$labels   = wp_list_pluck( self::signatures(), 0 );
		$findings = [];
		$likes    = [ '%<iframe%', '%eval(%', '%document.write%', '%fromCharCode%' ];
		$stop_at  = microtime( true ) + self::BUDGET;
		$partial  = false;

		// The table is walked in small pages by id. Ordinary content (a video embed) passes the
		// cheap SQL filter too, so every such row has to reach the strict check — not just the first few hundred.
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- an on-demand read-only scan; core has no API to search content for markup.
		$after = 0;
		while ( true ) {
			if ( count( $findings ) >= self::CAP ) {
				break;
			}
			if ( microtime( true ) > $stop_at ) {
				$partial = true;
				break;
			}
			$posts = (array) $wpdb->get_results(
				$wpdb->prepare(
					"SELECT ID, post_title, post_type, LEFT( post_content, %d ) AS post_content FROM {$wpdb->posts}
					WHERE ID > %d AND post_status NOT IN ( 'trash', 'auto-draft', 'inherit' )
					AND ( post_content LIKE %s OR post_content LIKE %s OR post_content LIKE %s OR post_content LIKE %s )
					ORDER BY ID ASC LIMIT %d",
					self::MAX_VALUE,
					$after,
					$likes[0],
					$likes[1],
					$likes[2],
					$likes[3],
					self::PAGE
				)
			);
			foreach ( $posts as $post ) {
				$after  = (int) $post->ID;
				$reason = self::match( (string) $post->post_content );
				if ( '' !== $reason ) {
					$findings[] = [
						/* translators: 1: post type, 2: post title. */
						'where'  => sprintf( __( '%1$s: %2$s', 'nhrrob-secure' ), $post->post_type, '' !== $post->post_title ? $post->post_title : '#' . $post->ID ),
						'reason' => $labels[ $reason ],
						'link'   => (string) get_edit_post_link( $post->ID, 'raw' ),
					];
				}
			}
			if ( count( $posts ) < self::PAGE ) {
				break;
			}
		}

		$after = 0;
		while ( ! $partial ) {
			if ( count( $findings ) >= self::CAP ) {
				break;
			}
			if ( microtime( true ) > $stop_at ) {
				$partial = true;
				break;
			}
			$options = (array) $wpdb->get_results(
				$wpdb->prepare(
					"SELECT option_id, option_name, LEFT( option_value, %d ) AS option_value FROM {$wpdb->options}
					WHERE option_id > %d AND option_name NOT LIKE %s AND option_name NOT LIKE %s AND option_name NOT LIKE %s
					AND ( option_value LIKE %s OR option_value LIKE %s OR option_value LIKE %s OR option_value LIKE %s )
					ORDER BY option_id ASC LIMIT %d",
					self::MAX_VALUE,
					$after,
					$wpdb->esc_like( '_transient_' ) . '%',
					$wpdb->esc_like( '_site_transient_' ) . '%',
					$wpdb->esc_like( 'nhrrob_secure_' ) . '%',
					$likes[0],
					$likes[1],
					$likes[2],
					$likes[3],
					self::PAGE
				)
			);
			foreach ( $options as $option ) {
				$after  = (int) $option->option_id;
				$reason = self::match( (string) $option->option_value );
				if ( '' !== $reason ) {
					$findings[] = [
						/* translators: %s: option name. */
						'where'  => sprintf( __( 'Setting: %s', 'nhrrob-secure' ), $option->option_name ),
						'reason' => $labels[ $reason ],
						'link'   => '',
					];
				}
			}
			if ( count( $options ) < self::PAGE ) {
				break;
			}
		}
		// phpcs:enable

		$result = [
			'checked'  => time(),
			'findings' => array_slice( $findings, 0, self::CAP ),
			// True when the time limit ended the scan before every row was looked at.
			'partial'  => $partial,
		];
		Scan::set( 'database', $result );
		return $result;
	}
}
