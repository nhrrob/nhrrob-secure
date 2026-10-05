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

	const CAP = 100;

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

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- an on-demand read-only scan; core has no API to search content for markup.
		$posts = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ID, post_title, post_type, post_content FROM {$wpdb->posts}
				WHERE post_status NOT IN ( 'trash', 'auto-draft', 'inherit' )
				AND ( post_content LIKE %s OR post_content LIKE %s OR post_content LIKE %s OR post_content LIKE %s )
				LIMIT 500",
				$likes[0],
				$likes[1],
				$likes[2],
				$likes[3]
			)
		);
		foreach ( (array) $posts as $post ) {
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

		$options = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT option_name, option_value FROM {$wpdb->options}
				WHERE option_name NOT LIKE %s AND option_name NOT LIKE %s AND option_name NOT LIKE %s
				AND ( option_value LIKE %s OR option_value LIKE %s OR option_value LIKE %s OR option_value LIKE %s )
				LIMIT 500",
				$wpdb->esc_like( '_transient_' ) . '%',
				$wpdb->esc_like( '_site_transient_' ) . '%',
				$wpdb->esc_like( 'nhrrob_secure_' ) . '%',
				$likes[0],
				$likes[1],
				$likes[2],
				$likes[3]
			)
		);
		// phpcs:enable
		foreach ( (array) $options as $option ) {
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

		$result = [
			'checked'  => time(),
			'findings' => array_slice( $findings, 0, self::CAP ),
		];
		Scan::set( 'database', $result );
		return $result;
	}
}
