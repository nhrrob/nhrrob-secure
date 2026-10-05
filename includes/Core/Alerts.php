<?php
/**
 * Email alerts.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Sends the plugin's alert emails and keeps repeats from piling up.
 */
class Alerts {

	/**
	 * Where alerts go: the configured address, else the site admin.
	 *
	 * @return string
	 */
	public static function recipient() {
		$email = (string) Settings::get( 'alert_email' );
		return '' !== $email ? $email : (string) get_option( 'admin_email' );
	}

	/**
	 * Send one alert.
	 *
	 * @param string   $subject  Subject, without the site name.
	 * @param string[] $lines    Body lines.
	 * @param string   $throttle Optional key: at most one email per key per $window seconds.
	 * @param int      $window   Throttle window in seconds.
	 * @return bool Whether an email was handed to wp_mail().
	 */
	public static function send( $subject, array $lines, $throttle = '', $window = HOUR_IN_SECONDS ) {
		if ( '' !== $throttle ) {
			$key = 'nhrrob_secure_alert_' . md5( $throttle );
			if ( get_transient( $key ) ) {
				return false;
			}
			set_transient( $key, 1, $window );
		}

		$site    = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$lines[] = '';
		/* translators: %s: URL of the plugin's admin screen. */
		$lines[] = sprintf( __( 'Open Secure: %s', 'nhrrob-secure' ), admin_url( 'tools.php?page=nhrrob-secure' ) );

		// The same text to a chat channel, when the owner gave a webhook address. Not waited for.
		$webhook = (string) Settings::get( 'alert_webhook' );
		if ( '' !== $webhook ) {
			wp_safe_remote_post(
				$webhook,
				[
					'timeout'  => 3,
					'blocking' => false,
					'headers'  => [ 'Content-Type' => 'application/json' ],
					'body'     => wp_json_encode( [ 'text' => sprintf( '[%s] %s', $site, $subject ) . "\n" . implode( "\n", $lines ) ] ),
				]
			);
		}

		return (bool) wp_mail( self::recipient(), sprintf( '[%s] %s', $site, $subject ), implode( "\n", $lines ) );
	}
}
