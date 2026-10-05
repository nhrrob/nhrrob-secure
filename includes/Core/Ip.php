<?php
/**
 * IP address helpers and the single client-address resolver.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * IPv4/IPv6 matching and "who is this visitor" for every module.
 *
 * The visitor address is REMOTE_ADDR unless the owner said the site sits
 * behind Cloudflare or a proxy AND the request really comes from one. A
 * forwarded header from anyone else is ignored, so it cannot be used to fake
 * an address in the log or dodge a lockout.
 */
class Ip {

	/**
	 * Resolved client address for this request.
	 *
	 * @var string|null
	 */
	private static $client = null;

	/**
	 * Cloudflare's published edge ranges.
	 *
	 * @return string[]
	 */
	public static function cloudflare_ranges() {
		$ranges = [
			'173.245.48.0/20',
			'103.21.244.0/22',
			'103.22.200.0/22',
			'103.31.4.0/22',
			'141.101.64.0/18',
			'108.162.192.0/18',
			'190.93.240.0/20',
			'188.114.96.0/20',
			'197.234.240.0/22',
			'198.41.128.0/17',
			'162.158.0.0/15',
			'104.16.0.0/13',
			'104.24.0.0/14',
			'172.64.0.0/13',
			'131.0.72.0/22',
			'2400:cb00::/32',
			'2606:4700::/32',
			'2803:f800::/32',
			'2405:b500::/32',
			'2405:8100::/32',
			'2a06:98c0::/29',
			'2c0f:f248::/32',
		];

		/**
		 * Filter the address ranges treated as Cloudflare.
		 *
		 * @param string[] $ranges CIDR ranges.
		 */
		return (array) apply_filters( 'nhrrob_secure_cloudflare_ranges', $ranges );
	}

	/**
	 * Whether a string is a single address or a CIDR range.
	 *
	 * @param string $range Address or CIDR.
	 * @return bool
	 */
	public static function valid_range( $range ) {
		$parts = explode( '/', (string) $range );
		if ( count( $parts ) > 2 || false === filter_var( $parts[0], FILTER_VALIDATE_IP ) ) {
			return false;
		}
		if ( 1 === count( $parts ) ) {
			return true;
		}
		$max = false !== strpos( $parts[0], ':' ) ? 128 : 32;
		return ctype_digit( $parts[1] ) && (int) $parts[1] <= $max;
	}

	/**
	 * Whether an address falls inside an address or CIDR range.
	 *
	 * @param string $ip    Address to test.
	 * @param string $range Address or CIDR.
	 * @return bool
	 */
	public static function in_range( $ip, $range ) {
		$parts  = explode( '/', (string) $range );
		$ip_bin = self::pack( $ip );
		$net    = self::pack( $parts[0] );
		if ( false === $ip_bin || false === $net || strlen( $ip_bin ) !== strlen( $net ) ) {
			return false;
		}
		$bits = isset( $parts[1] ) && ctype_digit( $parts[1] ) ? (int) $parts[1] : strlen( $net ) * 8;
		$bits = min( $bits, strlen( $net ) * 8 );

		$bytes = intdiv( $bits, 8 );
		if ( $bytes && 0 !== strncmp( $ip_bin, $net, $bytes ) ) {
			return false;
		}
		$rest = $bits % 8;
		if ( 0 === $rest ) {
			return true;
		}
		$mask = chr( ( 0xFF << ( 8 - $rest ) ) & 0xFF );
		return ( $ip_bin[ $bytes ] & $mask ) === ( $net[ $bytes ] & $mask );
	}

	/**
	 * Whether an address matches any range in a list.
	 *
	 * @param string   $ip     Address.
	 * @param string[] $ranges Addresses or CIDRs.
	 * @return bool
	 */
	public static function in_any( $ip, array $ranges ) {
		foreach ( $ranges as $range ) {
			if ( self::in_range( $ip, $range ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Binary form of an address; IPv4-mapped IPv6 is reduced to IPv4.
	 *
	 * @param string $ip Address.
	 * @return string|false
	 */
	private static function pack( $ip ) {
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}
		$bin = inet_pton( $ip );
		if ( false !== $bin && 16 === strlen( $bin ) && 0 === strncmp( $bin, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12 ) ) {
			return substr( $bin, 12 );
		}
		return $bin;
	}

	/**
	 * Whether an address is loopback or private (a local proxy or balancer).
	 *
	 * @param string $ip Address.
	 * @return bool
	 */
	public static function is_private( $ip ) {
		return false === filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
	}

	/**
	 * The address the request arrived from, before any proxy logic.
	 *
	 * @return string
	 */
	public static function remote() {
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		return false !== filter_var( $remote, FILTER_VALIDATE_IP ) ? $remote : '0.0.0.0';
	}

	/**
	 * Whether this request really arrived through Cloudflare.
	 *
	 * @return bool
	 */
	public static function via_cloudflare() {
		return isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && self::in_any( self::remote(), self::cloudflare_ranges() );
	}

	/**
	 * The visitor's address.
	 *
	 * @return string
	 */
	public static function client() {
		if ( null !== self::$client ) {
			return self::$client;
		}
		$headers = [
			'cf'  => isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) : '',
			'xff' => isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) : '',
		];

		self::$client = self::resolve( self::remote(), $headers, (string) Settings::get( 'ip_source' ), (array) Settings::get( 'trusted_proxies' ) );
		return self::$client;
	}

	/**
	 * Pure resolver behind client(), so the trust rules can be unit tested.
	 *
	 * @param string   $remote  REMOTE_ADDR.
	 * @param array    $headers Forwarded headers: 'cf' and 'xff'.
	 * @param string   $mode    direct | cloudflare | proxy.
	 * @param string[] $trusted Trusted proxy ranges (proxy mode).
	 * @return string
	 */
	public static function resolve( $remote, array $headers, $mode, array $trusted ) {
		if ( 'cloudflare' === $mode ) {
			$cf = isset( $headers['cf'] ) ? trim( $headers['cf'] ) : '';
			if ( self::in_any( $remote, self::cloudflare_ranges() ) && false !== filter_var( $cf, FILTER_VALIDATE_IP ) ) {
				return $cf;
			}
			return $remote;
		}

		if ( 'proxy' === $mode && ! empty( $headers['xff'] ) ) {
			$is_trusted = function ( $ip ) use ( $trusted ) {
				// With no list, only a proxy on the local network is believed.
				return $trusted ? self::in_any( $ip, $trusted ) : self::is_private( $ip );
			};
			if ( ! $is_trusted( $remote ) ) {
				return $remote;
			}
			// Walk back from the hop nearest to us; the first address that is not one of our proxies is the visitor.
			$hops = array_reverse( array_map( 'trim', explode( ',', $headers['xff'] ) ) );
			foreach ( $hops as $hop ) {
				if ( false === filter_var( $hop, FILTER_VALIDATE_IP ) ) {
					break;
				}
				if ( ! $is_trusted( $hop ) ) {
					return $hop;
				}
			}
		}

		return $remote;
	}

	/**
	 * Which address rule applies to an address: 'allow', 'block' or ''.
	 * Allow wins over block.
	 *
	 * @param string $ip Address.
	 * @return string
	 */
	public static function rule_for( $ip ) {
		$found = '';
		foreach ( (array) Settings::get( 'ip_rules' ) as $rule ) {
			if ( self::in_range( $ip, $rule['range'] ) ) {
				if ( 'allow' === $rule['type'] ) {
					return 'allow';
				}
				$found = 'block';
			}
		}
		return $found;
	}

	/**
	 * Forget the resolved address (tests).
	 *
	 * @return void
	 */
	public static function flush() {
		self::$client = null;
	}
}
