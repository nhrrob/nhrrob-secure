<?php
/**
 * Time-based one-time passwords (RFC 6238).
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Services;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The authenticator-app algorithm: HMAC-SHA1, 6 digits, 30-second steps —
 * what Google Authenticator, Authy, 1Password and the rest all expect.
 */
class Totp {

	const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	const PERIOD   = 30;

	/**
	 * A new random secret, base32 encoded (160 bits).
	 *
	 * @return string
	 */
	public static function generate_secret() {
		return self::base32_encode( random_bytes( 20 ) );
	}

	/**
	 * The code for a secret at a time step.
	 *
	 * @param string $secret Base32 secret.
	 * @param int    $step   Time step (unix time / 30).
	 * @return string Six digits.
	 */
	public static function code( $secret, $step ) {
		$key    = self::base32_decode( $secret );
		$binary = pack( 'N*', 0 ) . pack( 'N*', $step );
		$hash   = hash_hmac( 'sha1', $binary, $key, true );
		$offset = ord( $hash[19] ) & 0x0F;
		$value  = (
			( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 ) |
			( ( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 ) |
			( ( ord( $hash[ $offset + 2 ] ) & 0xFF ) << 8 ) |
			( ord( $hash[ $offset + 3 ] ) & 0xFF )
		) % 1000000;
		return str_pad( (string) $value, 6, '0', STR_PAD_LEFT );
	}

	/**
	 * Check a code, allowing one step of clock drift either way.
	 *
	 * @param string $secret Base32 secret.
	 * @param string $code   Code the user typed.
	 * @param int    $after  Reject steps at or before this one (stops a code being used twice).
	 * @param int    $now    Current unix time (for tests).
	 * @return int The matching time step, or 0 when the code is wrong.
	 */
	public static function verify( $secret, $code, $after = 0, $now = 0 ) {
		$code = preg_replace( '/\s+/', '', (string) $code );
		if ( ! preg_match( '/^\d{6}$/', $code ) || '' === self::base32_decode( $secret ) ) {
			return 0;
		}
		$current = intdiv( $now ? $now : time(), self::PERIOD );
		for ( $drift = -1; $drift <= 1; $drift++ ) {
			$step = $current + $drift;
			if ( $step > $after && hash_equals( self::code( $secret, $step ), $code ) ) {
				return $step;
			}
		}
		return 0;
	}

	/**
	 * The otpauth:// address an authenticator app reads from the QR code.
	 *
	 * @param string $secret  Base32 secret.
	 * @param string $account Account label (the user's email or login).
	 * @param string $issuer  Site name.
	 * @return string
	 */
	public static function uri( $secret, $account, $issuer ) {
		$issuer = str_replace( ':', ' ', $issuer );
		return 'otpauth://totp/' . rawurlencode( $issuer ) . ':' . rawurlencode( $account )
			. '?secret=' . $secret . '&issuer=' . rawurlencode( $issuer );
	}

	/**
	 * Base32 encode (RFC 4648, no padding).
	 *
	 * @param string $bytes Raw bytes.
	 * @return string
	 */
	public static function base32_encode( $bytes ) {
		$bits = '';
		$len  = strlen( $bytes );
		for ( $i = 0; $i < $len; $i++ ) {
			$bits .= str_pad( decbin( ord( $bytes[ $i ] ) ), 8, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 5 ) as $chunk ) {
			$out .= self::ALPHABET[ bindec( str_pad( $chunk, 5, '0' ) ) ];
		}
		return $out;
	}

	/**
	 * Base32 decode. Returns '' for anything that is not base32.
	 *
	 * @param string $text Base32 text.
	 * @return string Raw bytes.
	 */
	public static function base32_decode( $text ) {
		$text = strtoupper( rtrim( preg_replace( '/\s+/', '', (string) $text ), '=' ) );
		if ( '' === $text || strspn( $text, self::ALPHABET ) !== strlen( $text ) ) {
			return '';
		}
		$bits = '';
		$len  = strlen( $text );
		for ( $i = 0; $i < $len; $i++ ) {
			$bits .= str_pad( decbin( strpos( self::ALPHABET, $text[ $i ] ) ), 5, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 8 ) as $chunk ) {
			if ( 8 === strlen( $chunk ) ) {
				$out .= chr( bindec( $chunk ) );
			}
		}
		return $out;
	}
}
