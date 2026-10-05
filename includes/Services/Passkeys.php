<?php
/**
 * Passkeys (WebAuthn) as a second step at sign-in.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Services;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Registers and verifies passkeys without a library.
 *
 * Scope is deliberately small: ES256 and RS256 keys, no attestation (the
 * site does not need to know the make of the authenticator), and the passkey
 * is the second step after the password, not a replacement for it.
 *
 * What is checked on every sign-in: the response is for this challenge, this
 * site (origin and RP ID hash), the user was present, the signature verifies
 * against the stored public key, and the authenticator's counter did not go
 * backwards.
 */
class Passkeys {

	const META    = 'nhrrob_secure_passkeys';
	const MAX     = 10;
	const TIMEOUT = 5 * MINUTE_IN_SECONDS;

	/**
	 * Whether passkeys can work on this site: HTTPS and OpenSSL are needed.
	 *
	 * @return bool
	 */
	public static function available() {
		return function_exists( 'openssl_verify' ) && 'https' === wp_parse_url( home_url(), PHP_URL_SCHEME );
	}

	/**
	 * The relying-party id: this site's host name.
	 *
	 * @return string
	 */
	public static function rp_id() {
		return (string) wp_parse_url( home_url(), PHP_URL_HOST );
	}

	/**
	 * Origins a response may come from: the site address and the WordPress address.
	 *
	 * @return string[]
	 */
	public static function origins() {
		$out = [];
		foreach ( [ home_url(), site_url() ] as $url ) {
			$parts = wp_parse_url( $url );
			if ( ! empty( $parts['host'] ) ) {
				$out[] = 'https://' . $parts['host'] . ( isset( $parts['port'] ) ? ':' . $parts['port'] : '' );
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * A user's passkeys: credential id (base64url) => [ k: PEM key, n: counter, l: label, c: created ].
	 *
	 * @param int $user_id User id.
	 * @return array
	 */
	public static function all( $user_id ) {
		$keys = get_user_meta( $user_id, self::META, true );
		return is_array( $keys ) ? $keys : [];
	}

	/**
	 * Options for `navigator.credentials.create()`.
	 *
	 * @param \WP_User $user User.
	 * @return array
	 */
	public static function register_options( $user ) {
		$challenge = self::b64url( random_bytes( 32 ) );
		set_transient( 'nhrrob_secure_pk_' . $user->ID, $challenge, self::TIMEOUT );

		$exclude = [];
		foreach ( array_keys( self::all( $user->ID ) ) as $id ) {
			$exclude[] = [
				'type' => 'public-key',
				'id'   => $id,
			];
		}
		return [
			'rp'                     => [
				'name' => wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
				'id'   => self::rp_id(),
			],
			'user'                   => [
				'id'          => self::b64url( (string) $user->ID ),
				'name'        => $user->user_login,
				'displayName' => $user->display_name,
			],
			'challenge'              => $challenge,
			'pubKeyCredParams'       => [
				[
					'type' => 'public-key',
					'alg'  => -7,
				],
				[
					'type' => 'public-key',
					'alg'  => -257,
				],
			],
			'authenticatorSelection' => [
				'userVerification' => 'preferred',
				'residentKey'      => 'discouraged',
			],
			'attestation'            => 'none',
			'excludeCredentials'     => $exclude,
			'timeout'                => 60000,
		];
	}

	/**
	 * Store a newly created passkey.
	 *
	 * @param \WP_User $user        User.
	 * @param string   $client_json clientDataJSON, base64url.
	 * @param string   $attestation attestationObject, base64url.
	 * @param string   $label       Name the user gave it.
	 * @return true|\WP_Error
	 */
	public static function register( $user, $client_json, $attestation, $label ) {
		$challenge = (string) get_transient( 'nhrrob_secure_pk_' . $user->ID );
		delete_transient( 'nhrrob_secure_pk_' . $user->ID );

		$parsed = self::parse_registration( self::b64url_decode( $client_json ), self::b64url_decode( $attestation ), $challenge, self::origins(), self::rp_id() );
		if ( is_wp_error( $parsed ) ) {
			return $parsed;
		}

		$keys                  = self::all( $user->ID );
		$keys[ $parsed['id'] ] = [
			'k' => $parsed['pem'],
			'n' => $parsed['count'],
			'l' => '' !== $label ? substr( $label, 0, 40 ) : __( 'Passkey', 'nhrrob-secure' ),
			'c' => time(),
		];
		update_user_meta( $user->ID, self::META, array_slice( $keys, -self::MAX, self::MAX, true ) );
		return true;
	}

	/**
	 * Pure check of a registration response.
	 *
	 * @param string   $client_raw  clientDataJSON bytes.
	 * @param string   $attestation attestationObject bytes.
	 * @param string   $challenge   Expected challenge (base64url).
	 * @param string[] $origins     Accepted origins.
	 * @param string   $rp_id       Relying-party id.
	 * @return array|\WP_Error { id, pem, count }
	 */
	public static function parse_registration( $client_raw, $attestation, $challenge, array $origins, $rp_id ) {
		$fail = new \WP_Error( 'nhrrob_secure_passkey', __( 'The passkey could not be registered. Try again.', 'nhrrob-secure' ), [ 'status' => 400 ] );

		if ( ! self::client_data_ok( $client_raw, 'webauthn.create', $challenge, $origins ) ) {
			return $fail;
		}
		$object = self::cbor( $attestation );
		if ( ! is_array( $object ) || ! isset( $object['authData'] ) || ! is_string( $object['authData'] ) ) {
			return $fail;
		}
		$auth = $object['authData'];
		// 32 RP hash + 1 flags + 4 counter + 16 AAGUID + 2 id length.
		if ( strlen( $auth ) < 55 || ! hash_equals( hash( 'sha256', $rp_id, true ), substr( $auth, 0, 32 ) ) ) {
			return $fail;
		}
		$flags = ord( $auth[32] );
		if ( ! ( $flags & 0x01 ) || ! ( $flags & 0x40 ) ) {
			return $fail; // User not present, or no credential data attached.
		}
		$count  = unpack( 'N', substr( $auth, 33, 4 ) )[1];
		$id_len = unpack( 'n', substr( $auth, 53, 2 ) )[1];
		$id     = substr( $auth, 55, $id_len );
		$cose   = self::cbor( substr( $auth, 55 + $id_len ) );
		$pem    = is_array( $cose ) ? self::cose_to_pem( $cose ) : '';
		if ( $id_len < 1 || strlen( $id ) !== $id_len || '' === $pem ) {
			return $fail;
		}
		return [
			'id'    => self::b64url( $id ),
			'pem'   => $pem,
			'count' => (int) $count,
		];
	}

	/**
	 * Options for `navigator.credentials.get()` at sign-in.
	 *
	 * @param int    $user_id   User id.
	 * @param string $challenge Challenge (base64url).
	 * @return array
	 */
	public static function login_options( $user_id, $challenge ) {
		$allow = [];
		foreach ( array_keys( self::all( $user_id ) ) as $id ) {
			$allow[] = [
				'type' => 'public-key',
				'id'   => $id,
			];
		}
		return [
			'challenge'        => $challenge,
			'rpId'             => self::rp_id(),
			'allowCredentials' => $allow,
			'userVerification' => 'preferred',
			'timeout'          => 60000,
		];
	}

	/**
	 * Check a sign-in response against the user's passkeys.
	 *
	 * @param int    $user_id   User id.
	 * @param string $challenge Challenge issued for this sign-in (base64url).
	 * @param array  $response  id, client, auth, sig — all base64url.
	 * @return bool
	 */
	public static function verify( $user_id, $challenge, array $response ) {
		$keys = self::all( $user_id );
		$id   = isset( $response['id'] ) ? (string) $response['id'] : '';
		if ( '' === $challenge || ! isset( $keys[ $id ] ) ) {
			return false;
		}
		$count = self::check_assertion(
			$keys[ $id ]['k'],
			(int) $keys[ $id ]['n'],
			self::b64url_decode( isset( $response['client'] ) ? $response['client'] : '' ),
			self::b64url_decode( isset( $response['auth'] ) ? $response['auth'] : '' ),
			self::b64url_decode( isset( $response['sig'] ) ? $response['sig'] : '' ),
			$challenge,
			self::origins(),
			self::rp_id()
		);
		if ( false === $count ) {
			return false;
		}
		$keys[ $id ]['n'] = $count;
		update_user_meta( $user_id, self::META, $keys );
		return true;
	}

	/**
	 * Pure check of a sign-in response.
	 *
	 * @param string   $pem        Stored public key.
	 * @param int      $known      Stored signature counter.
	 * @param string   $client_raw clientDataJSON bytes.
	 * @param string   $auth       authenticatorData bytes.
	 * @param string   $signature  Signature bytes.
	 * @param string   $challenge  Expected challenge (base64url).
	 * @param string[] $origins    Accepted origins.
	 * @param string   $rp_id      Relying-party id.
	 * @return int|false The new counter, or false when the response is not valid.
	 */
	public static function check_assertion( $pem, $known, $client_raw, $auth, $signature, $challenge, array $origins, $rp_id ) {
		if ( ! self::client_data_ok( $client_raw, 'webauthn.get', $challenge, $origins ) ) {
			return false;
		}
		if ( strlen( $auth ) < 37 || ! hash_equals( hash( 'sha256', $rp_id, true ), substr( $auth, 0, 32 ) ) || ! ( ord( $auth[32] ) & 0x01 ) ) {
			return false;
		}
		if ( 1 !== openssl_verify( $auth . hash( 'sha256', $client_raw, true ), $signature, $pem, OPENSSL_ALGO_SHA256 ) ) {
			return false;
		}
		$count = (int) unpack( 'N', substr( $auth, 33, 4 ) )[1];
		// A counter that does not move forward means the key was copied. Authenticators that do not count report zero.
		if ( ( $count || $known ) && $count <= $known ) {
			return false;
		}
		return $count;
	}

	/**
	 * Whether clientDataJSON is of the expected type, for this challenge and this site.
	 *
	 * @param string   $raw       clientDataJSON bytes.
	 * @param string   $type      webauthn.create | webauthn.get.
	 * @param string   $challenge Expected challenge (base64url).
	 * @param string[] $origins   Accepted origins.
	 * @return bool
	 */
	private static function client_data_ok( $raw, $type, $challenge, array $origins ) {
		$data = json_decode( $raw, true );
		return is_array( $data )
			&& '' !== $challenge
			&& isset( $data['type'], $data['challenge'], $data['origin'] )
			&& $type === $data['type']
			&& hash_equals( $challenge, (string) $data['challenge'] )
			&& in_array( $data['origin'], $origins, true );
	}

	/**
	 * Turn a COSE public key into a PEM key OpenSSL can use.
	 *
	 * @param array $cose Decoded COSE key.
	 * @return string PEM, or '' for a key type that is not supported.
	 */
	public static function cose_to_pem( array $cose ) {
		$kty = isset( $cose[1] ) ? $cose[1] : 0;

		// EC2, P-256 (ES256).
		if ( 2 === $kty && isset( $cose[-1], $cose[-2], $cose[-3] ) && 1 === $cose[-1] && 32 === strlen( $cose[-2] ) && 32 === strlen( $cose[-3] ) ) {
			$der = hex2bin( '3059301306072a8648ce3d020106082a8648ce3d030107034200' ) . "\x04" . $cose[-2] . $cose[-3];
			return self::pem( $der );
		}
		// RSA (RS256).
		if ( 3 === $kty && isset( $cose[-1], $cose[-2] ) && strlen( $cose[-1] ) >= 256 ) {
			$key = self::der( 0x30, self::der_int( $cose[-1] ) . self::der_int( $cose[-2] ) );
			$der = self::der( 0x30, hex2bin( '300d06092a864886f70d0101010500' ) . self::der( 0x03, "\x00" . $key ) );
			return self::pem( $der );
		}
		return '';
	}

	/**
	 * Wrap DER bytes as a PEM public key.
	 *
	 * @param string $der DER bytes.
	 * @return string
	 */
	private static function pem( $der ) {
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- PEM is base64 by definition.
		return "-----BEGIN PUBLIC KEY-----\n" . chunk_split( base64_encode( $der ), 64, "\n" ) . "-----END PUBLIC KEY-----\n";
	}

	/**
	 * One DER element.
	 *
	 * @param int    $tag     Tag byte.
	 * @param string $content Content bytes.
	 * @return string
	 */
	private static function der( $tag, $content ) {
		$len = strlen( $content );
		if ( $len < 128 ) {
			$head = chr( $len );
		} else {
			$bytes = ltrim( pack( 'N', $len ), "\x00" );
			$head  = chr( 0x80 | strlen( $bytes ) ) . $bytes;
		}
		return chr( $tag ) . $head . $content;
	}

	/**
	 * A positive DER integer from big-endian bytes.
	 *
	 * @param string $bytes Big-endian bytes.
	 * @return string
	 */
	private static function der_int( $bytes ) {
		$bytes = ltrim( $bytes, "\x00" );
		if ( '' === $bytes || ( ord( $bytes[0] ) & 0x80 ) ) {
			$bytes = "\x00" . $bytes;
		}
		return self::der( 0x02, $bytes );
	}

	/**
	 * Decode the first CBOR item in a byte string. Covers what WebAuthn
	 * uses: integers, byte and text strings, arrays and maps.
	 *
	 * @param string $data   Bytes.
	 * @param int    $offset Where to start; moved past the item.
	 * @param int    $depth  Nesting depth (guards against hostile input).
	 * @return mixed Null when the bytes are not valid.
	 */
	public static function cbor( $data, &$offset = 0, $depth = 0 ) {
		if ( $depth > 8 || $offset >= strlen( $data ) ) {
			return null;
		}
		$first = ord( $data[ $offset++ ] );
		$major = $first >> 5;
		$info  = $first & 0x1f;

		if ( $info < 24 ) {
			$value = $info;
		} elseif ( $info <= 27 ) {
			$size = 1 << ( $info - 24 );
			if ( $offset + $size > strlen( $data ) ) {
				return null;
			}
			$value = 0;
			for ( $i = 0; $i < $size; $i++ ) {
				$value = ( $value << 8 ) | ord( $data[ $offset++ ] );
			}
		} else {
			return null; // Indefinite lengths are not used by WebAuthn.
		}

		switch ( $major ) {
			case 0:
				return $value;
			case 1:
				return -1 - $value;
			case 2:
			case 3:
				if ( $value < 0 || $offset + $value > strlen( $data ) ) {
					return null;
				}
				$bytes   = substr( $data, $offset, $value );
				$offset += $value;
				return $bytes;
			case 4:
				$list = [];
				for ( $i = 0; $i < $value && $i < 64; $i++ ) {
					$list[] = self::cbor( $data, $offset, $depth + 1 );
				}
				return $list;
			case 5:
				$map = [];
				for ( $i = 0; $i < $value && $i < 64; $i++ ) {
					$key = self::cbor( $data, $offset, $depth + 1 );
					if ( ! is_int( $key ) && ! is_string( $key ) ) {
						return null;
					}
					$map[ $key ] = self::cbor( $data, $offset, $depth + 1 );
				}
				return $map;
		}
		return null;
	}

	/**
	 * Base64url encode.
	 *
	 * @param string $bytes Bytes.
	 * @return string
	 */
	public static function b64url( $bytes ) {
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- WebAuthn transports binary values as base64url.
		return rtrim( strtr( base64_encode( $bytes ), '+/', '-_' ), '=' );
	}

	/**
	 * Base64url decode.
	 *
	 * @param string $text Base64url text.
	 * @return string Bytes ('' when not valid).
	 */
	public static function b64url_decode( $text ) {
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- reverses b64url().
		$bytes = base64_decode( strtr( (string) $text, '-_', '+/' ), true );
		return false === $bytes ? '' : $bytes;
	}
}
