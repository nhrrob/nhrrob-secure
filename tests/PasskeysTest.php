<?php
namespace NHRRob\Secure\Tests;

use NHRRob\Secure\Services\Passkeys;
use PHPUnit\Framework\TestCase;
use WP_Mock;

/**
 * WebAuthn responses produced by Node's crypto (tests/fixtures/make-passkey-vectors.js),
 * so the verifier is checked against an independent implementation.
 */
class PasskeysTest extends TestCase {

	protected function setUp(): void {
		WP_Mock::setUp();
		WP_Mock::userFunction( '__' )->andReturnArg( 0 );
		WP_Mock::userFunction( 'is_wp_error' )->andReturnUsing(
			function ( $thing ) {
				return $thing instanceof \WP_Error;
			}
		);
	}

	protected function tearDown(): void {
		WP_Mock::tearDown();
	}

	public function vectors() {
		$all = json_decode( file_get_contents( __DIR__ . '/fixtures/passkey.json' ), true );
		return [ 'ES256' => [ $all['ec'] ], 'RS256' => [ $all['rsa'] ] ];
	}

	/**
	 * @dataProvider vectors
	 */
	public function testRegistrationYieldsTheSameKeyNodeExported( $v ) {
		$parsed = Passkeys::parse_registration(
			Passkeys::b64url_decode( $v['register']['client'] ),
			Passkeys::b64url_decode( $v['register']['attestation'] ),
			$v['register']['challenge'],
			[ $v['origin'] ],
			$v['rpId']
		);
		$this->assertIsArray( $parsed );
		$this->assertSame( $v['credentialId'], $parsed['id'] );
		$this->assertSame( 0, $parsed['count'] );
		$strip = function ( $pem ) {
			return preg_replace( '/\s+/', '', $pem );
		};
		$this->assertSame( $strip( $v['spki'] ), $strip( $parsed['pem'] ) );
	}

	/**
	 * @dataProvider vectors
	 */
	public function testSignInVerifiesAndEveryTamperingIsRefused( $v ) {
		$client = Passkeys::b64url_decode( $v['signin']['client'] );
		$auth   = Passkeys::b64url_decode( $v['signin']['auth'] );
		$sig    = Passkeys::b64url_decode( $v['signin']['sig'] );
		$check  = function ( $pem, $known, $c, $a, $s, $challenge, $origins, $rp ) {
			return Passkeys::check_assertion( $pem, $known, $c, $a, $s, $challenge, $origins, $rp );
		};
		$ok = [ $v['spki'], 0, $client, $auth, $sig, $v['signin']['challenge'], [ $v['origin'] ], $v['rpId'] ];

		$this->assertSame( 7, $check( ...$ok ), 'A genuine response returns the new counter' );

		$wrong_challenge    = $ok;
		$wrong_challenge[5] = 'AAAA';
		$this->assertFalse( $check( ...$wrong_challenge ) );

		$wrong_origin    = $ok;
		$wrong_origin[6] = [ 'https://evil.test' ];
		$this->assertFalse( $check( ...$wrong_origin ) );

		$wrong_rp    = $ok;
		$wrong_rp[7] = 'evil.test';
		$this->assertFalse( $check( ...$wrong_rp ) );

		$tampered_auth    = $ok;
		$tampered_auth[3] = substr( $auth, 0, 33 ) . pack( 'N', 99 );
		$this->assertFalse( $check( ...$tampered_auth ), 'Changing the counter breaks the signature' );

		$bad_sig    = $ok;
		$bad_sig[4] = strrev( $sig );
		$this->assertFalse( $check( ...$bad_sig ) );

		$replayed    = $ok;
		$replayed[1] = 7;
		$this->assertFalse( $check( ...$replayed ), 'A counter that does not move forward is refused' );

		// A registration response cannot be used to sign in.
		$as_create    = $ok;
		$as_create[2] = Passkeys::b64url_decode( $v['register']['client'] );
		$this->assertFalse( $check( ...$as_create ) );
	}

	public function testRegistrationRefusesWrongChallengeOriginAndGarbage() {
		$v    = $this->vectors()['ES256'][0];
		$args = [ Passkeys::b64url_decode( $v['register']['client'] ), Passkeys::b64url_decode( $v['register']['attestation'] ), $v['register']['challenge'], [ $v['origin'] ], $v['rpId'] ];

		$a    = $args;
		$a[2] = 'other';
		$this->assertInstanceOf( \WP_Error::class, Passkeys::parse_registration( ...$a ) );
		$a    = $args;
		$a[3] = [ 'https://evil.test' ];
		$this->assertInstanceOf( \WP_Error::class, Passkeys::parse_registration( ...$a ) );
		$a    = $args;
		$a[4] = 'evil.test';
		$this->assertInstanceOf( \WP_Error::class, Passkeys::parse_registration( ...$a ) );
		$a    = $args;
		$a[1] = random_bytes( 80 );
		$this->assertInstanceOf( \WP_Error::class, Passkeys::parse_registration( ...$a ) );
		$a    = $args;
		$a[1] = '';
		$this->assertInstanceOf( \WP_Error::class, Passkeys::parse_registration( ...$a ) );
	}

	public function testCborDecoderStopsOnHostileInput() {
		$this->assertNull( Passkeys::cbor( '' ) );
		$this->assertNull( Passkeys::cbor( "\x5a\xff\xff\xff\xff" ) ); // Byte string claiming 4 GB.
		// Arrays nested 40 deep: decoding stops at the depth limit instead of recursing on.
		$deep  = Passkeys::cbor( str_repeat( "\x81", 40 ) );
		$depth = 0;
		while ( is_array( $deep ) ) {
			$deep = $deep[0];
			++$depth;
		}
		$this->assertLessThan( 12, $depth );
		$this->assertSame( -7, Passkeys::cbor( "\x26" ) );
		$this->assertSame( [ 'a' => 1 ], Passkeys::cbor( "\xa1\x61\x61\x01" ) );
	}
}
