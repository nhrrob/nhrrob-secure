<?php
namespace NHRRob\Secure\Tests;

use NHRRob\Secure\Services\Totp;
use PHPUnit\Framework\TestCase;

/**
 * RFC 6238 test vectors (SHA-1, truncated to 6 digits) and the replay guard.
 */
class TotpTest extends TestCase {

	/** The RFC's ASCII secret "12345678901234567890" in base32. */
	const SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

	public function testBase32RoundTrip() {
		$this->assertSame( self::SECRET, Totp::base32_encode( '12345678901234567890' ) );
		$this->assertSame( '12345678901234567890', Totp::base32_decode( self::SECRET ) );
		$this->assertSame( '12345678901234567890', Totp::base32_decode( 'gezd gnbv gy3t qojq gezd gnbv gy3t qojq' ) );
		$this->assertSame( '', Totp::base32_decode( 'not base32 !' ) );
	}

	public function testRfcVectors() {
		$vectors = [
			59         => '287082',
			1111111109 => '081804',
			1111111111 => '050471',
			1234567890 => '005924',
			2000000000 => '279037',
		];
		foreach ( $vectors as $time => $code ) {
			$this->assertSame( $code, Totp::code( self::SECRET, intdiv( $time, 30 ) ), "At $time" );
		}
	}

	public function testVerifyAllowsOneStepOfDriftOnly() {
		$now = 1234567890;
		$this->assertSame( intdiv( $now, 30 ), Totp::verify( self::SECRET, '005924', 0, $now ) );
		$this->assertNotSame( 0, Totp::verify( self::SECRET, '005 924', 0, $now + 30 ) );
		$this->assertNotSame( 0, Totp::verify( self::SECRET, '005924', 0, $now - 30 ) );
		$this->assertSame( 0, Totp::verify( self::SECRET, '005924', 0, $now + 90 ) );
		$this->assertSame( 0, Totp::verify( self::SECRET, '12345', 0, $now ) );
		$this->assertSame( 0, Totp::verify( '', '005924', 0, $now ) );
	}

	public function testACodeCannotBeUsedTwice() {
		$now  = 1234567890;
		$step = Totp::verify( self::SECRET, '005924', 0, $now );
		$this->assertSame( 0, Totp::verify( self::SECRET, '005924', $step, $now ) );
	}

	public function testGeneratedSecretIs160BitsOfBase32() {
		$secret = Totp::generate_secret();
		$this->assertSame( 32, strlen( $secret ) );
		$this->assertSame( 20, strlen( Totp::base32_decode( $secret ) ) );
	}
}
