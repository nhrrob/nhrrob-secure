<?php
namespace NHRRob\Secure\Tests;

use NHRRob\Secure\Core\Ip;
use NHRRob\Secure\Services\Checks;
use NHRRob\Secure\Services\CodeScan;
use NHRRob\Secure\Services\Hardening;
use NHRRob\Secure\Services\LoginGuard;
use NHRRob\Secure\Services\Vulnerabilities;
use PHPUnit\Framework\TestCase;
use WP_Mock;

/**
 * The pure decision rules: addresses, lockouts, signatures, passwords, versions, score.
 */
class RulesTest extends TestCase {

	protected function setUp(): void {
		WP_Mock::setUp();
		WP_Mock::userFunction( '__' )->andReturnArg( 0 );
	}

	protected function tearDown(): void {
		WP_Mock::tearDown();
	}

	public function testAddressRanges() {
		$this->assertTrue( Ip::valid_range( '203.0.113.9' ) );
		$this->assertTrue( Ip::valid_range( '203.0.113.0/24' ) );
		$this->assertTrue( Ip::valid_range( '2001:db8::/48' ) );
		$this->assertFalse( Ip::valid_range( '203.0.113.0/33' ) );
		$this->assertFalse( Ip::valid_range( '2001:db8::/129' ) );
		$this->assertFalse( Ip::valid_range( 'example.com' ) );
		$this->assertFalse( Ip::valid_range( '203.0.113.0/24/8' ) );

		$this->assertTrue( Ip::in_range( '203.0.113.77', '203.0.113.0/24' ) );
		$this->assertFalse( Ip::in_range( '203.0.114.1', '203.0.113.0/24' ) );
		$this->assertTrue( Ip::in_range( '10.1.2.3', '10.0.0.0/8' ) );
		$this->assertTrue( Ip::in_range( '203.0.113.130', '203.0.113.128/25' ) );
		$this->assertFalse( Ip::in_range( '203.0.113.127', '203.0.113.128/25' ) );
		$this->assertTrue( Ip::in_range( '198.51.100.4', '198.51.100.4' ) );
		// IPv6, which 1.3.3 could not match at all.
		$this->assertTrue( Ip::in_range( '2001:db8:42::7a1c', '2001:db8:42::/48' ) );
		$this->assertFalse( Ip::in_range( '2001:db8:43::1', '2001:db8:42::/48' ) );
		$this->assertTrue( Ip::in_range( '::ffff:203.0.113.5', '203.0.113.0/24' ) );
		$this->assertFalse( Ip::in_range( '2001:db8::1', '203.0.113.0/24' ) );
		$this->assertFalse( Ip::in_range( 'garbage', '0.0.0.0/0' ) );
	}

	public function testForwardedHeadersAreOnlyBelievedFromATrustedSource() {
		$cf = '173.245.48.10'; // Inside Cloudflare's published range.

		// Direct: headers never count.
		$this->assertSame( '198.51.100.1', Ip::resolve( '198.51.100.1', [ 'cf' => '8.8.8.8', 'xff' => '9.9.9.9' ], 'direct', [] ) );
		// Cloudflare mode: believed from Cloudflare, ignored from anyone else.
		$this->assertSame( '8.8.8.8', Ip::resolve( $cf, [ 'cf' => '8.8.8.8' ], 'cloudflare', [] ) );
		$this->assertSame( '198.51.100.1', Ip::resolve( '198.51.100.1', [ 'cf' => '8.8.8.8' ], 'cloudflare', [] ) );
		$this->assertSame( $cf, Ip::resolve( $cf, [ 'cf' => 'not-an-ip' ], 'cloudflare', [] ) );
		// Proxy mode with no list: only a local proxy is believed.
		$this->assertSame( '8.8.8.8', Ip::resolve( '10.0.0.5', [ 'xff' => '8.8.8.8' ], 'proxy', [] ) );
		$this->assertSame( '198.51.100.1', Ip::resolve( '198.51.100.1', [ 'xff' => '8.8.8.8' ], 'proxy', [] ) );
		// A visitor cannot plant an address at the front of the chain.
		$this->assertSame( '8.8.8.8', Ip::resolve( '10.0.0.5', [ 'xff' => '1.2.3.4, 8.8.8.8' ], 'proxy', [] ) );
		$this->assertSame( '8.8.8.8', Ip::resolve( '192.0.2.10', [ 'xff' => '1.2.3.4, 8.8.8.8, 192.0.2.11' ], 'proxy', [ '192.0.2.0/24' ] ) );
	}

	public function testLockoutCounting() {
		$policy = [ 'limit' => 5, 'minutes' => 20, 'progressive' => true ];
		$entry  = [ 'c' => 0, 'u' => [], 'l' => 0, 'x' => 0, 'v' => 0 ];
		$now    = 1000000;

		for ( $i = 1; $i <= 4; $i++ ) {
			$result = LoginGuard::count_failure( $entry, 'robin', $now + $i, $policy );
			$entry  = $result['entry'];
			$this->assertFalse( $result['locked'], "Attempt $i must not lock" );
			$this->assertSame( $i, $entry['c'], 'One failure counts once' );
		}
		$result = LoginGuard::count_failure( $entry, 'robin', $now + 5, $policy );
		$this->assertTrue( $result['locked'] );
		$this->assertSame( $now + 5 + 20 * 60, $result['entry']['x'] );

		// A second lockout the same day doubles.
		$again = LoginGuard::count_failure( $result['entry'], 'robin', $now + 3000, $policy );
		$this->assertTrue( $again['locked'] );
		$this->assertSame( $now + 3000 + 40 * 60, $again['entry']['x'] );

		// Many different usernames lock too, at three times the limit.
		$entry = [ 'c' => 0, 'u' => [], 'l' => 0, 'x' => 0, 'v' => 0 ];
		for ( $i = 1; $i <= 15; $i++ ) {
			$result = LoginGuard::count_failure( $entry, 'user' . $i, $now + $i, $policy );
			$entry  = $result['entry'];
		}
		$this->assertTrue( $result['locked'] );
		$this->assertCount( 10, $entry['u'], 'The username list is capped' );

		// A quiet hour forgives earlier failures.
		$entry  = [ 'c' => 4, 'u' => [ 'robin' => 4 ], 'l' => $now, 'x' => 0, 'v' => 0 ];
		$result = LoginGuard::count_failure( $entry, 'robin', $now + 3601, $policy );
		$this->assertFalse( $result['locked'] );
		$this->assertSame( 1, $result['entry']['c'] );
	}

	public function testCodeSignatures() {
		$clean = [
			'<?php WP_Filesystem(); $wp_filesystem->put_contents( $file, $data );',
			'<?php $result = $this->filesystem( $path );',
			'<?php ecosystem( $a ); request_filesystem_credentials( $url );',
			'<?php $ok = $process->exec( $_POST["cmd_id"] );',
			'<?php $value = base64_decode( $encoded ); $data = json_decode( $value );',
			'<?php if ( function_exists( "shell_exec" ) ) { $out = shell_exec( "git --version" ); }',
			'<?php // Never call eval() on user input.' . "\n" . 'echo esc_html( $_GET["q"] );',
			'<?php $callbacks[ $name ]( $args );',
		];
		foreach ( $clean as $code ) {
			$this->assertSame( '', CodeScan::match( $code ), 'Flagged normal code: ' . $code );
		}

		$this->assertSame( 'obfuscated_eval', CodeScan::match( '<?php eval(base64_decode("ZWNobyAxOw=="));' ) );
		$this->assertSame( 'obfuscated_eval', CodeScan::match( '<?php @eval ( gzinflate( base64_decode( $x ) ) );' ) );
		$this->assertSame( 'input_eval', CodeScan::match( '<?php eval($_POST["c"]);' ) );
		$this->assertSame( 'input_eval', CodeScan::match( '<?php system( $_GET["cmd"] );' ) );
		$this->assertSame( 'input_eval', CodeScan::match( '<?php @assert(stripslashes($_REQUEST["x"]));' ) );
		$this->assertSame( 'variable_call', CodeScan::match( '<?php $_GET["f"]($_POST["a"]);' ) );
		$this->assertSame( 'long_payload', CodeScan::match( '<?php $k = 1; eval(some_decoder("' . str_repeat( 'QUJD', 300 ) . '"));' ) );
		$this->assertSame( 'shell_marker', CodeScan::match( '<?php $default_action = "FilesMan";' ) );
	}

	public function testPasswordRule() {
		$this->assertNotSame( '', Hardening::weak_reason( 'Short1!', 'robin' ) );
		$this->assertNotSame( '', Hardening::weak_reason( 'onlylowercaseletters', 'robin' ) );
		$this->assertNotSame( '', Hardening::weak_reason( 'robin-2026-secure', 'robin' ) );
		$this->assertSame( '', Hardening::weak_reason( 'correct horse battery 9', 'robin' ) );
		$this->assertSame( '', Hardening::weak_reason( 'Tr0ub4dor&3xtra', 'robin' ) );
	}

	public function testVersionRanges() {
		$this->assertTrue( Vulnerabilities::affects( '5.3.1', [ 'max_version' => '5.3.2', 'max_operator' => 'lt' ] ) );
		$this->assertFalse( Vulnerabilities::affects( '5.3.2', [ 'max_version' => '5.3.2', 'max_operator' => 'lt' ] ) );
		$this->assertTrue( Vulnerabilities::affects( '5.3.2', [ 'max_version' => '5.3.2', 'max_operator' => 'le' ] ) );
		$this->assertFalse( Vulnerabilities::affects( '1.0', [ 'min_version' => '2.0', 'min_operator' => 'ge', 'max_version' => '2.5', 'max_operator' => 'lt' ] ) );
		$this->assertTrue( Vulnerabilities::affects( '2.1', [ 'min_version' => '2.0', 'min_operator' => 'ge', 'max_version' => '2.5', 'max_operator' => 'lt' ] ) );
		// No usable range means every version is treated as affected.
		$this->assertTrue( Vulnerabilities::affects( '9.9', [ 'max_version' => null, 'max_operator' => null ] ) );
		$this->assertTrue( Vulnerabilities::affects( '9.9', [ 'max_version' => '1.0', 'max_operator' => 'bogus' ] ) );
	}

	public function testFileChangeDecision() {
		$known = [ 'Plugin', 'aaa', '1.0' ];
		$this->assertSame( 'new', \NHRRob\Secure\Services\Monitor::compare( null, 'aaa', '1.0' ) );
		$this->assertSame( 'same', \NHRRob\Secure\Services\Monitor::compare( $known, 'aaa', '1.0' ) );
		// New code with a new version is an update; new code with the same version is not.
		$this->assertSame( 'updated', \NHRRob\Secure\Services\Monitor::compare( $known, 'bbb', '1.1' ) );
		$this->assertSame( 'changed', \NHRRob\Secure\Services\Monitor::compare( $known, 'bbb', '1.0' ) );
	}

	public function testProbeRules() {
		$probe = [ '/old/wp-login.php', '/.env', '/backup.zip', '/db.sql', '/x/.git/config', '/shell.PHP', '/config.yml', '/site.tar.gz' ];
		foreach ( $probe as $path ) {
			$this->assertTrue( \NHRRob\Secure\Services\Firewall::is_probe_path( $path ), $path );
		}
		// Broken links, images and assets are not probes.
		$normal = [ '/an-old-post/', '/category/news/page/9/', '/wp-content/uploads/2020/01/gone.jpg', '/theme/app.js', '/styles.css', '/feed/', '/favicon.ico', '/robots.txt', '/sitemap.xml' ];
		foreach ( $normal as $path ) {
			$this->assertFalse( \NHRRob\Secure\Services\Firewall::is_probe_path( $path ), $path );
		}

		$entry = [ 'c' => 0, 'u' => [], 'l' => 0, 'x' => 0, 'v' => 0 ];
		for ( $i = 1; $i <= 9; $i++ ) {
			$result = LoginGuard::count_probe( $entry, 1000 + $i );
			$entry  = $result['entry'];
			$this->assertFalse( $result['locked'] );
		}
		$result = LoginGuard::count_probe( $entry, 1010 );
		$this->assertTrue( $result['locked'] );
		$this->assertSame( 1010 + 3600, $result['entry']['x'] );
		$this->assertSame( 1, $result['entry']['p'] );
		// Slow probing never adds up.
		$slow = LoginGuard::count_probe( [ 'c' => 0, 'u' => [], 'l' => 0, 'x' => 0, 'v' => 0, 'q' => 9, 'ql' => 1000 ], 1000 + 601 );
		$this->assertFalse( $slow['locked'] );
		$this->assertSame( 1, $slow['entry']['q'] );
	}

	public function testFormDataRules() {
		$normal = [
			'{"comment":"I will select the best one from the list -- thanks"}',
			'{"message":"Use <script> tags carefully, e.g. <script>alert(1)</script> is the classic test"}',
			'{"your-message":"Our union select committee meets on 1=1 day"}',
			'{"email":"a@b.co","website":"https://example.com/a/../b"}',
		];
		foreach ( $normal as $body ) {
			$this->assertSame( '', \NHRRob\Secure\Services\Firewall::match_body( $body ), $body );
		}
		$this->assertSame( 'traversal', \NHRRob\Secure\Services\Firewall::match_body( '{"file":"../../../wp-config.php"}' ) );
		$this->assertSame( 'wrapper', \NHRRob\Secure\Services\Firewall::match_body( '{"url":"php://filter/convert.base64-encode/resource=x"}' ) );
		$this->assertSame( 'code', \NHRRob\Secure\Services\Firewall::match_body( '{"name":"<?php system($_GET[0]); ?>"}' ) );
	}

	public function testPublicRestRoutes() {
		$public = [ 'oembed/', 'contact-form-7/', 'wc/store/' ];
		$this->assertTrue( Hardening::rest_route_is_public( 'contact-form-7/v1/contact-forms/5/feedback', $public ) );
		$this->assertTrue( Hardening::rest_route_is_public( 'wc/store/v1/cart', $public ) );
		$this->assertFalse( Hardening::rest_route_is_public( 'wp/v2/users', $public ) );
		$this->assertFalse( Hardening::rest_route_is_public( 'wc/v3/orders', $public ) );
		$this->assertFalse( Hardening::rest_route_is_public( '', $public ) );
	}

	public function testPasswordMustChange() {
		$now = 2000000000;
		$day = 86400;
		$m   = [ \NHRRob\Secure\Services\Passwords::class, 'must_change' ];
		// Nothing configured.
		$this->assertFalse( $m( $now - 400 * $day, false, [ 'administrator' ], [], 0, true, $now ) );
		// Asked individually.
		$this->assertTrue( $m( $now, true, [ 'subscriber' ], [], 0, false, $now ) );
		// Expiry: only privileged accounts, only once the days are up.
		$this->assertFalse( $m( $now - 89 * $day, false, [ 'editor' ], [], 90, true, $now ) );
		$this->assertTrue( $m( $now - 91 * $day, false, [ 'editor' ], [], 90, true, $now ) );
		$this->assertFalse( $m( $now - 91 * $day, false, [ 'subscriber' ], [], 90, false, $now ) );
		// Forced for a role or everyone: passwords older than the request, not newer ones.
		$this->assertTrue( $m( $now - 10, false, [ 'author' ], [ 'author' => $now - 5 ], 0, false, $now ) );
		$this->assertFalse( $m( $now - 1, false, [ 'author' ], [ 'author' => $now - 5 ], 0, false, $now ) );
		$this->assertFalse( $m( $now - 10, false, [ 'editor' ], [ 'author' => $now - 5 ], 0, true, $now ) );
		$this->assertTrue( $m( $now - 10, false, [ 'subscriber' ], [ '*' => $now - 5 ], 0, false, $now ) );
	}

	public function testDatabaseSignatures() {
		$clean = [
			'<p>Watch this</p><iframe width="560" height="315" src="https://www.youtube.com/embed/x" frameborder="0"></iframe>',
			'<script async src="https://www.googletagmanager.com/gtag/js?id=G-1"></script><script>window.dataLayer=window.dataLayer||[];</script>',
			'<script>document.write(new Date().getFullYear())</script>',
			'<p>Never use eval() in JavaScript.</p>',
			'a:2:{s:4:"code";s:30:"<script>console.log(1)</script>";}',
		];
		foreach ( $clean as $text ) {
			$this->assertSame( '', \NHRRob\Secure\Services\DatabaseScan::match( $text ), $text );
		}
		$this->assertSame( 'hidden_iframe', \NHRRob\Secure\Services\DatabaseScan::match( '<iframe src="//evil.example/x" style="display:none"></iframe>' ) );
		$this->assertSame( 'hidden_iframe', \NHRRob\Secure\Services\DatabaseScan::match( '<iframe src="//evil.example/x" width="1" height="1"></iframe>' ) );
		$this->assertSame( 'obfuscated_js', \NHRRob\Secure\Services\DatabaseScan::match( '<script>eval(atob("YWxlcnQoMSk="))</script>' ) );
		$this->assertSame( 'obfuscated_js', \NHRRob\Secure\Services\DatabaseScan::match( '<script>document.write(unescape("%3Cscript%3E"))</script>' ) );
		$this->assertSame( 'obfuscated_js', \NHRRob\Secure\Services\DatabaseScan::match( 'String.fromCharCode(' . implode( ',', range( 60, 90 ) ) . ')' ) );
	}

	public function testScoreIsOutOfOneHundred() {
		$check = function ( $passed, $severity ) {
			return [ 'passed' => $passed, 'severity' => $severity ];
		};
		$this->assertSame( 100, Checks::score( [] ) );
		$this->assertSame( 100, Checks::score( [ $check( true, 'critical' ), $check( true, 'low' ) ] ) );
		$this->assertSame( 0, Checks::score( [ $check( false, 'critical' ), $check( false, 'low' ) ] ) );
		// critical 15 + high 10 passed, medium 6 + low 3 failed: 25 of 34.
		$this->assertSame( 74, Checks::score( [ $check( true, 'critical' ), $check( true, 'high' ), $check( false, 'medium' ), $check( false, 'low' ) ] ) );
	}
}
