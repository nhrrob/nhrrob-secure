<?php
namespace NHRRob\Secure\Tests;

use NHRRob\Secure\Rest\SecurityController;
use NHRRob\Secure\Services\Access;
use NHRRob\Secure\Services\BotCheck;
use NHRRob\Secure\Services\Checks;
use NHRRob\Secure\Services\EventLogger;
use NHRRob\Secure\Services\Integrity;
use NHRRob\Secure\Services\Permissions;
use NHRRob\Secure\Services\RateLimit;
use NHRRob\Secure\Services\Salts;
use NHRRob\Secure\Services\Sessions;
use NHRRob\Secure\Services\Setup;
use PHPUnit\Framework\TestCase;

/**
 * The decisions behind the 2.1 features, each as a pure function.
 */
class ParityTest extends TestCase {

	private function config() {
		$lines = [ '<?php', "define( 'DB_NAME', 'wp' );" ];
		foreach ( Salts::NAMES as $name ) {
			$lines[] = "define( '" . $name . "',  'old \\' value; with ) tricky \"chars\" for " . $name . "' );";
		}
		$lines[] = "\$table_prefix = 'wp_';";
		return implode( "\n", $lines ) . "\n";
	}

	public function testKeysAreReplacedAndNothingElse() {
		$values = [];
		foreach ( Salts::NAMES as $name ) {
			$values[ $name ] = 'new-$1-\\0' === $name ? '' : 'N3w $1 value {' . $name . '} <>~`+=,.;:/?|';
		}
		$new = Salts::replace( $this->config(), $values );
		$this->assertIsString( $new );
		$this->assertStringContainsString( "define( 'DB_NAME', 'wp' );", $new );
		$this->assertStringContainsString( "\$table_prefix = 'wp_';", $new );
		$this->assertStringNotContainsString( 'old ', $new );
		foreach ( Salts::NAMES as $name ) {
			$this->assertStringContainsString( "define( '" . $name . "', '" . $values[ $name ] . "' );", $new );
		}
		// The result is PHP that parses.
		$this->assertIsArray( token_get_all( $new, TOKEN_PARSE ) );
	}

	public function testKeysAreNotTouchedWhenTheFileIsNotWhatWeExpect() {
		$values = array_fill_keys( Salts::NAMES, 'x' );
		// One key missing.
		$this->assertNull( Salts::replace( str_replace( "define( 'NONCE_SALT'", "// define( 'NONCE_SALTX'", $this->config() ), $values ) );
		// A key defined twice.
		$this->assertNull( Salts::replace( $this->config() . "define( 'AUTH_KEY', 'again' );\n", $values ) );
		// A key that is not a plain string.
		$this->assertNull( Salts::replace( str_replace( "define( 'AUTH_KEY',  'old", "define( 'AUTH_KEY', getenv( 'AUTH_KEY' ) ); // 'old", $this->config() ), $values ) );
		// A value that could break out of the string.
		$this->assertNull( Salts::replace( $this->config(), array_merge( $values, [ 'AUTH_KEY' => "a'b" ] ) ) );
		$this->assertNull( Salts::replace( $this->config(), array_merge( $values, [ 'AUTH_KEY' => 'a\\' ] ) ) );
	}

	public function testRateLimitCountsOnlyTheLimitedPlaces() {
		$this->assertSame( 'login', RateLimit::bucket( 'wp-login.php', '/wp-login.php', [], 'wp-json', false ) );
		$this->assertSame( 'xmlrpc', RateLimit::bucket( 'xmlrpc.php', '/xmlrpc.php', [], 'wp-json', true ) );
		$this->assertSame( 'comment', RateLimit::bucket( 'wp-comments-post.php', '/wp-comments-post.php', [], 'wp-json', false ) );
		$this->assertSame( 'rest', RateLimit::bucket( 'index.php', '/wp-json/wp/v2/posts', [], 'wp-json', false ) );
		$this->assertSame( 'rest', RateLimit::bucket( 'index.php', '/wp-json', [], 'wp-json', false ) );
		$this->assertSame( 'rest', RateLimit::bucket( 'index.php', '/', [ 'rest_route' => '/wp/v2/posts' ], 'wp-json', false ) );
		$this->assertSame( 'search', RateLimit::bucket( 'index.php', '/', [ 's' => 'shoes' ], 'wp-json', false ) );
		// Ordinary page views are never counted.
		$this->assertSame( '', RateLimit::bucket( 'index.php', '/', [], 'wp-json', false ) );
		$this->assertSame( '', RateLimit::bucket( 'index.php', '/blog/wp-json-explained/', [], 'wp-json', false ) );
		$this->assertSame( '', RateLimit::bucket( 'index.php', '/shop/', [ 'orderby' => 'price' ], 'wp-json', false ) );
	}

	public function testBotCheckVerdict() {
		$this->assertTrue( BotCheck::verdict( [ 'success' => true ] ) );
		$this->assertTrue( BotCheck::verdict( [ 'success' => true, 'score' => 0.9 ] ) );
		$this->assertTrue( BotCheck::verdict( [ 'success' => true, 'score' => 0.5 ] ) );
		$this->assertFalse( BotCheck::verdict( [ 'success' => true, 'score' => 0.3 ] ) );
		$this->assertFalse( BotCheck::verdict( [ 'success' => false, 'score' => 0.9 ] ) );
		$this->assertFalse( BotCheck::verdict( null ) );
		$this->assertFalse( BotCheck::verdict( 'ok' ) );
	}

	public function testAbandonedPlugins() {
		$tested = [
			'Current'      => '7.1',
			'Patch'        => '7.1.2',
			'One behind'   => '7.0',
			'Two behind'   => '6.9.4',
			'Three behind' => '6.8',
			'Ancient'      => '5.2',
			'No data'      => '',
		];
		$this->assertSame( [ 'Three behind', 'Ancient' ], Checks::untested( $tested, '7.1.2' ) );
		$this->assertSame( [], Checks::untested( $tested, '' ) );
	}

	public function testServerFilesAreFlaggedOnlyForInjectedRules() {
		$wordpress = "# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule . /index.php [L]\n</IfModule>\n# END WordPress\n";
		$this->assertSame( '', Integrity::server_file_reason( $wordpress, 'example.com' ) );
		// A canonical redirect to the site itself next to a bad-bot rule is not a finding.
		$own = $wordpress . "RewriteCond %{HTTP_USER_AGENT} (baiduspider|yandex) [NC]\nRewriteRule .* - [F]\nRewriteRule ^(.*)$ https://www.example.com/$1 [R=301,L]\n";
		$this->assertSame( '', Integrity::server_file_reason( $own, 'example.com' ) );
		// A commented-out line is not a rule.
		$this->assertSame( '', Integrity::server_file_reason( "# php_value auto_prepend_file /tmp/x.php\n; auto_prepend_file = x\n", 'example.com' ) );

		$this->assertSame( 'redirect', Integrity::server_file_reason( "RewriteCond %{HTTP_REFERER} (google|bing|yahoo) [NC]\nRewriteRule ^(.*)$ http://pills.example.net/in.php [R=302,L]\n", 'example.com' ) );
		$this->assertSame( 'prepend', Integrity::server_file_reason( "php_value auto_prepend_file /home/u/public_html/wp-content/uploads/a.ico\n", 'example.com' ) );
		$this->assertSame( 'prepend', Integrity::server_file_reason( "auto_prepend_file = '/var/www/x.php'\n", 'example.com' ) );
		$this->assertSame( 'handler', Integrity::server_file_reason( "AddHandler application/x-httpd-php .jpg .png\n", 'example.com' ) );
		$this->assertSame( 'handler', Integrity::server_file_reason( "AddType application/x-httpd-php .ico\n", 'example.com' ) );
	}

	public function testOnlyThemeCodeIsCompared() {
		foreach ( [ 'functions.php', 'inc/setup.PHP', 'assets/js/view.js', 'templates/home.html', 'parts/header.htm', 'x.phtml' ] as $file ) {
			$this->assertTrue( Integrity::is_theme_code( $file ), $file );
		}
		// What differs between the copy bundled with WordPress and the WordPress.org release.
		foreach ( [ 'readme.txt', 'style.css', 'style.min.css', 'assets/fonts/a.woff2', 'screenshot.png', 'theme.json' ] as $file ) {
			$this->assertFalse( Integrity::is_theme_code( $file ), $file );
		}
	}

	public function testPermissions() {
		$this->assertTrue( Permissions::is_open( 0777 ) );
		$this->assertTrue( Permissions::is_open( 0666 ) );
		$this->assertFalse( Permissions::is_open( 0775 ) );
		$this->assertFalse( Permissions::is_open( 0644 ) );
		$this->assertFalse( Permissions::is_open( 0600 ) );
		// Only the one bit goes; what the owner and group may do stays.
		$this->assertSame( 0775, Permissions::closed( 0777 ) );
		$this->assertSame( 0664, Permissions::closed( 0666 ) );
		$this->assertSame( 0640, Permissions::closed( 0640 ) );
	}

	public function testOldestSessionsAreTheOnesEnded() {
		$sessions = [
			'a' => [ 'login' => 100 ],
			'b' => [ 'login' => 400 ],
			'c' => [ 'login' => 300 ],
			'd' => [ 'login' => 200 ],
		];
		$this->assertSame( [ 'b', 'c' ], array_keys( Sessions::newest( $sessions, 2 ) ) );
		$this->assertSame( [ 'b' ], array_keys( Sessions::newest( $sessions, 1 ) ) );
		// A limit of nothing never ends the session that was just created.
		$this->assertSame( [ 'b' ], array_keys( Sessions::newest( $sessions, 0 ) ) );
		$this->assertCount( 4, Sessions::newest( $sessions, 10 ) );

		// Three sign-ins in the same second: the list order decides, and the session just created always stays.
		$same = [
			'first'  => [ 'login' => 500 ],
			'second' => [ 'login' => 500 ],
			'third'  => [ 'login' => 500 ],
		];
		$this->assertSame( [ 'second', 'third' ], array_keys( Sessions::newest( $same, 2 ) ) );
		$this->assertSame( [ 'third' ], array_keys( Sessions::newest( $same, 1, 'third' ) ) );
		$this->assertSame( [ 'a', 'b' ], array_keys( Sessions::newest( $sessions, 2, 'a' ) ) );
	}

	public function testAccessEndDate() {
		$this->assertFalse( Access::is_over( 0, 1000 ) );
		$this->assertFalse( Access::is_over( 2000, 1000 ) );
		$this->assertTrue( Access::is_over( 1000, 1000 ) );
		$this->assertTrue( Access::is_over( 500, 1000 ) );
	}

	public function testPastedAddressList() {
		$list = SecurityController::parse_list( "203.0.113.5\n198.51.100.0/24  # office\r\n\n2001:db8::/48, 192.0.2.1 ; 192.0.2.2 # two more\n#only a comment\n" );
		$this->assertSame( [ '203.0.113.5', '198.51.100.0/24', '2001:db8::/48', '192.0.2.1', '192.0.2.2' ], array_column( $list, 'range' ) );
		$this->assertSame( [ '', 'office', 'two more', 'two more', 'two more' ], array_column( $list, 'note' ) );
		$this->assertSame( [], SecurityController::parse_list( '' ) );
	}

	public function testWhichPostChangesAreLogged() {
		$this->assertSame( 'published', EventLogger::post_event( 'publish', 'draft' ) );
		$this->assertSame( 'published', EventLogger::post_event( 'publish', 'future' ) );
		$this->assertSame( 'updated', EventLogger::post_event( 'publish', 'publish' ) );
		$this->assertSame( 'trashed', EventLogger::post_event( 'trash', 'publish' ) );
		$this->assertSame( 'restored', EventLogger::post_event( 'draft', 'trash' ) );
		// Saving a draft, and autosaves, are not events.
		$this->assertSame( '', EventLogger::post_event( 'draft', 'auto-draft' ) );
		$this->assertSame( '', EventLogger::post_event( 'draft', 'draft' ) );
		$this->assertSame( '', EventLogger::post_event( 'inherit', 'new' ) );
	}

	public function testRecommendedSetupOffersOnlyWhatIsStillOff() {
		$recommended = [
			'limit_login'   => [ true, 'a', 'b' ],
			'honeypot'      => [ true, 'c', 'd' ],
			'scan_schedule' => [ 'weekly', 'e', 'f' ],
		];
		$pending     = Setup::pending( $recommended, [ 'limit_login' => true, 'honeypot' => false, 'scan_schedule' => 'daily' ] );
		$this->assertSame( [ 'honeypot' ], array_column( $pending, 'key' ) );
		$pending = Setup::pending( $recommended, [ 'limit_login' => false, 'honeypot' => true, 'scan_schedule' => 'off' ] );
		$this->assertSame( [ 'limit_login', 'scan_schedule' ], array_column( $pending, 'key' ) );
	}
}
