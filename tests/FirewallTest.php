<?php
namespace NHRRob\Secure\Tests;

use NHRRob\Secure\Services\Firewall;
use PHPUnit\Framework\TestCase;
use WP_Mock;

/**
 * The request filter must never match what a normal visitor requests, and
 * must match the probes it exists for.
 */
class FirewallTest extends TestCase {

	protected function setUp(): void {
		WP_Mock::setUp();
		WP_Mock::userFunction( '__' )->andReturnArg( 0 );
	}

	protected function tearDown(): void {
		WP_Mock::tearDown();
	}

	public function testEveryRuleIsAValidPattern() {
		foreach ( Firewall::rules() as $id => $rule ) {
			$this->assertNotFalse( @preg_match( $rule[2], '' ), "Rule $id does not compile" );
		}
	}

	/**
	 * Requests 1.3.3's "advanced firewall" blocked, plus everyday traffic.
	 */
	public function testNormalRequestsAreNeverMatched() {
		$normal = [
			[ '/', '' ],
			[ '/', 's=mini cooper' ],
			[ '/', 's=wine tasting initiative' ],
			[ '/', 's=finish line' ],
			[ '/', 's=how to select a theme from the list' ],
			[ '/', 's=please update my address and set a reminder' ],
			[ '/', 's=union select committee' ],
			[ '/', 's=sleep (8 hours) tips' ],
			[ '/', 's=O\'Reilly or 1 and 2' ],
			[ '/', 'utm_campaign=spring--sale&utm_source=news' ],
			[ '/category/training/', '' ],
			[ '/category/environment/', '' ],
			[ '/product/t-shirt--blue/', '' ],
			[ '/blog/2026/how-to-select-a-theme-from-the-directory/', '' ],
			[ '/wp-json/wp/v2/posts', 'search=administration&per_page=10' ],
			[ '/wp-json/wp/v2/pages/12', '_fields=id,title&context=view' ],
			[ '/wp-admin/admin-ajax.php', 'action=heartbeat' ],
			[ '/wp-content/plugins/akismet/readme.txt', '' ],
			[ '/wp-content/uploads/2026/09/shell-beach.jpg', '' ],
			[ '/.well-known/acme-challenge/a1B2c3', '' ],
			[ '/.well-known/security.txt', '' ],
			[ '/docs/environment-variables/', '' ],
			[ '/git-tutorial/', '' ],
			[ '/shop/', 'orderby=price&min_price=10&max_price=90' ],
			[ '/checkout/', 'key=wc_order_Ab12Cd&order-received=412' ],
			[ '/', 'redirect_to=https://example.com/account/?tab=orders' ],
			[ '/', 'p=12&preview=true&_thumbnail_id=-1' ],
			[ '/feed/', '' ],
			[ '/wp-sitemap-posts-post-1.xml', '' ],
			[ '/backup-services/', '' ],
			[ '/database-design-course/', '' ],
			[ '/', 'q=javascript: the good parts' ],
			[ '/', 'ref=<3 your site' ],
			[ '/upload.php', '' ],
			[ '/contact/', 'subject=Question about eval (evaluation) of my order' ],
		];
		foreach ( $normal as $request ) {
			$this->assertSame( '', Firewall::match( $request[0], $request[1] ), 'Matched a normal request: ' . $request[0] . '?' . $request[1] );
		}
	}

	public function testProbesAreMatched() {
		$hostile = [
			[ '/.env', '', 'config' ],
			[ '/app/.env.production', '', 'config' ],
			[ '/.git/config', '', 'config' ],
			[ '/wp-config.php.bak', '', 'config' ],
			[ '/wp-config.php~', '', 'config' ],
			[ '/wp-config.old', '', 'config' ],
			[ '/backup.sql', '', 'config' ],
			[ '/site.tar.gz', '', 'config' ],
			[ '/wp-content/plugins/x/', 'file=../../../wp-config.php', 'traversal' ],
			[ '/download', 'f=..\\..\\windows\\win.ini', 'traversal' ],
			[ '/', 'page=../../../../etc/passwd', 'traversal' ],
			[ '/alfa.php', '', 'shell' ],
			[ '/wp-content/uploads/wso2.php', '', 'shell' ],
			[ '/', 'id=1\' UNION SELECT user_pass FROM wp_users-- ', 'sqli' ],
			[ '/', 'id=1 union/**/select 1,2,3', 'sqli' ],
			[ '/', 'id=1 AND SLEEP(5)', 'sqli' ],
			[ '/', 'u=admin\' or \'1\'=\'1', 'sqli' ],
			[ '/', 'q=<script>alert(1)</script>', 'xss' ],
			[ '/', 'q=<img src=x onerror=alert(1)>', 'xss' ],
			[ '/', 'next=javascript:alert(document.cookie)', 'xss' ],
			[ '/wp-admin/admin-ajax.php', 'action=x&f=php://filter/convert.base64-encode/resource=index', 'wrapper' ],
			[ '/', 'cmd=system($_GET[0])', 'code' ],
			[ '/', 'x=<?php phpinfo();', 'code' ],
		];
		foreach ( $hostile as $request ) {
			$this->assertSame( $request[2], Firewall::match( $request[0], $request[1] ), 'Missed: ' . $request[0] . '?' . $request[1] );
		}
	}
}
