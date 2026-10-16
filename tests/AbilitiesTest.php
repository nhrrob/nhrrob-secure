<?php
namespace NHRRob\Secure\Tests;

use NHRRob\Secure\Core\Abilities;
use PHPUnit\Framework\TestCase;
use WP_Mock;

/**
 * What AI agents and MCP clients may ask is a fixed, reviewed list: adding an
 * ability, or a check apply-fix may fix, must be a deliberate change to this test.
 */
class AbilitiesTest extends TestCase {

	protected function setUp(): void {
		WP_Mock::setUp();
		WP_Mock::userFunction( '__' )->andReturnArg( 0 );
	}

	protected function tearDown(): void {
		WP_Mock::tearDown();
	}

	public function testTheAbilityListIsExactlyTheReviewedOne() {
		$this->assertSame(
			[ 'nhrrob-secure/get-security-status', 'nhrrob-secure/list-vulnerabilities', 'nhrrob-secure/apply-fix' ],
			array_keys( ( new Abilities() )->definitions() )
		);
	}

	public function testEveryAbilityIsGatedAndOnlyApplyFixWrites() {
		$abilities = new Abilities();
		$gates     = [
			'nhrrob-secure/get-security-status'  => 'can_manage',
			// The Scanner section's gate: super admins only on a network.
			'nhrrob-secure/list-vulnerabilities' => 'can_manage_files',
			// File protection asks for the files gate itself.
			'nhrrob-secure/apply-fix'            => 'can_manage',
		];
		foreach ( $abilities->definitions() as $name => $args ) {
			$writes = 'nhrrob-secure/apply-fix' === $name;
			$this->assertSame( [ $abilities, $gates[ $name ] ], $args['permission_callback'], $name );
			$this->assertSame( ! $writes, $args['meta']['annotations']['readonly'], $name );
			$this->assertFalse( $args['meta']['annotations']['destructive'], $name );
			$this->assertSame( $writes, isset( $args['input_schema'] ), $name );
		}
	}

	public function testApplyFixOnlySwitchesSafeSettingsOn() {
		// Each is in the recommended setup or is file protection; none can lock anyone out.
		$this->assertSame(
			[
				'xmlrpc'      => [ 'disable_xmlrpc' => true ],
				'usernames'   => [ 'hide_usernames' => true ],
				'file_editor' => [ 'disable_file_editor' => true ],
				'limit_login' => [ 'limit_login' => true ],
				'files'       => [ 'protect_files' => true ],
			],
			Abilities::FIXES
		);
		$schema = ( new Abilities() )->definitions()['nhrrob-secure/apply-fix']['input_schema'];
		$this->assertSame( array_keys( Abilities::FIXES ), $schema['properties']['check']['enum'] );
	}

	public function testASiteAdministratorOfANetworkCannotReadScannerResults() {
		WP_Mock::userFunction( 'current_user_can' )->with( 'manage_options' )->andReturn( true );
		WP_Mock::userFunction( 'is_multisite' )->andReturn( true );
		WP_Mock::userFunction( 'is_super_admin' )->andReturn( false );
		$this->assertTrue( ( new Abilities() )->can_manage() );
		$this->assertFalse( ( new Abilities() )->can_manage_files() );
	}
}
