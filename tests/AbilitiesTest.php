<?php
namespace NHRRob\Secure\Tests;

use NHRRob\Secure\Core\Abilities;
use PHPUnit\Framework\TestCase;
use WP_Mock;

/**
 * What AI agents and MCP clients may ask is a fixed, reviewed list, and all of
 * it is read-only: adding an ability must be a deliberate change to this test.
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
			[ 'nhrrob-secure/get-security-status', 'nhrrob-secure/list-vulnerabilities' ],
			array_keys( ( new Abilities() )->definitions() )
		);
	}

	public function testEveryAbilityIsReadOnlyAndGated() {
		$abilities = new Abilities();
		$gates     = [
			'nhrrob-secure/get-security-status'  => 'can_manage',
			// The Scanner section's gate: super admins only on a network.
			'nhrrob-secure/list-vulnerabilities' => 'can_manage_files',
		];
		foreach ( $abilities->definitions() as $name => $args ) {
			$this->assertSame( [ $abilities, $gates[ $name ] ], $args['permission_callback'], $name );
			$this->assertTrue( $args['meta']['annotations']['readonly'], $name );
			$this->assertFalse( $args['meta']['annotations']['destructive'], $name );
			$this->assertArrayNotHasKey( 'input_schema', $args, $name );
		}
	}

	public function testASiteAdministratorOfANetworkCannotReadScannerResults() {
		WP_Mock::userFunction( 'current_user_can' )->with( 'manage_options' )->andReturn( true );
		WP_Mock::userFunction( 'is_multisite' )->andReturn( true );
		WP_Mock::userFunction( 'is_super_admin' )->andReturn( false );
		$this->assertTrue( ( new Abilities() )->can_manage() );
		$this->assertFalse( ( new Abilities() )->can_manage_files() );
	}
}
