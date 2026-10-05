<?php
/**
 * REST: dashboard, settings and the login screen's data.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Rest;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Core\Activity;
use NHRRob\Secure\Core\Alerts;
use NHRRob\Secure\Core\Ip;
use NHRRob\Secure\Core\Settings;
use NHRRob\Secure\Services\Checks;
use NHRRob\Secure\Services\FileProtection;
use NHRRob\Secure\Services\Firewall;
use NHRRob\Secure\Services\LoginGuard;
use NHRRob\Secure\Services\LoginUrl;
use NHRRob\Secure\Services\Scan;
use NHRRob\Secure\Services\Schedule;
use NHRRob\Secure\Services\Sessions;
use NHRRob\Secure\Services\Setup;
use NHRRob\Secure\Services\Summary;
use NHRRob\Secure\Services\Vulnerabilities;

/**
 * GET  /dashboard         score, checks, stats, recent activity
 * GET  /settings          settings + what the app needs to describe them
 * POST /settings          partial update, validated per key
 * POST /settings/import   replace settings from an export
 * POST /settings/test-alert  send a test alert to the email address and the webhook
 * POST /setup             switch the chosen recommended settings on
 * POST /setup/undo        put back what /setup changed
 * POST /setup/close       keep what was applied, or stop offering the rest
 * GET  /login             addresses locked out now
 * POST /login/unlock      unlock one address (or all)
 */
class SettingsController extends RestController {

	/**
	 * Settings the app may never write directly.
	 *
	 * @var string[]
	 */
	const INTERNAL = [ 'db_version', 'safe_mode', 'request_filter_since', 'ip_rules', 'password_force' ];

	/**
	 * Register the routes.
	 *
	 * @return void
	 */
	public function register() {
		$this->route( '/dashboard', 'GET', [ $this, 'dashboard' ] );
		$this->route( '/settings', 'GET', [ $this, 'get' ] );
		$this->route( '/settings', 'POST', [ $this, 'update' ] );
		$this->route( '/settings/import', 'POST', [ $this, 'import' ] );
		$this->route( '/settings/test-alert', 'POST', [ $this, 'test_alert' ] );
		$this->route( '/setup', 'POST', [ $this, 'setup' ] );
		$this->route( '/setup/undo', 'POST', [ $this, 'setup_undo' ] );
		$this->route( '/setup/close', 'POST', [ $this, 'setup_close' ] );
		$this->route( '/login', 'GET', [ $this, 'lockouts' ] );
		$this->route( '/login/unlock', 'POST', [ $this, 'unlock' ], [ 'ip' => $this->text( false ) ] );
	}

	/**
	 * Dashboard data.
	 *
	 * @return \WP_REST_Response
	 */
	public function dashboard() {
		// The file check makes a few requests to the site itself, so it only runs here when it never has.
		if ( null === Scan::get( 'files' ) ) {
			FileProtection::check();
		}
		$checks   = Checks::run();
		$coverage = Sessions::admin_coverage();
		$vuln     = Vulnerabilities::results();
		$recent   = Activity::query( [ 'per_page' => 5 ] );

		return rest_ensure_response(
			[
				'score'    => Checks::score( $checks ),
				'checks'   => $checks,
				'stats'    => [
					'lockouts'        => LoginGuard::recent_count(),
					'locked_now'      => count( LoginGuard::locked() ),
					'admins'          => $coverage['total'],
					'admins_2fa'      => $coverage['with_2fa'],
					'vulnerabilities' => count( $vuln['items'] ),
					'software'        => $vuln['total'],
					'scan_checked'    => $vuln['checked'],
					'blocked'         => Firewall::blocked_week(),
				],
				'activity' => $recent['items'],
				'notice'   => (string) Settings::get( 'upgrade_notice' ),
				'setup'    => Setup::for_app(),
				'site'     => [
					'name' => wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
					'url'  => home_url( '/' ),
				],
			]
		);
	}

	/**
	 * Settings plus the context the app needs.
	 *
	 * @return \WP_REST_Response
	 */
	public function get() {
		return rest_ensure_response( $this->payload() );
	}

	/**
	 * The settings payload.
	 *
	 * @param array $extra Extra keys to return alongside.
	 * @return array
	 */
	private function payload( array $extra = [] ) {
		$roles = [];
		foreach ( wp_roles()->roles as $key => $role ) {
			$roles[] = [
				'value' => $key,
				'label' => translate_user_role( $role['name'] ),
			];
		}
		return array_merge(
			[
				'settings' => Settings::for_app(),
				'meta'     => [
					'roles'        => $roles,
					'home'         => trailingslashit( home_url() ),
					'login_url'    => LoginUrl::active() ? LoginUrl::url() : '',
					'permalinks'   => '' !== (string) get_option( 'permalink_structure' ),
					'safe_mode'    => Settings::safe_mode(),
					'your_ip'      => Ip::client(),
					'remote_ip'    => Ip::remote(),
					'cloudflare'   => Ip::via_cloudflare(),
					'forwarded'    => isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) || isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ),
					'country'      => Firewall::country(),
					'alert_to'     => Alerts::recipient(),
					'activity'     => Activity::stats(),
					'can_files'    => $this->can_manage_files(),
					'files_server' => FileProtection::server(),
					'files_write'  => FileProtection::can_write(),
					'object_cache' => (bool) wp_using_ext_object_cache(),
				],
			],
			$extra
		);
	}

	/**
	 * Update settings.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function update( $request ) {
		$incoming = array_diff_key( (array) $request->get_json_params(), array_flip( self::INTERNAL ) );
		if ( ! $this->can_manage_files() ) {
			unset( $incoming['protect_files'] );
		}
		return $this->apply( $incoming );
	}

	/**
	 * Replace settings from an exported file.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function import( $request ) {
		$params   = (array) $request->get_json_params();
		$incoming = isset( $params['settings'] ) && is_array( $params['settings'] ) ? $params['settings'] : [];
		$incoming = array_intersect_key( $incoming, Settings::defaults() );
		if ( ! $incoming ) {
			return new \WP_Error( 'nhrrob_secure_import', __( 'That file does not contain Secure settings.', 'nhrrob-secure' ), [ 'status' => 400 ] );
		}

		// Address rules are allowed here, but never one that would block the person importing.
		$rules = isset( $incoming['ip_rules'] ) ? Settings::sanitize_ip_rules( $incoming['ip_rules'] ) : null;
		unset( $incoming['db_version'], $incoming['safe_mode'], $incoming['request_filter_since'], $incoming['ip_rules'], $incoming['turnstile_secret'], $incoming['password_force'] );
		if ( ! $this->can_manage_files() ) {
			unset( $incoming['protect_files'] );
		}

		$response = $this->apply( $incoming );
		if ( is_wp_error( $response ) || null === $rules ) {
			return $response;
		}
		$own   = Ip::client();
		$rules = array_values(
			array_filter(
				$rules,
				function ( $rule ) use ( $own ) {
					return 'allow' === $rule['type'] || ! Ip::in_range( $own, $rule['range'] );
				}
			)
		);
		Settings::set_raw( 'ip_rules', $rules );
		return rest_ensure_response( $this->payload() );
	}

	/**
	 * Validate, store and run the side effects of a settings change.
	 *
	 * @param array $incoming Values to change.
	 * @return \WP_REST_Response|\WP_Error
	 */
	private function apply( array $incoming ) {
		$before = Settings::all();
		$after  = Settings::update( $incoming );
		if ( is_wp_error( $after ) ) {
			return $after;
		}
		$extra = [];

		// A rule that would shut out the person saving it is refused, like a block rule for their own address.
		$agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		if ( $before['blocked_uas'] !== $after['blocked_uas'] && '' !== Firewall::blocked_agent( $agent, (array) $after['blocked_uas'] ) ) {
			Settings::write( $before );
			return new \WP_Error( 'nhrrob_secure_own_agent', __( 'One of those user agents matches the browser you are using, so nothing was changed.', 'nhrrob-secure' ), [ 'status' => 409 ] );
		}
		if ( $after['country_enabled'] && Firewall::country_refused( Firewall::country(), (string) $after['country_mode'], (array) $after['country_list'] ) ) {
			Settings::write( $before );
			return new \WP_Error( 'nhrrob_secure_own_country', __( 'That country rule would refuse the country you are in right now, so nothing was changed.', 'nhrrob-secure' ), [ 'status' => 409 ] );
		}

		// Moved login address: prove it works before leaving it on, and send the owner the address.
		$moved = $after['login_url_enabled'] && ( ! $before['login_url_enabled'] || $before['login_slug'] !== $after['login_slug'] );
		if ( $moved && ! Settings::safe_mode() ) {
			$test = LoginUrl::test( $after['login_slug'] );
			if ( 'failed' === $test ) {
				Settings::write( $before );
				return new \WP_Error( 'nhrrob_secure_login_test', __( 'The new address did not show the sign-in form, so nothing was changed. A caching or redirect rule may be in the way.', 'nhrrob-secure' ), [ 'status' => 409 ] );
			}
			$user = wp_get_current_user();
			wp_mail(
				$user->user_email,
				/* translators: %s: site name. */
				sprintf( __( '[%s] Your new sign-in address', 'nhrrob-secure' ), wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ),
				implode(
					"\n",
					[
						__( 'The sign-in page of your site has moved to:', 'nhrrob-secure' ),
						LoginUrl::url( $after['login_slug'] ),
						'',
						__( 'Bookmark it. wp-login.php now answers "Not found".', 'nhrrob-secure' ),
						__( 'If you ever lose this address, add this line to wp-config.php to get wp-login.php back:', 'nhrrob-secure' ),
						"define( 'NHRROB_SECURE_SAFE_MODE', true );",
					]
				)
			);
			$extra['login_test'] = $test;
		}

		if ( $before['protect_files'] !== $after['protect_files'] && FileProtection::can_write() ) {
			if ( ! FileProtection::apply( $after['protect_files'] ) ) {
				Settings::set_raw( 'protect_files', $before['protect_files'] );
				return new \WP_Error( 'nhrrob_secure_htaccess', __( 'The .htaccess file could not be changed safely, so file protection was left as it was.', 'nhrrob-secure' ), [ 'status' => 500 ] );
			}
			FileProtection::check();
		}

		if ( $before['scan_schedule'] !== $after['scan_schedule'] ) {
			Schedule::sync();
		}
		if ( $before['weekly_summary'] !== $after['weekly_summary'] ) {
			Summary::sync();
		}

		$changed = [];
		foreach ( $after as $key => $value ) {
			if ( $before[ $key ] !== $value && ! in_array( $key, [ 'upgrade_notice', 'request_filter_since', 'turnstile_secret' ], true ) ) {
				$changed[] = str_replace( '_', ' ', $key );
			}
		}
		if ( $changed ) {
			Activity::record( 'setting', 'changed', implode( ', ', array_slice( $changed, 0, 8 ) ), Activity::INFO );
		}

		return rest_ensure_response( $this->payload( $extra ) );
	}

	/**
	 * Send a test alert, so the owner can see that the email address and the webhook work.
	 *
	 * @return \WP_REST_Response
	 */
	public function test_alert() {
		$sent = Alerts::send( __( 'Test alert', 'nhrrob-secure' ), [ __( 'This is a test. Alerts from Secure will arrive like this one.', 'nhrrob-secure' ) ] );
		return rest_ensure_response( [ 'sent' => $sent ] );
	}

	/**
	 * Switch on the recommended settings the owner left ticked.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function setup( $request ) {
		$params = (array) $request->get_json_params();
		$patch  = Setup::patch( array_map( 'sanitize_key', isset( $params['keys'] ) ? (array) $params['keys'] : [] ) );
		if ( ! $patch ) {
			return new \WP_Error( 'nhrrob_secure_setup', __( 'Nothing was selected.', 'nhrrob-secure' ), [ 'status' => 400 ] );
		}
		$previous = array_intersect_key( Settings::all(), $patch );
		$response = $this->apply( $patch );
		if ( ! is_wp_error( $response ) ) {
			Setup::remember( $previous );
		}
		return $response;
	}

	/**
	 * Put back what the recommended setup changed.
	 *
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function setup_undo() {
		$values = Setup::undo_values();
		if ( ! $values ) {
			return new \WP_Error( 'nhrrob_secure_setup', __( 'There is nothing to undo.', 'nhrrob-secure' ), [ 'status' => 400 ] );
		}
		$response = $this->apply( $values );
		if ( ! is_wp_error( $response ) ) {
			Setup::close( false );
		}
		return $response;
	}

	/**
	 * Close the setup card.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response
	 */
	public function setup_close( $request ) {
		$params = (array) $request->get_json_params();
		Setup::close( ! empty( $params['dismiss'] ) );
		return rest_ensure_response( Setup::for_app() );
	}

	/**
	 * Addresses locked out right now.
	 *
	 * @return \WP_REST_Response
	 */
	public function lockouts() {
		return rest_ensure_response( [ 'locked' => LoginGuard::locked() ] );
	}

	/**
	 * Unlock an address (all when none is given).
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return \WP_REST_Response
	 */
	public function unlock( $request ) {
		$ip = (string) $request->get_param( 'ip' );
		if ( LoginGuard::unlock( $ip ) ) {
			Activity::record( 'login', 'unlock', '' !== $ip ? $ip : __( 'all addresses', 'nhrrob-secure' ), Activity::INFO );
		}
		return rest_ensure_response( [ 'locked' => LoginGuard::locked() ] );
	}
}
