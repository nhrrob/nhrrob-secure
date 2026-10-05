<?php
/**
 * Two-factor authentication.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Services;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Core\Activity;
use NHRRob\Secure\Core\Settings;

/**
 * Per-user second step at sign-in: an authenticator app or an emailed code,
 * with recovery codes.
 *
 * Setup always ends with the user entering a working code, so nobody can
 * switch it on and lock themselves out. The sign-in challenge allows five
 * tries. App secrets are encrypted at rest with a key derived from the site
 * salts.
 */
class TwoFactor {

	const META_ENABLED  = 'nhrrob_secure_2fa_enabled';
	const META_METHOD   = 'nhrrob_secure_2fa_method';
	const META_SECRET   = 'nhrrob_secure_2fa_secret';
	const META_RECOVERY = 'nhrrob_secure_2fa_recovery_codes';
	const META_PENDING  = 'nhrrob_secure_2fa_pending';
	const META_STEP     = 'nhrrob_secure_2fa_last_step';
	const META_DUE      = 'nhrrob_secure_2fa_due';
	const META_TRUSTED  = 'nhrrob_secure_2fa_trusted';
	const META_FAILS    = 'nhrrob_secure_2fa_fails';

	const ACTION       = 'nhrrob_secure_2fa';
	const MAX_ATTEMPTS = 5;
	const CHALLENGE    = 10 * MINUTE_IN_SECONDS;

	/**
	 * Id of the user this request authenticated with an application password (0 for none).
	 *
	 * @var int
	 */
	private $app_password_user = 0;

	/**
	 * Register the hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		$enabled = (bool) Settings::get( 'twofa_enabled' );
		// Two-factor state is user meta, shared by every site of a network. A user who
		// enrolled on one site must be challenged on all of them, or signing in through
		// a site where the feature is off would skip the second step.
		if ( ! $enabled && ! is_multisite() ) {
			return;
		}
		if ( $enabled ) {
			add_action( 'show_user_profile', [ $this, 'render_profile' ] );
			add_action( 'edit_user_profile', [ $this, 'render_profile' ] );
			// Outside wp-admin: a shortcode for any page, and WooCommerce's "Account details".
			add_shortcode( 'nhrrob_secure_2fa', [ $this, 'shortcode' ] );
			add_action( 'woocommerce_after_edit_account_form', [ $this, 'render_front' ] );
		}

		if ( Settings::safe_mode() ) {
			return;
		}
		add_action( 'application_password_did_authenticate', [ $this, 'flag_app_password' ] );
		add_filter( 'authenticate', [ $this, 'challenge' ], 50, 3 );
		add_action( 'login_form_' . self::ACTION, [ $this, 'handle_challenge' ] );
		add_filter( 'wp_login_errors', [ $this, 'expired_notice' ] );
		if ( $enabled ) {
			add_action( 'admin_init', [ $this, 'enforce' ] );
		}
	}

	// ---- State. ----

	/**
	 * Whether a user has two-factor switched on.
	 *
	 * @param int $user_id User id.
	 * @return bool
	 */
	public static function is_on( $user_id ) {
		return (bool) get_user_meta( $user_id, self::META_ENABLED, true );
	}

	/**
	 * The method a user chose: 'app' or 'email'.
	 *
	 * @param int $user_id User id.
	 * @return string
	 */
	public static function method( $user_id ) {
		$method = (string) get_user_meta( $user_id, self::META_METHOD, true );
		if ( in_array( $method, [ 'app', 'email', 'passkey' ], true ) ) {
			return $method;
		}
		// Accounts set up before 2.0 had one site-wide method.
		$allowed = (array) Settings::get( 'twofa_methods' );
		return get_user_meta( $user_id, self::META_SECRET, true ) && in_array( 'app', $allowed, true ) ? 'app' : (string) reset( $allowed );
	}

	/**
	 * The methods users can choose on this site. Passkeys need HTTPS and OpenSSL.
	 *
	 * @return string[]
	 */
	public static function methods() {
		$methods = (array) Settings::get( 'twofa_methods' );
		if ( ! Passkeys::available() ) {
			$methods = array_diff( $methods, [ 'passkey' ] );
		}
		return array_values( $methods );
	}

	/**
	 * Whether a user's role requires two-factor.
	 *
	 * @param \WP_User $user User.
	 * @return bool
	 */
	public static function is_required( $user ) {
		return (bool) array_intersect( (array) $user->roles, (array) Settings::get( 'twofa_roles' ) );
	}

	/**
	 * What the profile screen and the Users list need to know about a user.
	 *
	 * @param \WP_User $user User.
	 * @return array
	 */
	public static function status( $user ) {
		$codes = get_user_meta( $user->ID, self::META_RECOVERY, true );
		$due   = (int) get_user_meta( $user->ID, self::META_DUE, true );
		return [
			'enabled'   => self::is_on( $user->ID ),
			'method'    => self::is_on( $user->ID ) ? self::method( $user->ID ) : '',
			'required'  => self::is_required( $user ),
			'due'       => $due,
			'recovery'  => is_array( $codes ) ? count( $codes ) : 0,
			'methods'   => self::methods(),
			'email'     => $user->user_email,
			'safe_mode' => Settings::safe_mode(),
			'trusted'   => count( self::trusted( $user->ID ) ),
			'passkeys'  => array_values( wp_list_pluck( Passkeys::all( $user->ID ), 'l' ) ),
		];
	}

	// ---- Setup. ----

	/**
	 * Start setup: create a secret (app) or email a code (email).
	 *
	 * @param \WP_User $user   User.
	 * @param string   $method 'app' or 'email'.
	 * @return array|\WP_Error What the setup screen needs to show.
	 */
	public static function begin( $user, $method ) {
		if ( ! in_array( $method, self::methods(), true ) ) {
			return new \WP_Error( 'nhrrob_secure_2fa_method', __( 'That method is not available on this site.', 'nhrrob-secure' ), [ 'status' => 400 ] );
		}

		if ( 'passkey' === $method ) {
			update_user_meta( $user->ID, self::META_PENDING, [ 'm' => 'passkey' ] );
			return [
				'method'  => 'passkey',
				'options' => Passkeys::register_options( $user ),
			];
		}

		if ( 'app' === $method ) {
			$secret = Totp::generate_secret();
			update_user_meta(
				$user->ID,
				self::META_PENDING,
				[
					'm' => 'app',
					's' => self::encrypt( $secret ),
				]
			);
			return [
				'method' => 'app',
				'secret' => $secret,
				'uri'    => Totp::uri( $secret, $user->user_email, wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ),
			];
		}

		$code = self::email_code( $user );
		update_user_meta(
			$user->ID,
			self::META_PENDING,
			[
				'm' => 'email',
				'h' => wp_hash_password( $code ),
				'x' => time() + self::CHALLENGE,
			]
		);
		return [ 'method' => 'email' ];
	}

	/**
	 * Finish setup: the user proves the method works, then it switches on.
	 *
	 * @param \WP_User $user User.
	 * @param string   $code Code from the app or the email.
	 * @return array|\WP_Error New recovery codes, shown once.
	 */
	public static function confirm( $user, $code ) {
		$pending = get_user_meta( $user->ID, self::META_PENDING, true );
		$code    = preg_replace( '/\s+/', '', (string) $code );
		$valid   = false;

		if ( is_array( $pending ) && 'app' === $pending['m'] ) {
			$secret = self::decrypt( $pending['s'] );
			$step   = Totp::verify( $secret, $code );
			if ( $step ) {
				$valid = true;
				update_user_meta( $user->ID, self::META_SECRET, self::encrypt( $secret ) );
				update_user_meta( $user->ID, self::META_STEP, $step );
			}
		} elseif ( is_array( $pending ) && 'email' === $pending['m'] ) {
			$valid = time() < (int) $pending['x'] && wp_check_password( $code, $pending['h'] );
			if ( $valid ) {
				delete_user_meta( $user->ID, self::META_SECRET );
			}
		}

		if ( ! $valid ) {
			return new \WP_Error( 'nhrrob_secure_2fa_code', __( 'That code is not right. Check it and try again.', 'nhrrob-secure' ), [ 'status' => 400 ] );
		}

		update_user_meta( $user->ID, self::META_METHOD, $pending['m'] );
		update_user_meta( $user->ID, self::META_ENABLED, 1 );
		delete_user_meta( $user->ID, self::META_PENDING );
		delete_user_meta( $user->ID, self::META_DUE );
		self::factor_changed( $user );

		return [ 'recovery_codes' => self::new_recovery_codes( $user->ID ) ];
	}

	/**
	 * Finish passkey setup: store the new passkey, then switch two-factor on.
	 *
	 * @param \WP_User $user        User.
	 * @param string   $client      clientDataJSON, base64url.
	 * @param string   $attestation attestationObject, base64url.
	 * @param string   $label       Name for the passkey.
	 * @return array|\WP_Error New recovery codes, shown once.
	 */
	public static function confirm_passkey( $user, $client, $attestation, $label ) {
		$pending = get_user_meta( $user->ID, self::META_PENDING, true );
		if ( ! is_array( $pending ) || 'passkey' !== $pending['m'] || ! in_array( 'passkey', self::methods(), true ) ) {
			return new \WP_Error( 'nhrrob_secure_2fa_method', __( 'Start the passkey setup again.', 'nhrrob-secure' ), [ 'status' => 400 ] );
		}
		$stored = Passkeys::register( $user, $client, $attestation, $label );
		if ( is_wp_error( $stored ) ) {
			return $stored;
		}
		update_user_meta( $user->ID, self::META_METHOD, 'passkey' );
		update_user_meta( $user->ID, self::META_ENABLED, 1 );
		delete_user_meta( $user->ID, self::META_PENDING );
		delete_user_meta( $user->ID, self::META_SECRET );
		delete_user_meta( $user->ID, self::META_DUE );
		self::factor_changed( $user );

		return [ 'recovery_codes' => self::new_recovery_codes( $user->ID ) ];
	}

	/**
	 * Switch two-factor off for a user and forget their secret.
	 *
	 * @param \WP_User $user User.
	 * @return void
	 */
	public static function disable( $user ) {
		foreach ( [ self::META_ENABLED, self::META_METHOD, self::META_SECRET, self::META_RECOVERY, self::META_PENDING, self::META_STEP, self::META_DUE, self::META_TRUSTED, self::META_FAILS, Passkeys::META ] as $key ) {
			delete_user_meta( $user->ID, $key );
		}
		Activity::record( 'user', '2fa_off', $user->user_login, Activity::WARNING );
		self::notify_user(
			$user,
			__( 'Two-factor was switched off for your account', 'nhrrob-secure' ),
			[ __( 'Two-factor authentication is now off for your account. If you did not do this, change your password and contact the site administrator.', 'nhrrob-secure' ) ]
		);
	}

	/**
	 * After a second step was set up or replaced: forget trusted browsers and
	 * failure counts, log it and tell the account's owner.
	 *
	 * @param \WP_User $user User.
	 * @return void
	 */
	private static function factor_changed( $user ) {
		delete_user_meta( $user->ID, self::META_TRUSTED );
		delete_user_meta( $user->ID, self::META_FAILS );
		Activity::record( 'user', '2fa_on', $user->user_login, Activity::INFO );
		self::notify_user(
			$user,
			__( 'Two-factor was set up for your account', 'nhrrob-secure' ),
			[ __( 'A second sign-in step was just set up or replaced for your account. If you did not do this, change your password and contact the site administrator.', 'nhrrob-secure' ) ]
		);
	}

	/**
	 * Replace a user's recovery codes.
	 *
	 * @param int $user_id User id.
	 * @return string[] The new codes in plain text, to show once.
	 */
	public static function new_recovery_codes( $user_id ) {
		$plain  = [];
		$hashed = [];
		for ( $i = 0; $i < 8; $i++ ) {
			$code     = strtolower( wp_generate_password( 10, false ) );
			$plain[]  = $code;
			$hashed[] = wp_hash_password( $code );
		}
		update_user_meta( $user_id, self::META_RECOVERY, $hashed );
		return $plain;
	}

	/**
	 * Create and email a six-digit code.
	 *
	 * @param \WP_User $user User.
	 * @return string The code.
	 */
	private static function email_code( $user ) {
		$code = str_pad( (string) random_int( 0, 999999 ), 6, '0', STR_PAD_LEFT );
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		wp_mail(
			$user->user_email,
			/* translators: %s: site name. */
			sprintf( __( '[%s] Your sign-in code', 'nhrrob-secure' ), $site ),
			/* translators: %s: six-digit code. */
			sprintf( __( 'Your sign-in code is: %s', 'nhrrob-secure' ), $code ) . "\n\n" .
			__( 'It works for 10 minutes. If you did not try to sign in, change your password.', 'nhrrob-secure' )
		);
		return $code;
	}

	// ---- Encryption of app secrets. ----

	/**
	 * Key derived from the site salts.
	 *
	 * @param string|null $material The salt text to derive from; the site's current one when null.
	 * @return string 32 bytes.
	 */
	private static function key( $material = null ) {
		return hash( 'sha256', ( null === $material ? wp_salt( 'auth' ) : $material ) . '|nhrrob_secure_2fa', true );
	}

	/**
	 * Encrypt a secret for storage.
	 *
	 * @param string      $plain    Plain secret.
	 * @param string|null $material Salt text of keys that are about to replace the current ones (key rotation only).
	 * @return string
	 */
	public static function encrypt( $plain, $material = null ) {
		$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- binary ciphertext stored as text in user meta.
		return 'v1:' . base64_encode( $nonce . sodium_crypto_secretbox( $plain, $nonce, self::key( $material ) ) );
	}

	/**
	 * Decrypt a stored secret. Secrets saved before 2.0 are plain base32 and
	 * are returned as they are.
	 *
	 * @param string $stored Stored value.
	 * @return string Plain secret, or '' when it cannot be read (the salts changed).
	 */
	public static function decrypt( $stored ) {
		$stored = (string) $stored;
		if ( 0 !== strpos( $stored, 'v1:' ) ) {
			return $stored;
		}
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- reverses encrypt().
		$raw = base64_decode( substr( $stored, 3 ), true );
		if ( false === $raw || strlen( $raw ) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
			return '';
		}
		$plain = sodium_crypto_secretbox_open(
			substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ),
			substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ),
			self::key()
		);
		return false === $plain ? '' : $plain;
	}

	// ---- Sign-in challenge. ----

	/**
	 * Note which user this request authenticated with an application password.
	 *
	 * @param \WP_User $user The authenticated user.
	 * @return void
	 */
	public function flag_app_password( $user ) {
		$this->app_password_user = $user instanceof \WP_User ? (int) $user->ID : 0;
	}

	/**
	 * Pure counting of wrong second-step codes for one account. Five within
	 * fifteen minutes put the account's second step on hold, longer each time,
	 * whatever address or challenge they came from.
	 *
	 * @param array $state c: count, t: window start, x: held until, v: level.
	 * @param int   $now   Current time.
	 * @return array { state: array, held: bool }
	 */
	public static function count_wrong_code( array $state, $now ) {
		$state = array_merge(
			[
				'c' => 0,
				't' => 0,
				'x' => 0,
				'v' => 0,
			],
			$state
		);
		if ( $now - (int) $state['t'] > 15 * MINUTE_IN_SECONDS ) {
			$state['c'] = 0;
			$state['t'] = $now;
		}
		++$state['c'];
		$held = $state['c'] >= self::MAX_ATTEMPTS;
		if ( $held ) {
			$state['x'] = $now + min( DAY_IN_SECONDS, 15 * MINUTE_IN_SECONDS * pow( 2, (int) $state['v'] ) );
			$state['v'] = (int) $state['v'] + 1;
			$state['c'] = 0;
		}
		return [
			'state' => $state,
			'held'  => $held,
		];
	}

	/**
	 * Seconds an account's second step is on hold (0 when it is not).
	 *
	 * @param int $user_id User id.
	 * @return int
	 */
	public static function held_for( $user_id ) {
		$state = get_user_meta( $user_id, self::META_FAILS, true );
		return is_array( $state ) && isset( $state['x'] ) ? max( 0, (int) $state['x'] - time() ) : 0;
	}

	/**
	 * Record a wrong second-step code. Every wrong code counts — against the
	 * account, and against the address like a failed sign-in.
	 *
	 * @param \WP_User $user User.
	 * @return bool Whether the account is now on hold.
	 */
	private static function wrong_code( $user ) {
		$state  = get_user_meta( $user->ID, self::META_FAILS, true );
		$result = self::count_wrong_code( is_array( $state ) ? $state : [], time() );
		update_user_meta( $user->ID, self::META_FAILS, $result['state'] );

		if ( Settings::get( 'limit_login' ) ) {
			LoginGuard::register_failure( $user->user_login );
		}
		if ( $result['held'] ) {
			$wait = human_time_diff( time(), (int) $result['state']['x'] );
			Activity::record(
				'login',
				'2fa_failed',
				$user->user_login,
				Activity::CRITICAL,
				[
					'user'   => 0,
					'detail' => $wait,
				]
			);
			self::notify_user(
				$user,
				__( 'Someone has your password', 'nhrrob-secure' ),
				[
					__( 'Somebody entered your correct password and then several wrong two-factor codes. Two-factor stopped them, and the second step for your account is paused for a while.', 'nhrrob-secure' ),
					__( 'If this was not you, change your password now.', 'nhrrob-secure' ),
				]
			);
		}
		return $result['held'];
	}

	/**
	 * Email a user about a change to, or an attack on, their own second step.
	 *
	 * @param \WP_User $user    User.
	 * @param string   $subject Subject, without the site name.
	 * @param string[] $lines   Body lines.
	 * @return void
	 */
	private static function notify_user( $user, $subject, array $lines ) {
		wp_mail(
			$user->user_email,
			sprintf( '[%s] %s', wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ), $subject ),
			implode( "\n\n", $lines )
		);
	}

	/**
	 * After a correct password, hold the sign-in until the second step is done.
	 *
	 * @param mixed  $user     Result of earlier authenticate filters.
	 * @param string $username Submitted username.
	 * @param string $password Submitted password.
	 * @return mixed
	 */
	public function challenge( $user, $username = '', $password = '' ) {
		if ( ! $user instanceof \WP_User || $this->app_password_user === (int) $user->ID || ! self::is_on( $user->ID ) ) {
			return $user;
		}
		// Only a submitted password starts a challenge: an existing session revisiting wp-login.php does not.
		if ( '' === (string) $password ) {
			return $user;
		}
		// Core refuses these accounts at a later priority; do not start a challenge for them.
		if ( is_multisite() && is_user_spammy( $user ) ) {
			return $user;
		}
		// A locked-out address gets no challenge, and neither does an account whose second step is on hold.
		$locked = LoginGuard::locked_error();
		if ( $locked ) {
			return $locked;
		}
		$hold = self::held_for( $user->ID );
		if ( $hold > 0 ) {
			return new \WP_Error(
				'nhrrob_secure_2fa_hold',
				sprintf(
					/* translators: %s: time left, e.g. "12 mins". */
					__( 'Too many wrong two-factor codes for this account. Try again in %s.', 'nhrrob-secure' ),
					human_time_diff( time(), time() + $hold )
				)
			);
		}
		if ( self::is_trusted_browser( $user->ID ) ) {
			EventLogger::$login_kind = 'success_trusted';
			return $user;
		}
		// A password-only API sign-in has no way to show the second step.
		if ( ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return new \WP_Error( 'nhrrob_secure_2fa_required', __( 'This account uses two-factor authentication. Use an application password for API access.', 'nhrrob-secure' ) );
		}

		// phpcs:disable WordPress.Security.NonceVerification -- reading the sign-in form of a visitor who just proved their password.
		$redirect = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : '';
		$remember = ! empty( $_POST['rememberme'] );
		// phpcs:enable

		$data = [
			'u' => $user->ID,
			'r' => $redirect,
			'm' => $remember,
			'a' => 0,
		];
		if ( 'email' === self::method( $user->ID ) ) {
			$data['h'] = wp_hash_password( self::email_code( $user ) );
		} elseif ( 'passkey' === self::method( $user->ID ) ) {
			$data['c'] = Passkeys::b64url( random_bytes( 32 ) );
		}
		$token = wp_generate_password( 40, false );
		set_transient( self::ACTION . '_' . md5( $token ), $data, self::CHALLENGE );

		wp_safe_redirect(
			add_query_arg(
				[
					'action' => self::ACTION,
					'token'  => $token,
				],
				wp_login_url()
			)
		);
		exit;
	}

	/**
	 * Show the code form, or check a submitted code.
	 *
	 * @return void
	 */
	public function handle_challenge() {
		// phpcs:disable WordPress.Security.NonceVerification -- the one-time token issued after the password check authorizes this step.
		$token = isset( $_REQUEST['token'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['token'] ) ) : '';
		$code  = isset( $_POST['nhrrob_secure_code'] ) ? sanitize_text_field( wp_unslash( $_POST['nhrrob_secure_code'] ) ) : null;
		// phpcs:enable
		$key  = self::ACTION . '_' . md5( $token );
		$data = '' !== $token ? get_transient( $key ) : false;
		$user = is_array( $data ) ? get_userdata( (int) $data['u'] ) : false;

		// A challenge issued earlier is void once the address is locked out or the account is on hold.
		if ( ! $user || LoginGuard::locked_error() || self::held_for( $user->ID ) > 0 ) {
			if ( $user ) {
				delete_transient( $key );
			}
			wp_safe_redirect( add_query_arg( 'nhrrob_secure_expired', 1, wp_login_url() ) );
			exit;
		}

		// phpcs:disable WordPress.Security.NonceVerification -- same one-time token.
		$passkey = [];
		foreach ( [ 'id', 'client', 'auth', 'sig' ] as $part ) {
			$passkey[ $part ] = isset( $_POST[ 'nhrrob_secure_pk_' . $part ] ) ? sanitize_text_field( wp_unslash( $_POST[ 'nhrrob_secure_pk_' . $part ] ) ) : '';
		}
		// phpcs:enable

		$error = '';
		if ( null !== $code ) {
			$kind = isset( $data['c'] ) && '' !== $passkey['sig'] && Passkeys::verify( $user->ID, $data['c'], $passkey ) ? 'passkey' : $this->check_code( $user, $code, $data );
			if ( $kind ) {
				delete_transient( $key );
				delete_user_meta( $user->ID, self::META_FAILS );
				// phpcs:ignore WordPress.Security.NonceVerification.Missing -- same one-time token as the code itself.
				if ( ! empty( $_POST['nhrrob_secure_trust'] ) ) {
					self::trust_browser( $user->ID );
				}
				$this->complete( $user, $data, $kind );
			}

			// Counted per account and per address, so a fresh challenge does not buy more guesses.
			$held = self::wrong_code( $user );
			++$data['a'];
			if ( $held || $data['a'] >= self::MAX_ATTEMPTS || LoginGuard::locked_error() ) {
				delete_transient( $key );
				wp_safe_redirect( add_query_arg( 'nhrrob_secure_expired', 1, wp_login_url() ) );
				exit;
			}
			set_transient( $key, $data, self::CHALLENGE );
			$error = __( 'That code is not right. Check it and try again.', 'nhrrob-secure' );
		}

		$this->render_challenge( $token, self::method( $user->ID ), $error, isset( $data['c'] ) ? Passkeys::login_options( $user->ID, $data['c'] ) : [] );
		exit;
	}

	/**
	 * Tell the visitor why they are back at the sign-in form.
	 *
	 * @param \WP_Error $errors Sign-in screen messages.
	 * @return \WP_Error
	 */
	public function expired_notice( $errors ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- a flag that only selects a message.
		if ( isset( $_GET['nhrrob_secure_expired'] ) && $errors instanceof \WP_Error ) {
			$errors->add( 'nhrrob_secure_expired', __( 'The two-factor step expired or had too many wrong codes. Sign in again; after several wrong codes you have to wait first.', 'nhrrob-secure' ), 'message' );
		}
		return $errors;
	}

	/**
	 * Check a code against the user's method, then their recovery codes.
	 *
	 * @param \WP_User $user User.
	 * @param string   $code Submitted code.
	 * @param array    $data Challenge data.
	 * @return string '' when wrong, else how it was verified: success_2fa | recovery.
	 */
	private function check_code( $user, $code, array $data ) {
		$raw  = preg_replace( '/\s+/', '', $code );
		$code = strtolower( $raw );

		if ( isset( $data['h'] ) ) {
			if ( preg_match( '/^\d{6}$/', $code ) && wp_check_password( $code, $data['h'] ) ) {
				return 'success_2fa';
			}
		} else {
			$stored = (string) get_user_meta( $user->ID, self::META_SECRET, true );
			$step   = Totp::verify( self::decrypt( $stored ), $code, (int) get_user_meta( $user->ID, self::META_STEP, true ) );
			if ( $step ) {
				update_user_meta( $user->ID, self::META_STEP, $step );
				// Secrets saved before 2.0 get encrypted the first time they are used.
				if ( 0 !== strpos( $stored, 'v1:' ) ) {
					update_user_meta( $user->ID, self::META_SECRET, self::encrypt( $stored ) );
				}
				return 'success_2fa';
			}
		}

		$codes = get_user_meta( $user->ID, self::META_RECOVERY, true );
		if ( is_array( $codes ) && 10 === strlen( $code ) ) {
			foreach ( $codes as $index => $hash ) {
				// Codes issued before 2.0 were mixed case, so the text is also tried as typed.
				if ( wp_check_password( $code, $hash ) || ( $raw !== $code && wp_check_password( $raw, $hash ) ) ) {
					unset( $codes[ $index ] );
					update_user_meta( $user->ID, self::META_RECOVERY, array_values( $codes ) );
					return 'recovery';
				}
			}
		}
		return '';
	}

	/**
	 * Sign the user in after a correct second step.
	 *
	 * @param \WP_User $user User.
	 * @param array    $data Challenge data.
	 * @param string   $kind How the step was verified.
	 * @return void
	 */
	private function complete( $user, array $data, $kind ) {
		wp_set_auth_cookie( $user->ID, ! empty( $data['m'] ) );
		wp_set_current_user( $user->ID );

		EventLogger::$login_kind = $kind;
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- completing the core sign-in we paused, so plugins relying on it still run.
		do_action( 'wp_login', $user->user_login, $user );

		$requested = ! empty( $data['r'] ) ? $data['r'] : '';
		/** This filter is documented in wp-login.php */
		$redirect = apply_filters( 'login_redirect', $requested ? $requested : admin_url(), $requested, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * Print the code form inside the normal sign-in page frame.
	 *
	 * @param string $token  Challenge token.
	 * @param string $method User's method.
	 * @param string $error  Error to show.
	 * @param array  $passkey Passkey request options (passkey method only).
	 * @return void
	 */
	private function render_challenge( $token, $method, $error, array $passkey = [] ) {
		$errors = new \WP_Error();
		if ( '' !== $error ) {
			$errors->add( 'nhrrob_secure_2fa_code', $error );
		}
		if ( $passkey ) {
			wp_register_script( 'nhrrob-secure-passkey', false, [], NHRROB_SECURE_VERSION, true );
			wp_enqueue_script( 'nhrrob-secure-passkey' );
			wp_add_inline_script( 'nhrrob-secure-passkey', self::passkey_script( $passkey ) );
		}
		login_header( __( 'Two-factor code', 'nhrrob-secure' ), '', $errors );
		?>
		<form name="nhrrob_secure_2fa_form" id="loginform" action="<?php echo esc_url( add_query_arg( 'action', self::ACTION, wp_login_url() ) ); ?>" method="post">
			<?php if ( $passkey ) : ?>
				<p>
					<button type="button" id="nhrrob_secure_pk_go" class="button button-primary button-large" style="float:none;width:100%"><?php esc_html_e( 'Use your passkey', 'nhrrob-secure' ); ?></button>
				</p>
				<p id="nhrrob_secure_pk_error" style="color:#b32d2e;margin:8px 0" hidden><?php esc_html_e( 'The passkey was not accepted or the request was cancelled. Try again, or use a recovery code.', 'nhrrob-secure' ); ?></p>
				<?php foreach ( [ 'id', 'client', 'auth', 'sig' ] as $part ) : ?>
					<input type="hidden" name="nhrrob_secure_pk_<?php echo esc_attr( $part ); ?>" id="nhrrob_secure_pk_<?php echo esc_attr( $part ); ?>" value="" />
				<?php endforeach; ?>
				<p style="margin:16px 0 8px;color:#646970;font-size:13px"><?php esc_html_e( 'No passkey with you? Enter a recovery code:', 'nhrrob-secure' ); ?></p>
			<?php endif; ?>
			<p>
				<label for="nhrrob_secure_code"><?php esc_html_e( 'Code', 'nhrrob-secure' ); ?></label>
				<input type="text" name="nhrrob_secure_code" id="nhrrob_secure_code" class="input" size="20" autocomplete="one-time-code" inputmode="text" autofocus />
			</p>
			<p style="margin:-8px 0 16px;color:#646970;font-size:13px">
				<?php
				if ( 'passkey' === $method ) {
					esc_html_e( 'A recovery code signs you in once.', 'nhrrob-secure' );
				} elseif ( 'email' === $method ) {
					esc_html_e( 'Enter the 6-digit code we just emailed you, or one of your recovery codes.', 'nhrrob-secure' );
				} else {
					esc_html_e( 'Enter the 6-digit code from your authenticator app, or one of your recovery codes.', 'nhrrob-secure' );
				}
				?>
			</p>
			<?php if ( (int) Settings::get( 'twofa_trust_days' ) > 0 ) : ?>
				<p class="forgetmenot" style="margin-bottom:16px">
					<input type="checkbox" name="nhrrob_secure_trust" id="nhrrob_secure_trust" value="1" />
					<label for="nhrrob_secure_trust">
						<?php
						/* translators: %d: number of days. */
						echo esc_html( sprintf( __( 'Don\'t ask again on this browser for %d days', 'nhrrob-secure' ), (int) Settings::get( 'twofa_trust_days' ) ) );
						?>
					</label>
				</p>
			<?php endif; ?>
			<input type="hidden" name="token" value="<?php echo esc_attr( $token ); ?>" />
			<p class="submit">
				<input type="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'nhrrob-secure' ); ?>" />
			</p>
		</form>
		<?php
		login_footer( 'nhrrob_secure_code' );
	}

	/**
	 * The script behind "Use your passkey" on the sign-in step: asks the
	 * browser for the passkey and submits the response with the form.
	 *
	 * @param array $options Request options from Passkeys::login_options().
	 * @return string
	 */
	private static function passkey_script( array $options ) {
		return '( function () {'
			. 'var o = ' . wp_json_encode( $options ) . ';'
			. 'var dec = function ( s ) { s = s.replace( /-/g, "+" ).replace( /_/g, "/" ); var b = atob( s ), a = new Uint8Array( b.length ); for ( var i = 0; i < b.length; i++ ) { a[ i ] = b.charCodeAt( i ); } return a; };'
			. 'var enc = function ( b ) { var a = new Uint8Array( b ), s = ""; for ( var i = 0; i < a.length; i++ ) { s += String.fromCharCode( a[ i ] ); } return btoa( s ).replace( /\\+/g, "-" ).replace( /\\//g, "_" ).replace( /=+$/, "" ); };'
			. 'var set = function ( k, v ) { document.getElementById( "nhrrob_secure_pk_" + k ).value = v; };'
			. 'var go = document.getElementById( "nhrrob_secure_pk_go" );'
			. 'if ( ! go ) { return; }'
			. 'go.addEventListener( "click", function () {'
			. 'var fail = function () { document.getElementById( "nhrrob_secure_pk_error" ).hidden = false; };'
			. 'if ( ! window.PublicKeyCredential ) { fail(); return; }'
			. 'navigator.credentials.get( { publicKey: { challenge: dec( o.challenge ), rpId: o.rpId, timeout: o.timeout, userVerification: o.userVerification, allowCredentials: o.allowCredentials.map( function ( c ) { return { type: c.type, id: dec( c.id ) }; } ) } } )'
			. '.then( function ( c ) { set( "id", enc( c.rawId ) ); set( "client", enc( c.response.clientDataJSON ) ); set( "auth", enc( c.response.authenticatorData ) ); set( "sig", enc( c.response.signature ) ); go.form.submit(); } )'
			. '.catch( fail );'
			. '} );'
			. '} )();';
	}

	// ---- Trusted browsers. ----

	/**
	 * Name of the cookie that marks a trusted browser.
	 *
	 * @return string
	 */
	private static function trust_cookie() {
		return 'nhrrob_secure_trust_' . COOKIEHASH;
	}

	/**
	 * A user's trusted browsers that have not expired: token hash => [ x: expires, c: created, a: browser ].
	 *
	 * @param int $user_id User id.
	 * @return array
	 */
	public static function trusted( $user_id ) {
		$stored = get_user_meta( $user_id, self::META_TRUSTED, true );
		$now    = time();
		return array_filter(
			is_array( $stored ) ? $stored : [],
			function ( $entry ) use ( $now ) {
				return isset( $entry['x'] ) && (int) $entry['x'] > $now;
			}
		);
	}

	/**
	 * Remember this browser so the second step is skipped for a while.
	 *
	 * @param int $user_id User id.
	 * @return void
	 */
	public static function trust_browser( $user_id ) {
		$days = (int) Settings::get( 'twofa_trust_days' );
		if ( $days <= 0 ) {
			return;
		}
		$token   = wp_generate_password( 40, false );
		$expires = time() + $days * DAY_IN_SECONDS;
		$trusted = self::trusted( $user_id );

		$trusted[ hash( 'sha256', $token ) ] = [
			'x' => $expires,
			'c' => time(),
			'a' => isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 120 ) : '',
		];
		// Ten browsers per account is plenty; the oldest go first.
		update_user_meta( $user_id, self::META_TRUSTED, array_slice( $trusted, -10, 10, true ) );
		setcookie( self::trust_cookie(), $user_id . '|' . $token, $expires, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true );
	}

	/**
	 * Whether this browser carries a valid trust token for the user.
	 *
	 * @param int $user_id User id.
	 * @return bool
	 */
	public static function is_trusted_browser( $user_id ) {
		if ( (int) Settings::get( 'twofa_trust_days' ) <= 0 || empty( $_COOKIE[ self::trust_cookie() ] ) ) {
			return false;
		}
		$parts = explode( '|', sanitize_text_field( wp_unslash( $_COOKIE[ self::trust_cookie() ] ) ), 2 );
		if ( 2 !== count( $parts ) || (int) $parts[0] !== (int) $user_id ) {
			return false;
		}
		return isset( self::trusted( $user_id )[ hash( 'sha256', $parts[1] ) ] );
	}

	/**
	 * Forget every trusted browser of a user.
	 *
	 * @param int $user_id User id.
	 * @return void
	 */
	public static function forget_browsers( $user_id ) {
		delete_user_meta( $user_id, self::META_TRUSTED );
	}

	// ---- Requirement for roles, and the profile section. ----

	/**
	 * Ask users in a required role to set up two-factor; after the grace
	 * period, keep them on their profile until they do.
	 *
	 * @return void
	 */
	public function enforce() {
		global $pagenow;
		$user = wp_get_current_user();
		// Form handlers and uploads are left alone: redirecting them would lose what was submitted.
		if ( ! $user->exists() || wp_doing_ajax() || in_array( $pagenow, [ 'admin-post.php', 'async-upload.php' ], true ) || self::is_on( $user->ID ) || ! self::is_required( $user ) ) {
			return;
		}

		$due = (int) get_user_meta( $user->ID, self::META_DUE, true );
		if ( ! $due ) {
			$due = time() + DAY_IN_SECONDS * (int) Settings::get( 'twofa_grace_days' );
			update_user_meta( $user->ID, self::META_DUE, $due );
		}

		$overdue = time() >= $due;
		add_action(
			'admin_notices',
			function () use ( $overdue, $due ) {
				$link = '<a href="' . esc_url( admin_url( 'profile.php#nhrrob-secure-2fa' ) ) . '">' . esc_html__( 'Set it up now', 'nhrrob-secure' ) . '</a>';
				if ( $overdue ) {
					$text = esc_html__( 'Your account must use two-factor authentication. Set it up below to get back to the dashboard.', 'nhrrob-secure' );
				} else {
					/* translators: %s: time left, e.g. "5 days". */
					$text = sprintf( esc_html__( 'Your account must use two-factor authentication. You have %s left to set it up.', 'nhrrob-secure' ), esc_html( human_time_diff( time(), $due ) ) );
				}
				// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- both parts are escaped above.
				echo '<div class="notice notice-' . ( $overdue ? 'error' : 'warning' ) . '"><p>' . $text . ' ' . $link . '</p></div>';
			}
		);

		if ( $overdue && 'profile.php' !== $pagenow ) {
			wp_safe_redirect( admin_url( 'profile.php#nhrrob-secure-2fa' ) );
			exit;
		}
	}

	/**
	 * Load the setup app (script, styles, REST details) wherever it is shown.
	 *
	 * @return void
	 */
	public static function enqueue_setup() {
		$dir   = NHRROB_SECURE_PATH . '/admin/build';
		$asset = $dir . '/profile.asset.php';
		if ( ! file_exists( $asset ) || wp_script_is( 'nhrrob-secure-profile', 'enqueued' ) ) {
			return;
		}
		$meta = require $asset;
		$url  = NHRROB_SECURE_URL . '/admin/build';
		\NHRRob\Secure\Admin\AppPage::jsx_runtime();
		wp_enqueue_script( 'nhrrob-secure-profile', $url . '/profile.js', $meta['dependencies'], $meta['version'], true );
		wp_set_script_translations( 'nhrrob-secure-profile', 'nhrrob-secure' );
		wp_localize_script(
			'nhrrob-secure-profile',
			'nhrrobSecureProfile',
			[
				'restRoot' => esc_url_raw( rest_url() ),
				'nonce'    => wp_create_nonce( 'wp_rest' ),
			]
		);
		if ( file_exists( $dir . '/profile.css' ) ) {
			wp_enqueue_style( 'nhrrob-secure-profile', $url . '/profile.css', [], (string) filemtime( $dir . '/profile.css' ) );
		}
	}

	/**
	 * The `[nhrrob_secure_2fa]` shortcode.
	 *
	 * @return string
	 */
	public function shortcode() {
		ob_start();
		$this->render_front();
		return (string) ob_get_clean();
	}

	/**
	 * Two-factor setup for the signed-in user on the front of the site.
	 *
	 * @return void
	 */
	public function render_front() {
		if ( ! is_user_logged_in() ) {
			echo '<p>' . esc_html__( 'Sign in to set up two-factor authentication.', 'nhrrob-secure' ) . '</p>';
			return;
		}
		self::enqueue_setup();
		echo '<div class="nhrrob-secure-front"><h3 id="nhrrob-secure-2fa">' . esc_html__( 'Two-factor authentication', 'nhrrob-secure' ) . '</h3><div id="nhrrob-secure-2fa-app" class="nhrrob-secure-profile"></div></div>';
	}

	/**
	 * The two-factor section on the profile screen. Users manage their own;
	 * on someone else's profile it only shows the status.
	 *
	 * @param \WP_User $user Profile being shown.
	 * @return void
	 */
	public function render_profile( $user ) {
		$own = get_current_user_id() === $user->ID;
		?>
		<h2 id="nhrrob-secure-2fa"><?php esc_html_e( 'Two-factor authentication', 'nhrrob-secure' ); ?></h2>
		<?php if ( $own ) : ?>
			<div id="nhrrob-secure-2fa-app" class="nhrrob-secure-profile"></div>
		<?php else : ?>
			<p>
				<?php
				if ( self::is_on( $user->ID ) ) {
					esc_html_e( 'This user signs in with two-factor authentication. You can reset it under Tools → Secure → Users & Sessions.', 'nhrrob-secure' );
				} else {
					esc_html_e( 'This user has not set up two-factor authentication.', 'nhrrob-secure' );
				}
				?>
			</p>
			<?php
		endif;
	}
}
