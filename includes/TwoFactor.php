<?php

namespace NHRRob\Secure;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}


use RobThree\Auth\TwoFactorAuth;

/**
 * Two-Factor Authentication Handler
 */
class TwoFactor extends App {

    /**
     * @var TwoFactorAuth
     */
    private $tfa;

    /**
     * Initialize the class
     */
    public function __construct() {
        $this->tfa = new \RobThree\Auth\TwoFactorAuth(
            new \RobThree\Auth\Providers\Qr\QRServerProvider(),
            'NHR Secure'
        );

        if ( ! get_option( 'nhrrob_secure_enable_2fa', 0 ) ) {
            return;
        }

        // Add 2FA setup to user profile
        add_action( 'show_user_profile', [ $this, 'render_2fa_setup' ] );
        add_action( 'edit_user_profile', [ $this, 'render_2fa_setup' ] );
        add_action( 'personal_options_update', [ $this, 'save_2fa_setup' ] );
        add_action( 'edit_user_profile_update', [ $this, 'save_2fa_setup' ] );

        // Login verification
        add_filter( 'authenticate', [ $this, 'check_2fa_requirement' ], 50, 3 );
        add_action( 'login_init', [ $this, 'handle_login_actions' ] );
    }

    /**
     * Handle custom login actions
     */
    public function handle_login_actions() {
        $action = isset( $_REQUEST['action'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['action'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

        if ( 'nhrrob_secure_2fa' === $action ) {
            $this->render_2fa_form();
        }

        if ( 'nhrrob_secure_2fa_verify' === $action ) {
            $this->verify_2fa_code();
        }
    }

    /**
     * Render 2FA setup in user profile
     *
     * @param \WP_User $user
     */
    public function render_2fa_setup( $user ) {
        $secret = get_user_meta( $user->ID, 'nhrrob_secure_2fa_secret', true );
        $enabled = get_user_meta( $user->ID, 'nhrrob_secure_2fa_enabled', true );

        if ( ! $secret ) {
            $secret = $this->tfa->createSecret();
            update_user_meta( $user->ID, 'nhrrob_secure_2fa_secret', $secret );
        }

        // Generate QR Code URL
        $label = $user->user_email;
        $issuer = 'NHR Secure';
        $otpauth_url = sprintf( 'otpauth://totp/%s:%s?secret=%s&issuer=%s', urlencode( $issuer ), urlencode( $label ), $secret, urlencode( $issuer ) );
        $qrCodeUrl = sprintf( 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=%s', urlencode( $otpauth_url ) );

        $raw_codes = get_transient( 'nhrrob_2fa_raw_codes_' . $user->ID );
        $has_recovery_codes = (bool) get_user_meta( $user->ID, 'nhrrob_secure_2fa_recovery_codes', true );

        $this->render( 'profile-2fa', [
            'qrCodeUrl'          => $qrCodeUrl,
            'secret'             => $secret,
            'enabled'            => $enabled,
            'profile_url'        => admin_url( 'profile.php' ),
            'raw_recovery_codes' => $raw_codes,
            'has_recovery_codes' => $has_recovery_codes,
        ] );
    }

    /**
     * Save 2FA setup
     *
     * @param int $user_id
     */
    public function save_2fa_setup( $user_id ) {
        if ( ! current_user_can( 'edit_user', $user_id ) ) {
            return;
        }

        if ( ! isset( $_POST['nhr_2fa_profile_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['nhr_2fa_profile_nonce'] ) ), 'nhrrob_secure_save_2fa' ) ) {
            return;
        }

        $enabled = isset( $_POST['nhrrob_secure_2fa_enabled'] ) ? 1 : 0;
        $old_enabled = get_user_meta( $user_id, 'nhrrob_secure_2fa_enabled', true );

        update_user_meta( $user_id, 'nhrrob_secure_2fa_enabled', $enabled );

        // If 2FA was just enabled, or if regeneration is requested
        if ( ( $enabled && ! $old_enabled ) || isset( $_POST['nhrrob_secure_regenerate_recovery_codes'] ) ) {
            $this->generate_recovery_codes( $user_id );
        }
    }

    /**
     * Generate and save recovery codes
     * 
     * @param int $user_id
     * @return array The raw recovery codes
     */
    public function generate_recovery_codes( $user_id ) {
        $codes = [];
        $hashed_codes = [];

        for ( $i = 0; $i < 8; $i++ ) {
            $code = wp_generate_password( 10, false );
            $codes[] = $code;
            $hashed_codes[] = wp_hash_password( $code );
        }

        update_user_meta( $user_id, 'nhrrob_secure_2fa_recovery_codes', $hashed_codes );
        
        // Store raw codes in a transient for immediate display (valid for 30 seconds)
        set_transient( 'nhrrob_2fa_raw_codes_' . $user_id, $codes, 30 );

        return $codes;
    }

    /**
     * Check if user needs 2FA verification
     */
    public function check_2fa_requirement( $user, $username, $password ) {
        if ( is_wp_error( $user ) || ! $user instanceof \WP_User ) {
            return $user;
        }

        $enabled = get_user_meta( $user->ID, 'nhrrob_secure_2fa_enabled', true );
        if ( ! $enabled ) {
            return $user;
        }

        // Create a temporary token for the session
        $token = wp_generate_password( 32, false );
        set_transient( 'nhrrob_2fa_' . $token, $user->ID, 5 * MINUTE_IN_SECONDS );

        // Store the redirect URL if any
        $redirect_to = isset( $_REQUEST['redirect_to'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['redirect_to'] ) ) : admin_url(); // phpcs:ignore WordPress.Security.NonceVerification.Recommended

        // Redirect to 2FA verification page
        $login_url = wp_login_url();
        $verification_url = add_query_arg( [
            'action' => 'nhrrob_secure_2fa',
            'nhr_token' => $token,
            'redirect_to' => urlencode( $redirect_to ),
        ], $login_url );

        wp_safe_redirect( $verification_url );
        exit;
    }

    /**
     * Render the 2FA verification form
     */
    public function render_2fa_form() {
        $token = isset( $_GET['nhr_token'] ) ? sanitize_text_field( wp_unslash( $_GET['nhr_token'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $redirect_to = isset( $_GET['redirect_to'] ) ? sanitize_text_field( wp_unslash( $_GET['redirect_to'] ) ) : admin_url(); // phpcs:ignore WordPress.Security.NonceVerification.Recommended

        if ( ! get_transient( 'nhrrob_2fa_' . $token ) ) {
            wp_die( esc_html__( 'Invalid or expired 2FA token.', 'nhrrob-secure' ) );
        }
        
        $error = isset( $_GET['error'] ) ? sanitize_text_field( wp_unslash( $_GET['error'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        
        $this->render( 'login-2fa-form', [
            'token'       => $token,
            'redirect_to' => $redirect_to,
            'error'       => $error,
        ] );
    }

    /**
     * Verify the 2FA code
     */
    public function verify_2fa_code() {
        if ( ! isset( $_POST['nhr_2fa_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['nhr_2fa_nonce'] ) ), 'nhrrob_secure_2fa_verify' ) ) {
            wp_die( esc_html__( 'Nonce verification failed.', 'nhrrob-secure' ) );
        }

        $token = isset( $_POST['nhr_token'] ) ? sanitize_text_field( wp_unslash( $_POST['nhr_token'] ) ) : '';
        $code = isset( $_POST['nhr_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['nhr_2fa_code'] ) ) : '';
        $redirect_to = isset( $_POST['redirect_to'] ) ? sanitize_text_field( wp_unslash( $_POST['redirect_to'] ) ) : admin_url();

        $user_id = get_transient( 'nhrrob_2fa_' . $token );

        if ( ! $user_id ) {
            wp_die( esc_html__( 'Invalid or expired 2FA token.', 'nhrrob-secure' ) );
        }

        $user = get_userdata( $user_id );
        $secret = get_user_meta( $user_id, 'nhrrob_secure_2fa_secret', true );

        if ( $this->tfa->verifyCode( $secret, $code ) ) {
            // Success! Delete the transient and log the user in
            delete_transient( 'nhrrob_2fa_' . $token );
            wp_set_auth_cookie( $user_id, true );
            wp_safe_redirect( $redirect_to );
            exit;
        }

        // Check recovery codes
        $hashed_recovery_codes = get_user_meta( $user_id, 'nhrrob_secure_2fa_recovery_codes', true );
        if ( is_array( $hashed_recovery_codes ) ) {
            foreach ( $hashed_recovery_codes as $index => $hashed_code ) {
                if ( wp_check_password( $code, $hashed_code ) ) {
                    // Success with recovery code!
                    unset( $hashed_recovery_codes[ $index ] );
                    update_user_meta( $user_id, 'nhrrob_secure_2fa_recovery_codes', array_values( $hashed_recovery_codes ) );

                    delete_transient( 'nhrrob_2fa_' . $token );
                    wp_set_auth_cookie( $user_id, true );
                    wp_safe_redirect( $redirect_to );
                    exit;
                }
            }
        }

        // Fail!
        $verification_url = add_query_arg( [
                'action' => 'nhrrob_secure_2fa',
                'nhr_token' => $token,
                'redirect_to' => urlencode( $redirect_to ),
                'error' => 'invalid_code',
            ], wp_login_url() );
            wp_safe_redirect( $verification_url );
            exit;
    }
}
