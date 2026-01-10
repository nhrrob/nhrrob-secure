<?php
/**
 * 2FA Verification Form
 * 
 * @var string $token
 * @var string $redirect_to
 * @var string $error
 */
if ( ! defined( 'ABSPATH' ) ) exit;

// Load WordPress login styles if this is called outside login_header
if ( ! function_exists( 'login_header' ) ) {
    require_once ABSPATH . 'wp-includes/general-template.php';
}

global $errors;
if ( ! is_wp_error( $errors ) ) {
    $errors = new \WP_Error();
}

if ( 'invalid_code' === $error ) {
    $errors->add( 'invalid_code', esc_html__( 'Invalid authentication code. Please try again.', 'nhrrob-secure' ) );
}

login_header( esc_html__( '2FA Verification', 'nhrrob-secure' ), '', $errors );
?>
<form name="nhrrob_2fa_form" id="nhrrob_2fa_form" action="<?php echo esc_url( wp_login_url() ); ?>" method="post">
    <p>
        <label for="nhr_2fa_code"><?php esc_html_e( 'Authentication Code', 'nhrrob-secure' ); ?><br />
        <input type="text" name="nhr_2fa_code" id="nhr_2fa_code" class="input" value="" size="20" autofocus /></label>
    </p>
    <p class="description" style="margin-top: -10px; margin-bottom: 20px; font-size: 12px; color: #646970;">
        <?php esc_html_e( 'Enter the 6-digit code from your app or a 10-character recovery code.', 'nhrrob-secure' ); ?>
    </p>
    <input type="hidden" name="action" value="nhrrob_secure_2fa_verify" />
    <input type="hidden" name="nhr_token" value="<?php echo esc_attr( $token ); ?>" />
    <input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect_to ); ?>" />
    <?php wp_nonce_field( 'nhrrob_secure_2fa_verify', 'nhr_2fa_nonce' ); ?>
    <p class="submit">
        <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'nhrrob-secure' ); ?>" />
    </p>
</form>
<p id="backtoblog"><a href="<?php echo esc_url( home_url( '/' ) ); ?>">&larr; <?php esc_html_e( 'Go to site', 'nhrrob-secure' ); ?></a></p>
<?php
login_footer();
exit;
