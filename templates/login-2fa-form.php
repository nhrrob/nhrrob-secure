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

login_header( __( '2FA Verification', 'nhrrob-secure' ) );

if ( 'invalid_code' === $error ) {
    echo '<div id="login_error">' . __( 'Invalid authentication code. Please try again.', 'nhrrob-secure' ) . '</div>';
}
?>
<form name="nhrrob_2fa_form" id="nhrrob_2fa_form" action="<?php echo esc_url( wp_login_url() ); ?>" method="post">
    <p>
        <label for="nhr_2fa_code"><?php _e( 'Authentication Code', 'nhrrob-secure' ); ?><br />
        <input type="text" name="nhr_2fa_code" id="nhr_2fa_code" class="input" value="" size="20" autofocus /></label>
    </p>
    <input type="hidden" name="action" value="nhrrob_secure_2fa_verify" />
    <input type="hidden" name="nhr_token" value="<?php echo esc_attr( $token ); ?>" />
    <input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect_to ); ?>" />
    <p class="submit">
        <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'nhrrob-secure' ); ?>" />
    </p>
</form>
<p id="backtoblog"><a href="<?php echo esc_url( home_url( '/' ) ); ?>">&larr; <?php _e( 'Go to site', 'nhrrob-secure' ); ?></a></p>
<?php
login_footer();
exit;
