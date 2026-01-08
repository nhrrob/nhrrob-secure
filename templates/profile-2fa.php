<?php
/**
 * 2FA Setup in User Profile
 * 
 * @var string $qrCodeUrl
 * @var string $secret
 * @var bool $enabled
 */
if ( ! defined( 'ABSPATH' ) ) exit;
?>
<h3><?php esc_html_e( 'Two-Factor Authentication (NHR Secure)', 'nhrrob-secure' ); ?></h3>
<?php wp_nonce_field( 'nhrrob_secure_save_2fa', 'nhr_2fa_profile_nonce' ); ?>
<table class="form-table">
    <tr>
        <th><label for="nhrrob_secure_2fa_enabled"><?php esc_html_e( 'Enable 2FA', 'nhrrob-secure' ); ?></label></th>
        <td>
            <input type="checkbox" name="nhrrob_secure_2fa_enabled" id="nhrrob_secure_2fa_enabled" value="1" <?php checked( $enabled, 1 ); ?> />
            <span class="description"><?php esc_html_e( 'Enable Google Authenticator for this account.', 'nhrrob-secure' ); ?></span>
        </td>
    </tr>
    <?php if ( ! $enabled ) : ?>
        <tr>
            <th><?php esc_html_e( 'Scan QR Code', 'nhrrob-secure' ); ?></th>
            <td>
                <img src="<?php echo esc_url( $qrCodeUrl ); ?>" alt="<?php esc_attr_e( 'QR Code', 'nhrrob-secure' ); ?>" style="border: 1px solid #ccc; padding: 10px; background: #fff;" />
                <p class="description"><?php esc_html_e( 'Scan this QR code with your Google Authenticator app.', 'nhrrob-secure' ); ?></p>
                <p><code><?php echo esc_html( $secret ); ?></code></p>
            </td>
        </tr>
    <?php endif; ?>
</table>
