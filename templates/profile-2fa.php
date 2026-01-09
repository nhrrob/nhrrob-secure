<?php
/**
 * 2FA Setup in User Profile
 * 
 * @var string $qrCodeUrl
 * @var string $secret
 * @var bool $enabled
 * @var string $profile_url
 */
if ( ! defined( 'ABSPATH' ) ) exit;
?>
<div class="nhr-secure-2fa-section">
    <h3><?php esc_html_e( 'Two-Factor Authentication (NHR Secure)', 'nhrrob-secure' ); ?></h3>
    
    <?php wp_nonce_field( 'nhrrob_secure_save_2fa', 'nhr_2fa_profile_nonce' ); ?>
    <table class="form-table">
        <tr>
            <th><label for="nhrrob_secure_2fa_enabled"><?php esc_html_e( 'Status', 'nhrrob-secure' ); ?></label></th>
            <td>
                <label>
                    <input type="checkbox" name="nhrrob_secure_2fa_enabled" id="nhrrob_secure_2fa_enabled" value="1" <?php checked( $enabled, 1 ); ?> />
                    <?php esc_html_e( 'Enable Two-Factor Authentication', 'nhrrob-secure' ); ?>
                </label>
            </td>
        </tr>
        
        <?php if ( ! $enabled ) : ?>
            <tr>
                <th><?php esc_html_e( 'Setup Instructions', 'nhrrob-secure' ); ?></th>
                <td>
                    <ol class="mt-0">
                        <li><?php esc_html_e( 'Install an authenticator app like Google Authenticator, Authy, or Microsoft Authenticator on your mobile device.', 'nhrrob-secure' ); ?></li>
                        <li><?php printf( 
                            /* translators: 1: profile page link */
                            esc_html__( 'Scan the QR code below or manually enter the secret key into the app from your %s.', 'nhrrob-secure' ), 
                            '<a href="' . esc_url( $profile_url ) . '">' . esc_html__( 'profile page', 'nhrrob-secure' ) . '</a>'
                        ); ?></li>
                        <li><?php esc_html_e( 'Once scanned, check the box above and click "Update Profile" to activate 2FA.', 'nhrrob-secure' ); ?></li>
                    </ol>
                    
                    <div class="nhr-secure-2fa-qr-code">
                        <img src="<?php echo esc_url( $qrCodeUrl ); ?>" alt="<?php esc_attr_e( '2FA QR Code', 'nhrrob-secure' ); ?>" />
                    </div>
                    
                    <p class="mt-4">
                        <strong><?php esc_html_e( 'Secret Key:', 'nhrrob-secure' ); ?></strong><br>
                        <code class="nhr-secure-2fa-secret"><?php echo esc_html( $secret ); ?></code>
                    </p>
                    
                    <p class="nhr-secure-2fa-warning">
                        <span class="dashicons dashicons-warning"></span>
                        <?php esc_html_e( 'Important: If you enable this, you will be required to provide a code every time you log in.', 'nhrrob-secure' ); ?>
                    </p>
                </td>
            </tr>
        <?php else : ?>
            <tr>
                <th><?php esc_html_e( 'Configuration', 'nhrrob-secure' ); ?></th>
                <td>
                    <p class="nhr-secure-2fa-success">
                        <span class="dashicons dashicons-yes-alt"></span>
                        <?php esc_html_e( 'Two-Factor Authentication is currently active on your account.', 'nhrrob-secure' ); ?>
                    </p>
                    <p class="description">
                        <?php esc_html_e( 'To disable or re-configure, uncheck the "Status" box above and update your profile.', 'nhrrob-secure' ); ?>
                    </p>
                </td>
            </tr>
        <?php endif; ?>
    </table>
</div>
