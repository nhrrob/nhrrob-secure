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
<div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ccd0d4;">
    <h3><?php esc_html_e( 'Two-Factor Authentication (NHR Secure)', 'nhrrob-secure' ); ?></h3>
    <p class="description" style="font-size: 14px; margin-bottom: 20px; max-width: 800px; display: none;">
        <?php esc_html_e( 'Two-factor authentication (2FA) strengthens your account security by requiring a second method of verification. Once enabled, you will need to provide a code from your mobile device every time you log in to your WordPress dashboard.', 'nhrrob-secure' ); ?>
    </p>
    
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
                    <ol style="margin-top: 0;">
                        <li><?php esc_html_e( 'Install an authenticator app like Google Authenticator, Authy, or Microsoft Authenticator on your mobile device.', 'nhrrob-secure' ); ?></li>
                        <li><?php printf( 
                            /* translators: 1: profile page link */
                            esc_html__( 'Scan the QR code below or manually enter the secret key into the app from your %s.', 'nhrrob-secure' ), 
                            '<a href="' . esc_url( $profile_url ) . '">' . esc_html__( 'profile page', 'nhrrob-secure' ) . '</a>'
                        ); ?></li>
                        <li><?php esc_html_e( 'Once scanned, check the box above and click "Update Profile" to activate 2FA.', 'nhrrob-secure' ); ?></li>
                    </ol>
                    
                    <div style="margin-top: 20px;">
                        <img src="<?php echo esc_url( $qrCodeUrl ); ?>" alt="<?php esc_attr_e( '2FA QR Code', 'nhrrob-secure' ); ?>" style="border: 1px solid #ccc; padding: 15px; background: #fff; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);" />
                    </div>
                    
                    <p style="margin-top: 15px;">
                        <strong><?php esc_html_e( 'Secret Key:', 'nhrrob-secure' ); ?></strong><br>
                        <code style="padding: 5px 10px; background: #f0f0f1; border: 1px solid #ccd0d4; border-radius: 3px; font-size: 14px; margin-top: 5px; display: inline-block; letter-spacing: 1px;"><?php echo esc_html( $secret ); ?></code>
                    </p>
                    
                    <p class="description" style="color: #d63638; font-weight: 500;">
                        <span class="dashicons dashicons-warning" style="font-size: 18px; width: 18px; height: 18px; vertical-align: middle;"></span>
                        <?php esc_html_e( 'Important: If you enable this, you will be required to provide a code every time you log in.', 'nhrrob-secure' ); ?>
                    </p>
                </td>
            </tr>
        <?php else : ?>
            <tr>
                <th><?php esc_html_e( 'Configuration', 'nhrrob-secure' ); ?></th>
                <td>
                    <p style="color: #00a32a; font-weight: 500;">
                        <span class="dashicons dashicons-yes-alt" style="font-size: 18px; width: 18px; height: 18px; vertical-align: middle;"></span>
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
