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
<div class="nhrrob-secure-2fa-section">
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
                    <?php if ( isset( $type ) && 'email' === $type ) : ?>
                        <div class="nhrrob-secure-2fa-email-instructions">
                            <p><?php printf( wp_kses_post( __( 'Two-Factor Authentication is currently set to <strong>Email OTP</strong> mode.', 'nhrrob-secure' ) ) ); ?></p>
                            <p class="description"><?php 
                                /* translators: %s: User email address */
                                printf( wp_kses_post( __( 'You will receive a verification code at <strong>%s</strong> when you log in.', 'nhrrob-secure' ) ), esc_html( $user->user_email ?? 'your email address' ) ); 
                            ?></p>
                        </div>
                    <?php else : ?>
                        <ol class="mt-0 ml-5">
                            <li><?php esc_html_e( 'Install an authenticator app like Google Authenticator, Authy, or Microsoft Authenticator on your mobile device.', 'nhrrob-secure' ); ?></li>
                            <li><?php esc_html_e( 'Scan the QR code below or manually enter the secret key into the app.', 'nhrrob-secure' ); ?></li>
                            <li><?php esc_html_e( 'Once scanned, check the box above and click "Update Profile" to activate 2FA.', 'nhrrob-secure' ); ?></li>
                        </ol>
                        
                        <div class="nhrrob-secure-2fa-qr-code">
                            <img width="96" height="96" src="<?php echo esc_url( $qrCodeUrl ); ?>" alt="<?php esc_attr_e( '2FA QR Code', 'nhrrob-secure' ); ?>" />
                        </div>
                        
                        <p>
                            <strong><?php esc_html_e( 'Secret Key:', 'nhrrob-secure' ); ?></strong>
                            <code class="nhrrob-secure-2fa-secret"><?php echo esc_html( $secret ); ?></code>
                        </p>
                    <?php endif; ?>
                </td>
            </tr>
        <?php else : ?>
            <tr>
                <th><?php esc_html_e( 'Configuration', 'nhrrob-secure' ); ?></th>
                <td>
                    <p class="nhrrob-secure-2fa-success">
                        <span class="dashicons dashicons-yes-alt"></span>
                        <?php esc_html_e( 'Two-Factor Authentication is currently active on your account.', 'nhrrob-secure' ); ?>
                    </p>
                    
                    <div class="nhrrob-secure-recovery-codes-section">
                        <h4 class="mt-4 mb-2"><?php esc_html_e( 'Recovery Codes', 'nhrrob-secure' ); ?></h4>
                        <p class="description">
                            <?php esc_html_e( 'Recovery codes allow you to access your account if you lose your phone. Each code can be used only once.', 'nhrrob-secure' ); ?>
                        </p>
                        
                        <?php if ( ! empty( $raw_recovery_codes ) ) : ?>
                            <div class="nhrrob-secure-recovery-codes-display">
                                <div class="nhrrob-secure-recovery-codes-actions">
                                    <button type="button" class="nhrrob-secure-action-button" id="nhrrob-secure-copy-recovery-codes">
                                        <span class="dashicons dashicons-clipboard"></span>
                                        <span><?php esc_html_e( 'Copy', 'nhrrob-secure' ); ?></span>
                                    </button>
                                    <button type="button" class="nhrrob-secure-action-button" id="nhrrob-secure-download-recovery-codes">
                                        <span class="dashicons dashicons-download"></span>
                                        <span><?php esc_html_e( 'Download', 'nhrrob-secure' ); ?></span>
                                    </button>
                                </div>
                                
                                <p><strong><?php esc_html_e( 'Your New Recovery Codes:', 'nhrrob-secure' ); ?></strong></p>
                                <p class="nhrrob-secure-2fa-warning">
                                    <span class="dashicons dashicons-warning"></span>
                                    <?php esc_html_e( 'IMPORTANT: Copy these codes now. They will not be shown again!', 'nhrrob-secure' ); ?>
                                </p>
                                <ul class="nhrrob-secure-recovery-codes-list">
                                    <?php foreach ( $raw_recovery_codes as $nhrrob_secure_recovery_code ) : ?>
                                        <li class="nhrrob-secure-recovery-codes-item"><?php echo esc_html( $nhrrob_secure_recovery_code ); ?></li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        <?php endif; ?>

                        <p>
                            <label>
                                <input type="checkbox" name="nhrrob_secure_regenerate_recovery_codes" value="1" />
                                <?php esc_html_e( 'Regenerate Recovery Codes', 'nhrrob-secure' ); ?>
                            </label>
                        </p>
                    </div>
                </td>
            </tr>
        <?php endif; ?>
    </table>
</div>
