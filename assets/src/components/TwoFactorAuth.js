import { Card, CardBody, ToggleControl } from '@wordpress/components';
import { __ } from '@wordpress/i18n';

const TwoFactorAuth = ({ settings, updateSetting }) => {
    return (
        <Card className="nhrrob-secure-card">
            <CardBody>
                <h2 className="nhrrob-secure-card-title">
                    {__('Two-Factor Authentication', 'nhrrob-secure')}
                </h2>
                
                <ToggleControl
                    label={__('Enable Global 2FA', 'nhrrob-secure')}
                    help={
                        <>
                            {__('Enables Google Authenticator support for all users. Users can set it up in their ', 'nhrrob-secure')}
                            <a href={nhrrobSecureSettings.profile_url} target="_blank" rel="noreferrer">
                                {__('profile page', 'nhrrob-secure')}
                            </a>.
                        </>
                    }
                    checked={settings.nhrrob_secure_enable_2fa}
                    onChange={(value) => updateSetting('nhrrob_secure_enable_2fa', value)}
                />
            </CardBody>
        </Card>
    );
};

export default TwoFactorAuth;
