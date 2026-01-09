import { Card, CardBody, ToggleControl, TextControl } from '@wordpress/components';
import { __ } from '@wordpress/i18n';

const CustomLoginPage = ({ settings, updateSetting }) => {
    return (
        <Card className="nhr-secure-card">
            <CardBody>
                <h2 className="nhr-secure-card-title">
                    {__('Custom Login Page', 'nhrrob-secure')}
                </h2>
                
                <ToggleControl
                    label={__('Enable Custom Login URL', 'nhrrob-secure')}
                    help={__('Hide wp-login.php and use a custom login URL', 'nhrrob-secure')}
                    checked={settings.nhrrob_secure_custom_login_page}
                    onChange={(value) => updateSetting('nhrrob_secure_custom_login_page', value)}
                />

                {settings.nhrrob_secure_custom_login_page && (
                    <TextControl
                        label={__('Custom Login URL', 'nhrrob-secure')}
                        help={__('Your login page will be accessible at this URL', 'nhrrob-secure')}
                        value={settings.nhrrob_secure_custom_login_url}
                        onChange={(value) => updateSetting('nhrrob_secure_custom_login_url', value)}
                        placeholder="/hidden-access-52w"
                    />
                )}

                {settings.nhrrob_secure_custom_login_page && (
                    <div className="nhr-secure-info">
                        <strong>{__('Your login URL:', 'nhrrob-secure')}</strong>
                        <code>{window.location.origin}{settings.nhrrob_secure_custom_login_url}</code>
                    </div>
                )}
            </CardBody>
        </Card>
    );
};

export default CustomLoginPage;
