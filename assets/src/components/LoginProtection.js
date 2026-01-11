import { Card, CardBody, ToggleControl, TextControl } from '@wordpress/components';
import { __ } from '@wordpress/i18n';

const LoginProtection = ({ settings, updateSetting }) => {
    return (
        <Card className="nhrrob-secure-card">
            <CardBody>
                <h2 className="nhrrob-secure-card-title">
                    {__('Login Protection', 'nhrrob-secure')}
                </h2>
                
                <ToggleControl
                    label={__('Enable Login Attempts Limit', 'nhrrob-secure')}
                    help={__('Limit failed login attempts to prevent brute force attacks', 'nhrrob-secure')}
                    checked={settings.nhrrob_secure_limit_login_attempts}
                    onChange={(value) => updateSetting('nhrrob_secure_limit_login_attempts', value)}
                />

                {settings.nhrrob_secure_limit_login_attempts && (
                    <TextControl
                        label={__('Maximum Login Attempts', 'nhrrob-secure')}
                        help={__('Number of failed attempts before blocking (default: 5)', 'nhrrob-secure')}
                        type="number"
                        value={settings.nhrrob_secure_login_attempts_limit}
                        onChange={(value) => updateSetting('nhrrob_secure_login_attempts_limit', parseInt(value) || 5)}
                        min="1"
                        max="20"
                    />
                )}

                <ToggleControl
                    label={__('Enable Proxy IP Detection', 'nhrrob-secure')}
                    help={__('Detect real IP behind proxies (Cloudflare, etc.)', 'nhrrob-secure')}
                    checked={settings.nhrrob_secure_enable_proxy_ip}
                    onChange={(value) => updateSetting('nhrrob_secure_enable_proxy_ip', value)}
                />
            </CardBody>
        </Card>
    );
};

export default LoginProtection;
