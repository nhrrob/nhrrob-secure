import { render, useState, useEffect } from '@wordpress/element';
import { 
    Card, 
    CardBody, 
    ToggleControl, 
    TextControl,
    Button,
    Spinner,
    Notice
} from '@wordpress/components';
import { __ } from '@wordpress/i18n';
import apiFetch from '@wordpress/api-fetch';
import './style.css';

const SettingsApp = () => {
    const [settings, setSettings] = useState(null);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [notice, setNotice] = useState(null);

    useEffect(() => {
        loadSettings();
    }, []);

    const loadSettings = async () => {
        try {
            const data = await apiFetch({ path: '/nhrrob-secure/v1/settings' });
            setSettings(data);
            setLoading(false);
        } catch (error) {
            setNotice({ type: 'error', message: __('Failed to load settings', 'nhrrob-secure') });
            setLoading(false);
        }
    };

    const handleSave = async () => {
        setSaving(true);
        setNotice(null);

        try {
            await apiFetch({
                path: '/nhrrob-secure/v1/settings',
                method: 'POST',
                data: settings,
            });
            setNotice({ type: 'success', message: __('Settings saved successfully!', 'nhrrob-secure') });
        } catch (error) {
            setNotice({ type: 'error', message: __('Failed to save settings', 'nhrrob-secure') });
        } finally {
            setSaving(false);
        }
    };

    const updateSetting = (key, value) => {
        setSettings({ ...settings, [key]: value });
    };

    if (loading) {
        return (
            <div className="nhr-secure-loading">
                <Spinner />
            </div>
        );
    }

    return (
        <div className="nhr-secure-settings">
            <div className="nhr-secure-header">
                <h1>{__('NHR Secure Settings', 'nhrrob-secure')}</h1>
                <p className="nhr-secure-subtitle">
                    {__('Configure security features for your WordPress site', 'nhrrob-secure')}
                </p>
            </div>

            {notice && (
                <Notice 
                    status={notice.type} 
                    isDismissible 
                    onRemove={() => setNotice(null)}
                >
                    {notice.message}
                </Notice>
            )}

            <div className="nhr-secure-cards">
                <Card className="nhr-secure-card">
                    <CardBody>
                        <h2 className="nhr-secure-card-title">
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

                <Card className="nhr-secure-card">
                    <CardBody>
                        <h2 className="nhr-secure-card-title">
                            {__('Two-Factor Authentication', 'nhrrob-secure')}
                        </h2>
                        
                        <ToggleControl
                            label={__('Enable Global 2FA', 'nhrrob-secure')}
                            help={__('Enables Google Authenticator support for all users. Users can set it up in their profile.', 'nhrrob-secure')}
                            checked={settings.nhrrob_secure_enable_2fa}
                            onChange={(value) => updateSetting('nhrrob_secure_enable_2fa', value)}
                        />
                    </CardBody>
                </Card>

                <Card className="nhr-secure-card">
                    <CardBody>
                        <h2 className="nhr-secure-card-title">
                            {__('File Protection', 'nhrrob-secure')}
                        </h2>
                        
                        <ToggleControl
                            label={__('Protect Debug Log', 'nhrrob-secure')}
                            help={__('Block direct access to wp-content/debug.log', 'nhrrob-secure')}
                            checked={settings.nhrrob_secure_protect_debug_log}
                            onChange={(value) => updateSetting('nhrrob_secure_protect_debug_log', value)}
                        />
                    </CardBody>
                </Card>
            </div>

            <div className="nhr-secure-actions">
                <Button 
                    variant="primary" 
                    onClick={handleSave}
                    isBusy={saving}
                    disabled={saving}
                >
                    {saving ? __('Saving...', 'nhrrob-secure') : __('Save Settings', 'nhrrob-secure')}
                </Button>
            </div>
        </div>
    );
};

// Render the app
const rootElement = document.getElementById('nhrrob-secure-settings-root');
if (rootElement) {
    render(<SettingsApp />, rootElement);
}
