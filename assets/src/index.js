import { render, useState, useEffect } from '@wordpress/element';
import { 
    Button,
    Spinner,
    Notice
} from '@wordpress/components';
import { __ } from '@wordpress/i18n';
import apiFetch from '@wordpress/api-fetch';
import LoginProtection from './components/LoginProtection';
import CustomLoginPage from './components/CustomLoginPage';
import TwoFactorAuth from './components/TwoFactorAuth';
import FileProtection from './components/FileProtection';
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
                <LoginProtection settings={settings} updateSetting={updateSetting} />
                <CustomLoginPage settings={settings} updateSetting={updateSetting} />
                <TwoFactorAuth settings={settings} updateSetting={updateSetting} />
                <FileProtection settings={settings} updateSetting={updateSetting} />
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

