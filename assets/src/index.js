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
import VulnerabilityChecker from './components/VulnerabilityChecker';
import AuditLog from './components/AuditLog';
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

    const toggleDarkMode = async () => {
        const newValue = !settings.nhrrob_secure_dark_mode;
        updateSetting('nhrrob_secure_dark_mode', newValue);

        // Save immediately for better UX
        try {
            await apiFetch({
                path: '/nhrrob-secure/v1/settings',
                method: 'POST',
                data: { ...settings, nhrrob_secure_dark_mode: newValue },
            });
        } catch (error) {
            console.error('Failed to save dark mode preference', error);
        }
    };

    useEffect(() => {
        if (settings?.nhrrob_secure_dark_mode) {
            document.body.classList.add('nhrrob-secure-dark-mode-active');
        } else {
            document.body.classList.remove('nhrrob-secure-dark-mode-active');
        }
    }, [settings?.nhrrob_secure_dark_mode]);

    if (loading) {
        return (
            <div className="nhrrob-secure-loading">
                <Spinner />
            </div>
        );
    }

    return (
        <div className={`nhrrob-secure-settings ${settings.nhrrob_secure_dark_mode ? 'dark-mode' : ''}`}>
            <div className="nhrrob-secure-header">
                <div className="nhrrob-secure-header-main">
                    <h1>{__('NHR Secure Settings', 'nhrrob-secure')}</h1>
                    <Button
                        className="nhrrob-secure-dark-mode-toggle"
                        icon={settings.nhrrob_secure_dark_mode ?
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" width="20" height="20"><path d="M12 7c-2.76 0-5 2.24-5 5s2.24 5 5 5 5-2.24 5-5-2.24-5-5-5zM2 13h2c.55 0 1-.45 1-1s-.45-1-1-1H2c-.55 0-1 .45-1 1s.45 1 1 1zm18 0h2c.55 0 1-.45 1-1s-.45-1-1-1h-2c-.55 0-1 .45-1 1s.45 1 1 1zM11 2v2c0 .55.45 1 1 1s1-.45 1-1V2c0-.55-.45-1-1-1s-1 .45-1 1zm0 18v2c0 .55.45 1 1 1s1-.45 1-1v-2c0-.55-.45-1-1-1s-1 .45-1 1zM5.99 4.58a.996.996 0 00-1.41 0 .996.996 0 000 1.41l1.06 1.06c.39.39 1.03.39 1.41 0s.39-1.03 0-1.41L5.99 4.58zm12.37 12.37a.996.996 0 00-1.41 0 .996.996 0 000 1.41l1.06 1.06c.39.39 1.03.39 1.41 0s.39-1.03 0-1.41l-1.06-1.06zm1.06-10.96a.996.996 0 00-1.41-1.41l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06zM7.05 18.36a.996.996 0 00-1.41-1.41l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06z" /></svg> :
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" width="20" height="20"><path d="M12 3c-4.97 0-9 4.03-9 9s4.03 9 9 9 9-4.03 9-9c0-.46-.04-.92-.1-1.36-.98 1.37-2.58 2.26-4.4 2.26-2.98 0-5.4-2.42-5.4-5.4 0-1.81.89-3.42 2.26-4.4-.44-.06-.9-.1-1.36-.1z" /></svg>
                        }
                        onClick={toggleDarkMode}
                        label={__('Toggle Dark Mode', 'nhrrob-secure')}
                    />
                </div>
                <p className="nhrrob-secure-subtitle">
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

            <div className="nhrrob-secure-cards">
                <LoginProtection settings={settings} updateSetting={updateSetting} />
                <CustomLoginPage settings={settings} updateSetting={updateSetting} />
                <TwoFactorAuth settings={settings} updateSetting={updateSetting} />
                <FileProtection settings={settings} updateSetting={updateSetting} />
                <VulnerabilityChecker />
                <AuditLog settings={settings} updateSetting={updateSetting} />
            </div>

            <div className="nhrrob-secure-actions">
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

