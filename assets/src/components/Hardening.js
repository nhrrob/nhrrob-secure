import { Card, CardBody, ToggleControl, TextareaControl, Button, Spinner, Notice } from '@wordpress/components';
import { __ } from '@wordpress/i18n';

const Hardening = ({ settings, updateSetting }) => {
    return (
        <Card className="nhrrob-secure-card nhrrob-secure-hardening-card">
            <CardBody>
                <h2 className="nhrrob-secure-card-title">{__('Hardening & Firewall', 'nhrrob-secure')}</h2>

                <div className="nhrrob-secure-setting-group">
                    <h3 className="nhrrob-secure-setting-subtitle">{__('General Hardening', 'nhrrob-secure')}</h3>

                    <ToggleControl
                        label={__('Disable XML-RPC', 'nhrrob-secure')}
                        help={__('Prevents external systems (like mobile apps and Jetpack) from accessing your site via XML-RPC. Recommended if not used.', 'nhrrob-secure')}
                        checked={settings.nhrrob_secure_disable_xmlrpc}
                        onChange={(value) => updateSetting('nhrrob_secure_disable_xmlrpc', value)}
                    />

                    <ToggleControl
                        label={__('Disable File Editor', 'nhrrob-secure')}
                        help={__('Disables the built-in theme and plugin file editor to prevent code execution if an admin account is compromised.', 'nhrrob-secure')}
                        checked={settings.nhrrob_secure_disable_file_editor}
                        onChange={(value) => updateSetting('nhrrob_secure_disable_file_editor', value)}
                    />

                    <ToggleControl
                        label={__('Hide WP Version', 'nhrrob-secure')}
                        help={__('Removes WordPress version from page source and RSS feeds to make reconnaissance harder for attackers.', 'nhrrob-secure')}
                        checked={settings.nhrrob_secure_hide_wp_version}
                        onChange={(value) => updateSetting('nhrrob_secure_hide_wp_version', value)}
                    />

                    <ToggleControl
                        label={__('Disable REST API User Enumeration', 'nhrrob-secure')}
                        help={__('Blocks access to /wp-json/wp/v2/users to prevent attackers from listing your users.', 'nhrrob-secure')}
                        checked={settings.nhrrob_secure_disable_rest_users}
                        onChange={(value) => updateSetting('nhrrob_secure_disable_rest_users', value)}
                    />
                </div>

                <div className="nhrrob-secure-setting-group border-t border-gray-100 pt-4 mt-4">
                    <h3 className="nhrrob-secure-setting-subtitle">{__('Firewall Rules', 'nhrrob-secure')}</h3>

                    <ToggleControl
                        label={__('Advanced Firewall (IPS) Protection', 'nhrrob-secure')}
                        help={__('Proactively block common attacks like SQL Injection, XSS, and LFI by scanning request data.', 'nhrrob-secure')}
                        checked={settings?.nhrrob_secure_enable_advanced_firewall || false}
                        onChange={(value) => updateSetting('nhrrob_secure_enable_advanced_firewall', value)}
                    />

                    <TextareaControl
                        label={__('Block User Agents', 'nhrrob-secure')}
                        help={__('Enter one User-Agent per line to block. Case-insensitive partial match. Example: "HTTrack", "curl".', 'nhrrob-secure')}
                        value={settings.nhrrob_secure_firewall_blocked_uas}
                        onChange={(value) => updateSetting('nhrrob_secure_firewall_blocked_uas', value)}
                        rows={5}
                        placeholder="SemrushBot&#10;AhrefsBot&#10;MJ12bot"
                    />
                </div>

            </CardBody>
        </Card>
    );
};

export default Hardening;
