import { Card, CardBody, ToggleControl, CheckboxControl } from '@wordpress/components';
import { __ } from '@wordpress/i18n';

const TwoFactorAuth = ({ settings, updateSetting }) => {
    const enforcedRoles = settings.nhrrob_secure_2fa_enforced_roles || [];
    const availableRoles = settings.available_roles || [];

    const handleRoleToggle = (role, isChecked) => {
        const nextRoles = isChecked 
            ? [...enforcedRoles, role]
            : enforcedRoles.filter(r => r !== role);
        updateSetting('nhrrob_secure_2fa_enforced_roles', nextRoles);
    };

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

                {settings.nhrrob_secure_enable_2fa && (
                    <div className="nhrrob-secure-enforced-roles mt-4 pt-4 border-t border-gray-100">
                        <h3 className="text-sm font-semibold mb-3">
                            {__('Enforced 2FA by Role', 'nhrrob-secure')}
                        </h3>
                        <p className="text-xs text-gray-500 mb-4">
                            {__('Users with the selected roles will be forced to set up 2FA before they can access the admin dashboard.', 'nhrrob-secure')}
                        </p>
                        
                        <div className="grid grid-cols-2 gap-2">
                            {availableRoles.map((role) => (
                                <CheckboxControl
                                    key={role.value}
                                    label={role.label}
                                    checked={enforcedRoles.includes(role.value)}
                                    onChange={(checked) => handleRoleToggle(role.value, checked)}
                                />
                            ))}
                        </div>
                    </div>
                )}
            </CardBody>
        </Card>
    );
};

export default TwoFactorAuth;
