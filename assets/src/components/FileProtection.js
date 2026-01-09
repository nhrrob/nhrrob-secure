import { Card, CardBody, ToggleControl } from '@wordpress/components';
import { __ } from '@wordpress/i18n';

const FileProtection = ({ settings, updateSetting }) => {
    return (
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
    );
};

export default FileProtection;
