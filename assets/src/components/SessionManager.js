import { Card, CardBody, Button, Spinner, Notice, TextControl } from '@wordpress/components';
import { __ } from '@wordpress/i18n';
import { useState, useEffect } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';

const SessionManager = ({ settings, updateSetting }) => {
    const [sessions, setSessions] = useState([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    useEffect(() => {
        fetchSessions();
    }, []);

    const fetchSessions = async () => {
        setLoading(true);
        setError(null);
        try {
            const data = await apiFetch({ path: '/nhrrob-secure/v1/sessions' });
            setSessions(data);
        } catch (err) {
            setError(err.message || __('Failed to load sessions.', 'nhrrob-secure'));
        } finally {
            setLoading(false);
        }
    };

    const destroySession = async (verifier) => {
        if (!confirm(__('Are you sure you want to log out this session?', 'nhrrob-secure'))) return;

        try {
            await apiFetch({
                path: '/nhrrob-secure/v1/sessions/destroy',
                method: 'POST',
                data: { verifier }
            });
            fetchSessions();
        } catch (err) {
            alert(err.message || __('Failed to destroy session.', 'nhrrob-secure'));
        }
    };

    const destroyOtherSessions = async () => {
        if (!confirm(__('Are you sure you want to log out all other devices?', 'nhrrob-secure'))) return;

        try {
            await apiFetch({
                path: '/nhrrob-secure/v1/sessions/destroy-others',
                method: 'POST'
            });
            fetchSessions();
            alert(__('All other sessions logged out.', 'nhrrob-secure'));
        } catch (err) {
            alert(err.message || __('Failed to destroy sessions.', 'nhrrob-secure'));
        }
    };

    return (
        <Card className="nhrrob-secure-card nhrrob-secure-sessions-card">
            <CardBody>
                <div className="nhrrob-secure-card-header-flex">
                    <h2 className="nhrrob-secure-card-title">{__('User Session Management', 'nhrrob-secure')}</h2>
                    <Button
                        variant="primary"
                        onClick={fetchSessions}
                        isBusy={loading}
                        disabled={loading}
                        icon="update"
                    >
                        {__('Refresh', 'nhrrob-secure')}
                    </Button>
                </div>

                <div className="nhrrob-secure-setting-group">
                    <TextControl
                        label={__('Idle Timeout (Minutes)', 'nhrrob-secure')}
                        help={__('Automatically log out inactive users after X minutes. Set to 0 to disable.', 'nhrrob-secure')}
                        type="number"
                        value={settings?.nhrrob_secure_idle_timeout || 0}
                        onChange={(value) => updateSetting('nhrrob_secure_idle_timeout', parseInt(value) || 0)}
                        min="0"
                    />
                </div>

                {error && (
                    <Notice status="error" isDismissible={false}>
                        {error}
                    </Notice>
                )}

                <div className="nhrrob-secure-sessions-list mt-4">
                    <h3 className="text-sm font-semibold mb-3">{__('Active Sessions', 'nhrrob-secure')}</h3>

                    {sessions.length === 0 && !loading ? (
                        <p>{__('No active sessions found.', 'nhrrob-secure')}</p>
                    ) : (
                        <div className="sessions-grid">
                            {sessions.map((session, index) => (
                                <div key={index} className={`session-item p-3 border rounded mb-2 ${session.is_current ? 'bg-blue-50 border-blue-200' : 'bg-gray-50 border-gray-200'}`}>
                                    <div className="flex justify-between items-start">
                                        <div className="session-info">
                                            <div className="font-medium text-gray-700">
                                                {session.ip}
                                                {session.is_current && <span className="ml-2 px-2 py-0.5 text-xs bg-blue-100 text-blue-800 rounded-full">{__('Current Session', 'nhrrob-secure')}</span>}
                                            </div>
                                            <div className="text-xs text-gray-500 mt-1">
                                                <div>{__('Login:', 'nhrrob-secure')} {new Date(session.login * 1000).toLocaleString()}</div>
                                                <div>{__('Expires:', 'nhrrob-secure')} {new Date(session.expiration * 1000).toLocaleString()}</div>
                                                <div className="mt-1 font-mono text-gray-400 truncate w-64" title={session.ua}>{session.ua}</div>
                                            </div>
                                        </div>

                                        {!session.is_current && (
                                            <Button
                                                variant="link"
                                                isDestructive
                                                onClick={() => destroySession(session.verifier)}
                                            >
                                                {__('Logout', 'nhrrob-secure')}
                                            </Button>
                                        )}
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                {sessions.length > 1 && (
                    <div className="mt-4 pt-3 border-t">
                        <Button
                            variant="secondary"
                            isDestructive
                            onClick={destroyOtherSessions}
                            className="w-full justify-center"
                        >
                            {__('Log Out All Other Devices', 'nhrrob-secure')}
                        </Button>
                    </div>
                )}

            </CardBody>
        </Card>
    );
};

export default SessionManager;
