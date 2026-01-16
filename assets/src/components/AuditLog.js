
import { Card, CardBody, Button, Spinner, SelectControl } from '@wordpress/components';
import { __ } from '@wordpress/i18n';
import { useState, useEffect } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';

const AuditLog = ({ settings, updateSetting }) => {
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [total, setTotal] = useState(0);
    const [page, setPage] = useState(1);
    const perPage = 20;

    useEffect(() => {
        fetchLogs();
    }, [page]);

    const fetchLogs = async () => {
        setLoading(true);
        try {
            const offset = (page - 1) * perPage;
            const data = await apiFetch({ path: `/nhrrob-secure/v1/logs?limit=${perPage}&offset=${offset}` });
            setLogs(data.items);
            setTotal(data.total);
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const totalPages = Math.ceil(total / perPage);

    return (
        <Card className="nhrrob-secure-card nhrrob-secure-audit-log-card">
            <CardBody>
                <div className="nhrrob-secure-card-header-flex">
                    <h2 className="nhrrob-secure-card-title">
                        {__('Activity Audit Log', 'nhrrob-secure')}
                    </h2>
                    <div className="nhrrob-secure-card-header-actions">
                        {settings && (
                            <SelectControl
                                className="nhrrob-secure-retention-select"
                                value={settings.nhrrob_secure_log_retention_days}
                                options={[
                                    { label: __('Keep logs: 7 days', 'nhrrob-secure'), value: 7 },
                                    { label: __('Keep logs: 30 days', 'nhrrob-secure'), value: 30 },
                                    { label: __('Keep logs: 90 days', 'nhrrob-secure'), value: 90 },
                                    { label: __('Keep logs: 1 year', 'nhrrob-secure'), value: 365 },
                                ]}
                                onChange={(value) => updateSetting('nhrrob_secure_log_retention_days', parseInt(value))}
                            />
                        )}
                        <Button
                            variant="secondary"
                            isSmall
                            onClick={fetchLogs}
                            disabled={loading}
                            className="nhrrob-secure-btn-outline"
                        >
                            {__('Refresh', 'nhrrob-secure')}
                        </Button>
                    </div>
                </div>

                {loading && <div className="nhrrob-secure-loading-overlay"><Spinner /></div>}

                <div className="nhrrob-secure-audit-table-wrapper">
                    <table className="nhrrob-secure-audit-table">
                        <thead>
                            <tr>
                                <th>{__('Date', 'nhrrob-secure')}</th>
                                <th>{__('User', 'nhrrob-secure')}</th>
                                <th>{__('Context', 'nhrrob-secure')}</th>
                                <th>{__('Action', 'nhrrob-secure')}</th>
                                <th>{__('Item', 'nhrrob-secure')}</th>
                                <th>{__('IP Address', 'nhrrob-secure')}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {logs.length > 0 ? (
                                logs.map((log) => (
                                    <tr key={log.id} className={`severity-${log.severity}`}>
                                        <td>{new Date(log.date).toLocaleString()}</td>
                                        <td>{log.user}</td>
                                        <td><span className="nhrrob-secure-badge">{log.context}</span></td>
                                        <td>{log.action}</td>
                                        <td>{log.label}</td>
                                        <td>{log.ip}</td>
                                    </tr>
                                ))
                            ) : (
                                <tr>
                                    <td colSpan="6" className="no-logs">
                                        {!loading && __('No activity logs found.', 'nhrrob-secure')}
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>

                {totalPages > 1 && (
                    <div className="nhrrob-secure-pagination">
                        <Button
                            isSmall
                            disabled={page === 1 || loading}
                            onClick={() => setPage(page - 1)}
                        >
                            &laquo; {__('Prev', 'nhrrob-secure')}
                        </Button>
                        <span className="nhrrob-secure-page-info">
                            {__('Page', 'nhrrob-secure')} {page} {__('of', 'nhrrob-secure')} {totalPages}
                        </span>
                        <Button
                            isSmall
                            disabled={page === totalPages || loading}
                            onClick={() => setPage(page + 1)}
                        >
                            {__('Next', 'nhrrob-secure')} &raquo;
                        </Button>
                    </div>
                )}
            </CardBody>
        </Card>
    );
};

export default AuditLog;
