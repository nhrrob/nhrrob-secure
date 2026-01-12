import { useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import apiFetch from '@wordpress/api-fetch';
import { Button } from '@wordpress/components';

const FileScanner = () => {
    const [scanning, setScanning] = useState(false);
    const [results, setResults] = useState(null);
    const [error, setError] = useState(null);
    const [scanType, setScanType] = useState('core'); // core, malware

    const runScan = async () => {
        setScanning(true);
        setError(null);
        setResults(null);

        try {
            const path = scanType === 'core' ? '/nhrrob-secure/v1/scanner/core' : '/nhrrob-secure/v1/scanner/malware';
            const response = await apiFetch({ path: path, method: 'POST' });
            setResults(response);
        } catch (err) {
            setError(err.message || __('An error occurred during scan.', 'nhrrob-secure'));
        } finally {
            setScanning(false);
        }
    };

    const handleRepair = async (file) => {
        if (!confirm(__('Are you sure you want to repair this file? It will be overwritten with the original version.', 'nhrrob-secure'))) return;
        
        try {
            await apiFetch({
                path: '/nhrrob-secure/v1/scanner/repair',
                method: 'POST',
                data: { file }
            });
            alert(__('File repaired successfully.', 'nhrrob-secure'));
            // Refresh results
            runScan();
        } catch (err) {
            alert(err.message || __('Repair failed.', 'nhrrob-secure'));
        }
    };

    const handleDelete = async (file) => {
        if (!confirm(__('Are you sure you want to PERMANENTLY delete this file?', 'nhrrob-secure'))) return;

        try {
            await apiFetch({
                path: '/nhrrob-secure/v1/scanner/delete',
                method: 'POST',
                data: { file }
            });
            alert(__('File deleted successfully.', 'nhrrob-secure'));
            // Refresh results
            runScan();
        } catch (err) {
            alert(err.message || __('Delete failed.', 'nhrrob-secure'));
        }
    };

    return (
        <div className="nhrrob-secure-card nhrrob-secure-vulnerability-card padded-header">
             <div className="nhrrob-secure-card-header-flex">
                <div className="nhrrob-secure-header-content">
                    <h2 className="nhrrob-secure-card-title">{__('File Scanner', 'nhrrob-secure')}</h2>
                    <p className="nhrrob-secure-card-subtitle">{__('Scan your site for file modifications and potential malware.', 'nhrrob-secure')}</p>
                </div>
                <div className="nhrrob-scan-controls">
                    <div className="nhrrob-scan-type-toggle">
                        <button 
                            className={`nhrrob-scan-toggle-btn ${scanType === 'core' ? 'active' : ''}`}
                            onClick={() => setScanType('core')}
                            disabled={scanning}
                        >
                            {__('Core Integrity', 'nhrrob-secure')}
                        </button>
                        <button 
                            className={`nhrrob-scan-toggle-btn ${scanType === 'malware' ? 'active' : ''}`}
                            onClick={() => setScanType('malware')}
                            disabled={scanning}
                        >
                            {__('Malware Scan', 'nhrrob-secure')}
                        </button>
                    </div>
                     <Button 
                        variant="primary" 
                        onClick={() => runScan()} 
                        isBusy={scanning} 
                        disabled={scanning}
                        icon="update"
                        iconPosition="right"
                    >
                        {scanning ? __('Scanning...', 'nhrrob-secure') : __('Start Scan', 'nhrrob-secure')}
                    </Button>
                </div>
            </div>
            
            <div className="nhrrob-card-body">
                {error && <div className="notice notice-error inline-notice"><p>{error}</p></div>}
                
                {results && (
                     <div className="nhrrob-secure-vulnerability-list">
                        
                        {/* Status Message */}
                        {((scanType === 'core' && (results.modified?.length > 0 || results.missing?.length > 0)) ||
                          (scanType === 'malware' && results.suspicious?.length > 0)) && (
                             <div className="notice notice-warning inline-notice nhrrob-warning-notice">
                                <p>{__('Issues detected! Please review and update the items below.', 'nhrrob-secure')}</p>
                            </div>
                        )}

                        {scanType === 'core' && (
                            <>
                                {results.modified && results.modified.length > 0 && (
                                    <div className="nhrrob-result-group">
                                        <h3 className="nhrrob-result-group-title">{__('Modified Core Files', 'nhrrob-secure')}</h3>
                                        <div className="nhrrob-result-list">
                                            {results.modified.map((file, index) => (
                                                <div key={index} className="nhrrob-result-row">
                                                    <div className="nhrrob-file-info">
                                                        <strong>{file}</strong>
                                                    </div>
                                                    <Button variant="secondary" isSmall onClick={() => handleRepair(file)}>
                                                        {__('Repair', 'nhrrob-secure')}
                                                    </Button>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}
                                
                                {results.missing && results.missing.length > 0 && (
                                     <div className="nhrrob-result-group">
                                        <h3 className="nhrrob-result-group-title">{__('Missing Core Files', 'nhrrob-secure')}</h3>
                                        <div className="nhrrob-result-list">
                                            {results.missing.map((file, index) => (
                                                <div key={index} className="nhrrob-result-row">
                                                    <div className="nhrrob-file-info">
                                                        <strong>{file}</strong>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {(!results.modified?.length && !results.missing?.length) && (
                                    <div className="nhrrob-secure-status-success">
                                        <span className="dashicons dashicons-yes-alt"></span>
                                        {__('No modified core files found.', 'nhrrob-secure')}
                                    </div>
                                )}
                            </>
                        )}

                        {scanType === 'malware' && (
                             <>
                                {results.suspicious && results.suspicious.length > 0 ? (
                                    <div className="nhrrob-result-group">
                                        <h3 className="nhrrob-result-group-title">{__('Suspicious Files', 'nhrrob-secure')}</h3>
                                        <div className="nhrrob-result-list">
                                            {results.suspicious.map((item, index) => (
                                                 <div key={index} className="nhrrob-result-row">
                                                    <div className="nhrrob-file-info">
                                                        <strong>{item.file}</strong>
                                                        <span className="nhrrob-file-meta">{item.reason}</span>
                                                    </div>
                                                    <Button variant="link" isDestructive onClick={() => handleDelete(item.file)}>
                                                        {__('Delete', 'nhrrob-secure')}
                                                    </Button>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                ) : (
                                    <div className="nhrrob-secure-status-success">
                                        <span className="dashicons dashicons-yes-alt"></span>
                                        {__('No suspicious files found.', 'nhrrob-secure')}
                                    </div>
                                )}
                                <p className="description nhrrob-scan-count">
                                    <small>{__('Scanned files:', 'nhrrob-secure')} {results.scanned_count}</small>
                                </p>
                            </>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
};

export default FileScanner;
