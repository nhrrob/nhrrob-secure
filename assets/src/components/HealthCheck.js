import { useState, useEffect } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import { Button, Spinner, Icon } from '@wordpress/components';
import apiFetch from '@wordpress/api-fetch';

const HealthCheck = ({ onApplyOneClick }) => {
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const [applying, setApplying] = useState(false);

    useEffect(() => {
        fetchStats();
    }, []);

    const fetchStats = async () => {
        try {
            const data = await apiFetch({ path: '/nhrrob-secure/v1/health-stats' });
            setStats(data);
            setLoading(false);
        } catch (error) {
            console.error('Failed to fetch health stats', error);
            setLoading(false);
        }
    };

    const handleOneClick = async () => {
        setApplying(true);
        try {
            const data = await apiFetch({
                path: '/nhrrob-secure/v1/one-click-secure',
                method: 'POST'
            });
            if (data.success) {
                setStats(data.stats);
                onApplyOneClick(data.settings);
            }
        } catch (error) {
            console.error('One-click secure failed', error);
        } finally {
            setApplying(false);
        }
    };

    if (loading) {
        return (
            <div className="nhrrob-secure-card p-6 flex items-center justify-center">
                <Spinner />
            </div>
        );
    }

    if (!stats) return null;

    const { score, total, checks, grade } = stats;
    const percentage = Math.round((score / total) * 100);

    const getScoreColor = (p) => {
        if (p >= 80) return 'text-green-500';
        if (p >= 60) return 'text-yellow-500';
        return 'text-red-500';
    };

    const getGradeColor = (g) => {
        if (g.startsWith('A')) return 'bg-green-100 text-green-700';
        if (g === 'B') return 'bg-yellow-100 text-yellow-700';
        return 'bg-red-100 text-red-700';
    };

    return (
        <div className="nhrrob-secure-card h-full flex flex-col">
            <div className="p-5 border-b border-gray-100 dark:border-gray-800 flex items-center justify-between">
                <div>
                    <h2 className="nhrrob-secure-card-title border-0 pb-0">
                        {__('Security Health Check', 'nhrrob-secure')}
                    </h2>
                    <p className="text-xs text-gray-500 mt-1">
                        {__('Overall protection status of your WordPress site', 'nhrrob-secure')}
                    </p>
                </div>
                <div className={`text-2xl font-bold px-3 py-1 rounded-lg ${getGradeColor(grade)}`}>
                    {grade}
                </div>
            </div>

            <div className="p-6 flex flex-col md:flex-row items-center gap-8">
                {/* Score Circle */}
                <div className="relative w-32 h-32 flex items-center justify-center">
                    <svg className="w-full h-full transform -rotate-90">
                        <circle
                            cx="64"
                            cy="64"
                            r="58"
                            stroke="currentColor"
                            strokeWidth="10"
                            fill="transparent"
                            className="text-gray-100 dark:text-gray-800"
                        />
                        <circle
                            cx="64"
                            cy="64"
                            r="58"
                            stroke="currentColor"
                            strokeWidth="10"
                            fill="transparent"
                            strokeDasharray={364}
                            strokeDashoffset={364 - (364 * percentage) / 100}
                            strokeLinecap="round"
                            className={`transition-all duration-1000 ease-out ${getScoreColor(percentage)}`}
                        />
                    </svg>
                    <div className="absolute flex flex-col items-center">
                        <span className="text-3xl font-bold">{percentage}%</span>
                        <span className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold">{__('Secure', 'nhrrob-secure')}</span>
                    </div>
                </div>

                <div className="flex-1 w-full">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-4">
                        {checks.map((check) => (
                            <div key={check.id} className="flex items-start gap-2 group">
                                <div className={`mt-0.5 rounded-full p-0.5 ${check.passed ? 'text-green-500' : 'text-red-400 opacity-60'}`}>
                                    <Icon icon={check.passed ? 'yes' : 'no-alt'} size={16} />
                                </div>
                                <div>
                                    <span className={`text-xs font-medium ${check.passed ? 'text-gray-700 dark:text-gray-300' : 'text-gray-400'}`}>
                                        {check.label}
                                    </span>
                                </div>
                            </div>
                        ))}
                    </div>

                    <Button
                        variant="secondary"
                        className="justify-center text-xs py-2 h-auto hover:bg-blue-600 hover:text-white transition-colors"
                        onClick={handleOneClick}
                        isBusy={applying}
                        disabled={applying}
                    >
                        {applying ? __('Applying...', 'nhrrob-secure') : __('One-Click Secure Recommendations', 'nhrrob-secure')}
                    </Button>
                </div>
            </div>
        </div>
    );
};

export default HealthCheck;
