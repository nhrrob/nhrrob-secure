import { Card, CardBody, TextareaControl, SelectControl, Button, Notice } from '@wordpress/components';
import { __ } from '@wordpress/i18n';
import { useState } from '@wordpress/element';

const IPManager = ({ settings, updateSetting }) => {
    const countries = [
        { label: __('Select Countries to Block...', 'nhrrob-secure'), value: '' },
        { label: 'Afghanistan', value: 'AF' },
        { label: 'Albania', value: 'AL' },
        { label: 'Algeria', value: 'DZ' },
        { label: 'Argentina', value: 'AR' },
        { label: 'Australia', value: 'AU' },
        { label: 'Austria', value: 'AT' },
        { label: 'Bangladesh', value: 'BD' },
        { label: 'Belarus', value: 'BY' },
        { label: 'Belgium', value: 'BE' },
        { label: 'Brazil', value: 'BR' },
        { label: 'Bulgaria', value: 'BG' },
        { label: 'Canada', value: 'CA' },
        { label: 'Chile', value: 'CL' },
        { label: 'China', value: 'CN' },
        { label: 'Colombia', value: 'CO' },
        { label: 'Croatia', value: 'HR' },
        { label: 'Cuba', value: 'CU' },
        { label: 'Czech Republic', value: 'CZ' },
        { label: 'Denmark', value: 'DK' },
        { label: 'Egypt', value: 'EG' },
        { label: 'Estonia', value: 'EE' },
        { label: 'Ethiopia', value: 'ET' },
        { label: 'Finland', value: 'FI' },
        { label: 'France', value: 'FR' },
        { label: 'Germany', value: 'DE' },
        { label: 'Ghana', value: 'GH' },
        { label: 'Greece', value: 'GR' },
        { label: 'Hong Kong', value: 'HK' },
        { label: 'Hungary', value: 'HU' },
        { label: 'Iceland', value: 'IS' },
        { label: 'India', value: 'IN' },
        { label: 'Indonesia', value: 'ID' },
        { label: 'Iran', value: 'IR' },
        { label: 'Iraq', value: 'IQ' },
        { label: 'Ireland', value: 'IE' },
        { label: 'Israel', value: 'IL' },
        { label: 'Italy', value: 'IT' },
        { label: 'Japan', value: 'JP' },
        { label: 'Kazakhstan', value: 'KZ' },
        { label: 'Kenya', value: 'KE' },
        { label: 'Kuwait', value: 'KW' },
        { label: 'Latvia', value: 'LV' },
        { label: 'Lebanon', value: 'LB' },
        { label: 'Libya', value: 'LY' },
        { label: 'Lithuania', value: 'LT' },
        { label: 'Luxembourg', value: 'LU' },
        { label: 'Malaysia', value: 'MY' },
        { label: 'Mexico', value: 'MX' },
        { label: 'Morocco', value: 'MA' },
        { label: 'Myanmar', value: 'MM' },
        { label: 'Nepal', value: 'NP' },
        { label: 'Netherlands', value: 'NL' },
        { label: 'New Zealand', value: 'NZ' },
        { label: 'Nigeria', value: 'NG' },
        { label: 'North Korea', value: 'KP' },
        { label: 'Norway', value: 'NO' },
        { label: 'Pakistan', value: 'PK' },
        { label: 'Palestine', value: 'PS' },
        { label: 'Philippines', value: 'PH' },
        { label: 'Poland', value: 'PL' },
        { label: 'Portugal', value: 'PT' },
        { label: 'Qatar', value: 'QA' },
        { label: 'Romania', value: 'RO' },
        { label: 'Russia', value: 'RU' },
        { label: 'Saudi Arabia', value: 'SA' },
        { label: 'Serbia', value: 'RS' },
        { label: 'Singapore', value: 'SG' },
        { label: 'Slovakia', value: 'SK' },
        { label: 'Slovenia', value: 'SI' },
        { label: 'Somalia', value: 'SO' },
        { label: 'South Africa', value: 'ZA' },
        { label: 'South Korea', value: 'KR' },
        { label: 'Spain', value: 'ES' },
        { label: 'Sri Lanka', value: 'LK' },
        { label: 'Sudan', value: 'SD' },
        { label: 'Sweden', value: 'SE' },
        { label: 'Switzerland', value: 'CH' },
        { label: 'Syria', value: 'SY' },
        { label: 'Taiwan', value: 'TW' },
        { label: 'Thailand', value: 'TH' },
        { label: 'Turkey', value: 'TR' },
        { label: 'Ukraine', value: 'UA' },
        { label: 'United Arab Emirates', value: 'AE' },
        { label: 'United Kingdom', value: 'GB' },
        { label: 'United States', value: 'US' },
        { label: 'Venezuela', value: 'VE' },
        { label: 'Vietnam', value: 'VN' },
        { label: 'Yemen', value: 'YE' },
        { label: 'Zimbabwe', value: 'ZW' },
    ];

    const selectedCountries = settings.nhrrob_secure_blocked_countries || [];

    const toggleCountry = (countryCode) => {
        if (!countryCode) return;
        
        let newSelection;
        if (selectedCountries.includes(countryCode)) {
            newSelection = selectedCountries.filter(c => c !== countryCode);
        } else {
            newSelection = [...selectedCountries, countryCode];
        }
        updateSetting('nhrrob_secure_blocked_countries', newSelection);
    };

    return (
        <Card className="nhrrob-secure-card nhrrob-secure-ip-card">
            <CardBody>
                <h2 className="nhrrob-secure-card-title">{__('IP & Country Management', 'nhrrob-secure')}</h2>
                <p className="text-sm text-gray-500 dark:text-gray-400 mb-6">
                    {__('Control access to your site by whitelisting safe IPs or blocking malicious ones and entire countries.', 'nhrrob-secure')}
                </p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {/* Whitelist */}
                    <div className="nhrrob-secure-setting-group">
                        <label className="block text-sm font-semibold text-green-600 dark:text-green-400 mb-2">
                            {__('IP Whitelist (Safe)', 'nhrrob-secure')}
                        </label>
                        <TextareaControl
                            help={__('One IP or CIDR per line (e.g., 192.168.1.1 or 10.0.0.0/24). Whitelisted IPs bypass all security filters.', 'nhrrob-secure')}
                            value={settings.nhrrob_secure_ip_whitelist}
                            onChange={(value) => updateSetting('nhrrob_secure_ip_whitelist', value)}
                            rows={6}
                            placeholder="1.2.3.4"
                        />
                    </div>

                    {/* Blacklist */}
                    <div className="nhrrob-secure-setting-group">
                        <label className="block text-sm font-semibold text-red-600 dark:text-red-400 mb-2">
                            {__('IP Blacklist (Blocked)', 'nhrrob-secure')}
                        </label>
                        <TextareaControl
                            help={__('One IP or CIDR per line. Blacklisted IPs are blocked immediately from the entire site.', 'nhrrob-secure')}
                            value={settings.nhrrob_secure_ip_blacklist}
                            onChange={(value) => updateSetting('nhrrob_secure_ip_blacklist', value)}
                            rows={6}
                            placeholder="5.6.7.8"
                        />
                    </div>
                </div>

                <div className="mt-8 border-t border-gray-100 dark:border-gray-700">
                    <h3 className="text-sm font-semibold mb-4 text-gray-900 dark:text-gray-100">{__('Country Blocking', 'nhrrob-secure')}</h3>
                    <div className="flex flex-wrap gap-4 items-end">
                        <div className="flex-1 max-w-xs nhrrob-secure-country-select">
                            <SelectControl
                                label={__('Add Country to Block', 'nhrrob-secure')}
                                options={countries}
                                onChange={toggleCountry}
                                className="dark-mode-select"
                            />
                        </div>
                    </div>

                    {selectedCountries.length > 0 && (
                        <div className="mt-4 flex flex-wrap gap-2">
                            {selectedCountries.map(code => (
                                <div key={code} className="bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 px-3 py-1.5 rounded-full text-xs font-medium flex items-center gap-1 border border-red-200 dark:border-red-800/50">
                                    {countries.find(c => c.value === code)?.label || code}
                                    <button 
                                        onClick={() => toggleCountry(code)}
                                        className="focus:outline-none transition-colors text-sm leading-none -mr-0.5 bg-red-50 dark:bg-red-900/20 border-none cursor-pointer"
                                        title={__('Remove', 'nhrrob-secure')}
                                        aria-label={__('Remove', 'nhrrob-secure')}
                                    >
                                        ×
                                    </button>
                                </div>
                            ))}
                        </div>
                    )}

                    <p className="text-xs text-gray-400 dark:text-gray-500 mt-4 italic">
                        {__('Note: Country blocking uses a free GeoIP lookup service with caching for performance.', 'nhrrob-secure')}
                    </p>
                </div>

            </CardBody>
        </Card>
    );
};

export default IPManager;
