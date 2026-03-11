import { Card, CardBody, TextareaControl } from '@wordpress/components';
import { __ } from '@wordpress/i18n';
import Select from 'react-select';

const IPManager = ({ settings, updateSetting }) => {
    const countryOptions = [
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

    // Build react-select value array from stored country codes
    const selectedOptions = countryOptions.filter(opt => selectedCountries.includes(opt.value));

    const handleCountryChange = (chosen) => {
        const codes = chosen ? chosen.map(opt => opt.value) : [];
        updateSetting('nhrrob_secure_blocked_countries', codes);
    };

    // react-select custom styles that respect the plugin's dark mode CSS variables
    const selectStyles = {
        control: (base, state) => ({
            ...base,
            backgroundColor: 'var(--nhrrob-secure-card-bg)',
            borderColor: state.isFocused ? 'var(--nhrrob-secure-primary)' : 'var(--nhrrob-secure-border)',
            boxShadow: state.isFocused ? '0 0 0 1px var(--nhrrob-secure-primary)' : base.boxShadow,
            '&:hover': { borderColor: 'var(--nhrrob-secure-primary)' },
            minHeight: '38px',
        }),
        menu: (base) => ({
            ...base,
            backgroundColor: 'var(--nhrrob-secure-card-bg)',
            border: '1px solid var(--nhrrob-secure-border)',
            boxShadow: 'var(--nhrrob-secure-shadow)',
            zIndex: 9999,
        }),
        option: (base, state) => ({
            ...base,
            backgroundColor: state.isSelected
                ? 'var(--nhrrob-secure-primary)'
                : state.isFocused
                ? 'rgba(114, 174, 230, 0.15)'
                : 'transparent',
            color: state.isSelected ? '#fff' : 'var(--nhrrob-secure-text)',
            cursor: 'pointer',
        }),
        multiValue: (base) => ({
            ...base,
            backgroundColor: 'var(--nhrrob-secure-bg)',
            border: '1px solid var(--nhrrob-secure-border)',
            borderRadius: '4px',
        }),
        multiValueLabel: (base) => ({
            ...base,
            color: 'var(--nhrrob-secure-text)',
            fontWeight: '500',
            fontSize: '12px',
            paddingLeft: '8px',
        }),
        multiValueRemove: (base) => ({
            ...base,
            color: 'var(--nhrrob-secure-text-muted)',
            borderRadius: '0 4px 4px 0',
            '&:hover': { backgroundColor: 'var(--nhrrob-secure-border)', color: 'var(--nhrrob-secure-text)' },
        }),
        input: (base) => ({
            ...base,
            color: 'var(--nhrrob-secure-text)',
            minWidth: '120px',
        }),
        placeholder: (base) => ({
            ...base,
            color: 'var(--nhrrob-secure-text-muted)',
        }),
        singleValue: (base) => ({
            ...base,
            color: 'var(--nhrrob-secure-text)',
        }),
        indicatorSeparator: (base) => ({
            ...base,
            backgroundColor: 'var(--nhrrob-secure-border)',
        }),
        dropdownIndicator: (base) => ({
            ...base,
            color: 'var(--nhrrob-secure-text-muted)',
            '&:hover': { color: 'var(--nhrrob-secure-text)' },
        }),
        clearIndicator: (base) => ({
            ...base,
            color: 'var(--nhrrob-secure-text-muted)',
            '&:hover': { color: 'var(--nhrrob-secure-text)' },
        }),
        noOptionsMessage: (base) => ({
            ...base,
            color: 'var(--nhrrob-secure-text-muted)',
        }),
    };

    return (
        <Card className="nhrrob-secure-card nhrrob-secure-ip-card">
            <CardBody>
                <h2 className="nhrrob-secure-card-title">{__('IP & Country Management', 'nhrrob-secure')}</h2>
                <p className="text-sm nhrrob-text-muted mb-6">
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
                    <h3 className="text-sm font-semibold mb-2 nhrrob-text-primary">{__('Country Blocking', 'nhrrob-secure')}</h3>
                    <label className="block text-xs nhrrob-text-muted mb-2 uppercase tracking-wide font-medium">
                        {__('Select Countries to Block', 'nhrrob-secure')}
                    </label>
                    <Select
                        isMulti
                        options={countryOptions}
                        value={selectedOptions}
                        onChange={handleCountryChange}
                        placeholder={__('Search and select countries...', 'nhrrob-secure')}
                        classNamePrefix="nhrrob-country-select"
                        styles={selectStyles}
                        noOptionsMessage={() => __('No countries found', 'nhrrob-secure')}
                    />
                    <p className="text-xs nhrrob-text-muted mt-3 italic">
                        {__('Note: Country blocking uses a free GeoIP lookup service with caching for performance.', 'nhrrob-secure')}
                    </p>
                </div>

            </CardBody>
        </Card>
    );
};

export default IPManager;
