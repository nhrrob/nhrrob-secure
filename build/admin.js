/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ "./assets/src/components/AuditLog.js"
/*!*******************************************!*\
  !*** ./assets/src/components/AuditLog.js ***!
  \*******************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(react__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _wordpress_components__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @wordpress/components */ "@wordpress/components");
/* harmony import */ var _wordpress_components__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var _wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @wordpress/i18n */ "@wordpress/i18n");
/* harmony import */ var _wordpress_i18n__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__);
/* harmony import */ var _wordpress_element__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @wordpress/element */ "@wordpress/element");
/* harmony import */ var _wordpress_element__WEBPACK_IMPORTED_MODULE_3___default = /*#__PURE__*/__webpack_require__.n(_wordpress_element__WEBPACK_IMPORTED_MODULE_3__);
/* harmony import */ var _wordpress_api_fetch__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! @wordpress/api-fetch */ "@wordpress/api-fetch");
/* harmony import */ var _wordpress_api_fetch__WEBPACK_IMPORTED_MODULE_4___default = /*#__PURE__*/__webpack_require__.n(_wordpress_api_fetch__WEBPACK_IMPORTED_MODULE_4__);





const AuditLog = ({
  settings,
  updateSetting
}) => {
  const [logs, setLogs] = (0,_wordpress_element__WEBPACK_IMPORTED_MODULE_3__.useState)([]);
  const [loading, setLoading] = (0,_wordpress_element__WEBPACK_IMPORTED_MODULE_3__.useState)(true);
  const [total, setTotal] = (0,_wordpress_element__WEBPACK_IMPORTED_MODULE_3__.useState)(0);
  const [page, setPage] = (0,_wordpress_element__WEBPACK_IMPORTED_MODULE_3__.useState)(1);
  const perPage = 20;
  (0,_wordpress_element__WEBPACK_IMPORTED_MODULE_3__.useEffect)(() => {
    fetchLogs();
  }, [page]);
  const fetchLogs = async () => {
    setLoading(true);
    try {
      const offset = (page - 1) * perPage;
      const data = await _wordpress_api_fetch__WEBPACK_IMPORTED_MODULE_4___default()({
        path: `/nhrrob-secure/v1/logs?limit=${perPage}&offset=${offset}`
      });
      setLogs(data.items);
      setTotal(data.total);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };
  const totalPages = Math.ceil(total / perPage);
  return (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.Card, {
    className: "nhrrob-secure-card nhrrob-secure-audit-log-card"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.CardBody, null, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("div", {
    className: "nhrrob-secure-card-header-flex"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("h2", {
    className: "nhrrob-secure-card-title"
  }, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Activity Audit Log', 'nhrrob-secure')), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("div", {
    className: "nhrrob-secure-card-header-actions"
  }, settings && (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.SelectControl, {
    className: "nhrrob-secure-retention-select",
    value: settings.nhrrob_secure_log_retention_days,
    options: [{
      label: (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Keep logs: 7 days', 'nhrrob-secure'),
      value: 7
    }, {
      label: (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Keep logs: 30 days', 'nhrrob-secure'),
      value: 30
    }, {
      label: (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Keep logs: 90 days', 'nhrrob-secure'),
      value: 90
    }, {
      label: (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Keep logs: 1 year', 'nhrrob-secure'),
      value: 365
    }],
    onChange: value => updateSetting('nhrrob_secure_log_retention_days', parseInt(value))
  }), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.Button, {
    variant: "secondary",
    isSmall: true,
    onClick: fetchLogs,
    disabled: loading,
    className: "nhrrob-secure-btn-outline"
  }, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Refresh', 'nhrrob-secure')))), loading && (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("div", {
    className: "nhrrob-secure-loading-overlay"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.Spinner, null)), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("div", {
    className: "nhrrob-secure-audit-table-wrapper"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("table", {
    className: "nhrrob-secure-audit-table"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("thead", null, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("tr", null, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("th", null, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Date', 'nhrrob-secure')), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("th", null, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('User', 'nhrrob-secure')), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("th", null, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Context', 'nhrrob-secure')), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("th", null, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Action', 'nhrrob-secure')), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("th", null, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Item', 'nhrrob-secure')), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("th", null, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('IP Address', 'nhrrob-secure')))), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("tbody", null, logs.length > 0 ? logs.map(log => (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("tr", {
    key: log.id,
    className: `severity-${log.severity}`
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("td", null, new Date(log.date).toLocaleString()), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("td", null, log.user), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("td", null, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("span", {
    className: "nhrrob-secure-badge"
  }, log.context)), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("td", null, log.action), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("td", null, log.label), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("td", null, log.ip))) : (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("tr", null, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("td", {
    colSpan: "6",
    className: "no-logs"
  }, !loading && (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('No activity logs found.', 'nhrrob-secure')))))), totalPages > 1 && (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("div", {
    className: "nhrrob-secure-pagination"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.Button, {
    isSmall: true,
    disabled: page === 1 || loading,
    onClick: () => setPage(page - 1)
  }, "\xAB ", (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Prev', 'nhrrob-secure')), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("span", {
    className: "nhrrob-secure-page-info"
  }, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Page', 'nhrrob-secure'), " ", page, " ", (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('of', 'nhrrob-secure'), " ", totalPages), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.Button, {
    isSmall: true,
    disabled: page === totalPages || loading,
    onClick: () => setPage(page + 1)
  }, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Next', 'nhrrob-secure'), " \xBB"))));
};
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (AuditLog);

/***/ },

/***/ "./assets/src/components/CustomLoginPage.js"
/*!**************************************************!*\
  !*** ./assets/src/components/CustomLoginPage.js ***!
  \**************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(react__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _wordpress_components__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @wordpress/components */ "@wordpress/components");
/* harmony import */ var _wordpress_components__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var _wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @wordpress/i18n */ "@wordpress/i18n");
/* harmony import */ var _wordpress_i18n__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__);



const CustomLoginPage = ({
  settings,
  updateSetting
}) => {
  return (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.Card, {
    className: "nhrrob-secure-card"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.CardBody, null, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("h2", {
    className: "nhrrob-secure-card-title"
  }, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Custom Login Page', 'nhrrob-secure')), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.ToggleControl, {
    label: (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Enable Custom Login URL', 'nhrrob-secure'),
    help: (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Hide wp-login.php and use a custom login URL', 'nhrrob-secure'),
    checked: settings.nhrrob_secure_custom_login_page,
    onChange: value => updateSetting('nhrrob_secure_custom_login_page', value)
  }), settings.nhrrob_secure_custom_login_page && (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.TextControl, {
    label: (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Custom Login URL', 'nhrrob-secure'),
    help: (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Your login page will be accessible at this URL', 'nhrrob-secure'),
    value: settings.nhrrob_secure_custom_login_url,
    onChange: value => updateSetting('nhrrob_secure_custom_login_url', value),
    placeholder: "/hidden-access-52w"
  }), settings.nhrrob_secure_custom_login_page && (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("div", {
    className: "nhrrob-secure-info"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("strong", null, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Your login URL:', 'nhrrob-secure')), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("code", null, window.location.origin, settings.nhrrob_secure_custom_login_url))));
};
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (CustomLoginPage);

/***/ },

/***/ "./assets/src/components/FileProtection.js"
/*!*************************************************!*\
  !*** ./assets/src/components/FileProtection.js ***!
  \*************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(react__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _wordpress_components__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @wordpress/components */ "@wordpress/components");
/* harmony import */ var _wordpress_components__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var _wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @wordpress/i18n */ "@wordpress/i18n");
/* harmony import */ var _wordpress_i18n__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__);



const FileProtection = ({
  settings,
  updateSetting
}) => {
  return (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.Card, {
    className: "nhrrob-secure-card"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.CardBody, null, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("h2", {
    className: "nhrrob-secure-card-title"
  }, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('File Protection', 'nhrrob-secure')), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.ToggleControl, {
    label: (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Protect Debug Log', 'nhrrob-secure'),
    help: (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Block direct access to wp-content/debug.log', 'nhrrob-secure'),
    checked: settings.nhrrob_secure_protect_debug_log,
    onChange: value => updateSetting('nhrrob_secure_protect_debug_log', value)
  })));
};
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (FileProtection);

/***/ },

/***/ "./assets/src/components/LoginProtection.js"
/*!**************************************************!*\
  !*** ./assets/src/components/LoginProtection.js ***!
  \**************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(react__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _wordpress_components__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @wordpress/components */ "@wordpress/components");
/* harmony import */ var _wordpress_components__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var _wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @wordpress/i18n */ "@wordpress/i18n");
/* harmony import */ var _wordpress_i18n__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__);



const LoginProtection = ({
  settings,
  updateSetting
}) => {
  return (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.Card, {
    className: "nhrrob-secure-card"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.CardBody, null, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("h2", {
    className: "nhrrob-secure-card-title"
  }, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Login Protection', 'nhrrob-secure')), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.ToggleControl, {
    label: (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Enable Login Attempts Limit', 'nhrrob-secure'),
    help: (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Limit failed login attempts to prevent brute force attacks', 'nhrrob-secure'),
    checked: settings.nhrrob_secure_limit_login_attempts,
    onChange: value => updateSetting('nhrrob_secure_limit_login_attempts', value)
  }), settings.nhrrob_secure_limit_login_attempts && (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.TextControl, {
    label: (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Maximum Login Attempts', 'nhrrob-secure'),
    help: (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Number of failed attempts before blocking (default: 5)', 'nhrrob-secure'),
    type: "number",
    value: settings.nhrrob_secure_login_attempts_limit,
    onChange: value => updateSetting('nhrrob_secure_login_attempts_limit', parseInt(value) || 5),
    min: "1",
    max: "20"
  }), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.ToggleControl, {
    label: (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Enable Proxy IP Detection', 'nhrrob-secure'),
    help: (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Detect real IP behind proxies (Cloudflare, etc.)', 'nhrrob-secure'),
    checked: settings.nhrrob_secure_enable_proxy_ip,
    onChange: value => updateSetting('nhrrob_secure_enable_proxy_ip', value)
  })));
};
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (LoginProtection);

/***/ },

/***/ "./assets/src/components/TwoFactorAuth.js"
/*!************************************************!*\
  !*** ./assets/src/components/TwoFactorAuth.js ***!
  \************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(react__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _wordpress_components__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @wordpress/components */ "@wordpress/components");
/* harmony import */ var _wordpress_components__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var _wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @wordpress/i18n */ "@wordpress/i18n");
/* harmony import */ var _wordpress_i18n__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__);



const TwoFactorAuth = ({
  settings,
  updateSetting
}) => {
  const enforcedRoles = settings.nhrrob_secure_2fa_enforced_roles || [];
  const availableRoles = settings.available_roles || [];
  const handleRoleToggle = (role, isChecked) => {
    const nextRoles = isChecked ? [...enforcedRoles, role] : enforcedRoles.filter(r => r !== role);
    updateSetting('nhrrob_secure_2fa_enforced_roles', nextRoles);
  };
  return (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.Card, {
    className: "nhrrob-secure-card"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.CardBody, null, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("h2", {
    className: "nhrrob-secure-card-title"
  }, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Two-Factor Authentication', 'nhrrob-secure')), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.ToggleControl, {
    label: (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Enable Global 2FA', 'nhrrob-secure'),
    help: (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(react__WEBPACK_IMPORTED_MODULE_0__.Fragment, null, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Enables Google Authenticator support for all users. Users can set it up in their ', 'nhrrob-secure'), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("a", {
      href: nhrrobSecureSettings.profile_url,
      target: "_blank",
      rel: "noreferrer"
    }, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('profile page', 'nhrrob-secure')), "."),
    checked: settings.nhrrob_secure_enable_2fa,
    onChange: value => updateSetting('nhrrob_secure_enable_2fa', value)
  }), settings.nhrrob_secure_enable_2fa && (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(react__WEBPACK_IMPORTED_MODULE_0__.Fragment, null, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("div", {
    className: "nhrrob-secure-2fa-method pt-4 border-t border-gray-100"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("h3", {
    className: "text-sm font-semibold mb-3"
  }, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('2FA Method', 'nhrrob-secure')), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.RadioControl, {
    selected: settings.nhrrob_secure_2fa_type || 'app',
    options: [{
      label: (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Authenticator App (Recommended)', 'nhrrob-secure'),
      value: 'app'
    }, {
      label: (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Email OTP', 'nhrrob-secure'),
      value: 'email'
    }],
    onChange: value => updateSetting('nhrrob_secure_2fa_type', value)
  })), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("div", {
    className: "nhrrob-secure-enforced-roles pt-4 border-t border-gray-100"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("h3", {
    className: "text-sm font-semibold mb-3"
  }, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Enforced 2FA by Role', 'nhrrob-secure')), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("p", {
    className: "text-xs text-gray-500 mb-4"
  }, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Users with the selected roles will be forced to set up 2FA before they can access the admin dashboard.', 'nhrrob-secure')), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("div", {
    className: "grid grid-cols-2 gap-2"
  }, availableRoles.map(role => (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.CheckboxControl, {
    key: role.value,
    label: role.label,
    checked: enforcedRoles.includes(role.value),
    onChange: checked => handleRoleToggle(role.value, checked)
  })))))));
};
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (TwoFactorAuth);

/***/ },

/***/ "./assets/src/components/VulnerabilityChecker.js"
/*!*******************************************************!*\
  !*** ./assets/src/components/VulnerabilityChecker.js ***!
  \*******************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(react__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _wordpress_components__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @wordpress/components */ "@wordpress/components");
/* harmony import */ var _wordpress_components__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var _wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @wordpress/i18n */ "@wordpress/i18n");
/* harmony import */ var _wordpress_i18n__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__);
/* harmony import */ var _wordpress_element__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @wordpress/element */ "@wordpress/element");
/* harmony import */ var _wordpress_element__WEBPACK_IMPORTED_MODULE_3___default = /*#__PURE__*/__webpack_require__.n(_wordpress_element__WEBPACK_IMPORTED_MODULE_3__);
/* harmony import */ var _wordpress_api_fetch__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! @wordpress/api-fetch */ "@wordpress/api-fetch");
/* harmony import */ var _wordpress_api_fetch__WEBPACK_IMPORTED_MODULE_4___default = /*#__PURE__*/__webpack_require__.n(_wordpress_api_fetch__WEBPACK_IMPORTED_MODULE_4__);





const VulnerabilityChecker = () => {
  const [results, setResults] = (0,_wordpress_element__WEBPACK_IMPORTED_MODULE_3__.useState)(null);
  const [loading, setLoading] = (0,_wordpress_element__WEBPACK_IMPORTED_MODULE_3__.useState)(true);
  const [scanning, setScanning] = (0,_wordpress_element__WEBPACK_IMPORTED_MODULE_3__.useState)(false);
  const [error, setError] = (0,_wordpress_element__WEBPACK_IMPORTED_MODULE_3__.useState)(null);
  (0,_wordpress_element__WEBPACK_IMPORTED_MODULE_3__.useEffect)(() => {
    fetchStatus();
  }, []);
  const fetchStatus = async () => {
    try {
      const data = await _wordpress_api_fetch__WEBPACK_IMPORTED_MODULE_4___default()({
        path: '/nhrrob-secure/v1/vulnerability/status'
      });
      setResults(data);
      setLoading(false);
    } catch (err) {
      setError((0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Failed to fetch vulnerability status', 'nhrrob-secure'));
      setLoading(false);
    }
  };
  const handleScan = async () => {
    setScanning(true);
    setError(null);
    try {
      const data = await _wordpress_api_fetch__WEBPACK_IMPORTED_MODULE_4___default()({
        path: '/nhrrob-secure/v1/vulnerability/scan',
        method: 'POST'
      });
      setResults(data);
    } catch (err) {
      setError((0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Failed to run vulnerability scan', 'nhrrob-secure'));
    } finally {
      setScanning(false);
    }
  };
  if (loading) {
    return (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.Card, {
      className: "nhrrob-secure-card"
    }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.CardBody, null, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.Spinner, null)));
  }
  const hasVulnerabilities = results && (results.core.length > 0 || results.plugins.length > 0 || results.themes.length > 0);
  const formatDate = timestamp => {
    if (!timestamp) return (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Never', 'nhrrob-secure');
    return new Date(timestamp * 1000).toLocaleString();
  };
  return (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.Card, {
    className: "nhrrob-secure-card nhrrob-secure-vulnerability-card"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.CardBody, null, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("div", {
    className: "nhrrob-secure-card-header-flex"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("h2", {
    className: "nhrrob-secure-card-title"
  }, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Vulnerability Checker', 'nhrrob-secure')), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.Button, {
    variant: "secondary",
    isSmall: true,
    onClick: handleScan,
    isBusy: scanning,
    disabled: scanning,
    className: "nhrrob-secure-btn-outline"
  }, scanning ? (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Scanning...', 'nhrrob-secure') : (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Scan Now', 'nhrrob-secure'))), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("p", {
    className: "nhrrob-secure-last-scan"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("strong", null, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Last Scan:', 'nhrrob-secure')), " ", formatDate(results.last_scan)), error && (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.Notice, {
    status: "error",
    isDismissible: false
  }, error), !hasVulnerabilities ? (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("div", {
    className: "nhrrob-secure-status-success"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("span", {
    className: "dashicons dashicons-yes-alt"
  }), (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('No vulnerabilities detected. Your site is secure.', 'nhrrob-secure')) : (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("div", {
    className: "nhrrob-secure-vulnerability-list"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_1__.Notice, {
    status: "warning",
    isDismissible: false
  }, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Vulnerabilities detected! Please review and update the items below.', 'nhrrob-secure')), results.core.length > 0 && (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("div", {
    className: "vulnerability-section"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("h3", null, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('WordPress Core', 'nhrrob-secure')), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("ul", null, results.core.map((v, i) => (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("li", {
    key: i
  }, v.name)))), results.plugins.length > 0 && (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("div", {
    className: "vulnerability-section"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("h3", null, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Plugins', 'nhrrob-secure')), results.plugins.map((plugin, i) => (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("div", {
    key: i,
    className: "vulnerability-item"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("strong", null, plugin.name, " (", plugin.version, ")"), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("ul", null, plugin.vulnerabilities.map((v, j) => (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("li", {
    key: j
  }, v.name)))))), results.themes.length > 0 && (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("div", {
    className: "vulnerability-section"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("h3", null, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_2__.__)('Themes', 'nhrrob-secure')), results.themes.map((theme, i) => (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("div", {
    key: i,
    className: "vulnerability-item"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("strong", null, theme.name, " (", theme.version, ")"), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("ul", null, theme.vulnerabilities.map((v, j) => (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("li", {
    key: j
  }, v.name)))))))));
};
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (VulnerabilityChecker);

/***/ },

/***/ "./assets/src/index.js"
/*!*****************************!*\
  !*** ./assets/src/index.js ***!
  \*****************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(react__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _wordpress_element__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @wordpress/element */ "@wordpress/element");
/* harmony import */ var _wordpress_element__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_wordpress_element__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var _wordpress_components__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @wordpress/components */ "@wordpress/components");
/* harmony import */ var _wordpress_components__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(_wordpress_components__WEBPACK_IMPORTED_MODULE_2__);
/* harmony import */ var _wordpress_i18n__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @wordpress/i18n */ "@wordpress/i18n");
/* harmony import */ var _wordpress_i18n__WEBPACK_IMPORTED_MODULE_3___default = /*#__PURE__*/__webpack_require__.n(_wordpress_i18n__WEBPACK_IMPORTED_MODULE_3__);
/* harmony import */ var _wordpress_api_fetch__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! @wordpress/api-fetch */ "@wordpress/api-fetch");
/* harmony import */ var _wordpress_api_fetch__WEBPACK_IMPORTED_MODULE_4___default = /*#__PURE__*/__webpack_require__.n(_wordpress_api_fetch__WEBPACK_IMPORTED_MODULE_4__);
/* harmony import */ var _components_LoginProtection__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./components/LoginProtection */ "./assets/src/components/LoginProtection.js");
/* harmony import */ var _components_CustomLoginPage__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./components/CustomLoginPage */ "./assets/src/components/CustomLoginPage.js");
/* harmony import */ var _components_TwoFactorAuth__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./components/TwoFactorAuth */ "./assets/src/components/TwoFactorAuth.js");
/* harmony import */ var _components_FileProtection__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ./components/FileProtection */ "./assets/src/components/FileProtection.js");
/* harmony import */ var _components_VulnerabilityChecker__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ./components/VulnerabilityChecker */ "./assets/src/components/VulnerabilityChecker.js");
/* harmony import */ var _components_AuditLog__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! ./components/AuditLog */ "./assets/src/components/AuditLog.js");
/* harmony import */ var _style_css__WEBPACK_IMPORTED_MODULE_11__ = __webpack_require__(/*! ./style.css */ "./assets/src/style.css");












const SettingsApp = () => {
  const [settings, setSettings] = (0,_wordpress_element__WEBPACK_IMPORTED_MODULE_1__.useState)(null);
  const [loading, setLoading] = (0,_wordpress_element__WEBPACK_IMPORTED_MODULE_1__.useState)(true);
  const [saving, setSaving] = (0,_wordpress_element__WEBPACK_IMPORTED_MODULE_1__.useState)(false);
  const [notice, setNotice] = (0,_wordpress_element__WEBPACK_IMPORTED_MODULE_1__.useState)(null);
  (0,_wordpress_element__WEBPACK_IMPORTED_MODULE_1__.useEffect)(() => {
    loadSettings();
  }, []);
  const loadSettings = async () => {
    try {
      const data = await _wordpress_api_fetch__WEBPACK_IMPORTED_MODULE_4___default()({
        path: '/nhrrob-secure/v1/settings'
      });
      setSettings(data);
      setLoading(false);
    } catch (error) {
      setNotice({
        type: 'error',
        message: (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_3__.__)('Failed to load settings', 'nhrrob-secure')
      });
      setLoading(false);
    }
  };
  const handleSave = async () => {
    setSaving(true);
    setNotice(null);
    try {
      await _wordpress_api_fetch__WEBPACK_IMPORTED_MODULE_4___default()({
        path: '/nhrrob-secure/v1/settings',
        method: 'POST',
        data: settings
      });
      setNotice({
        type: 'success',
        message: (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_3__.__)('Settings saved successfully!', 'nhrrob-secure')
      });
    } catch (error) {
      setNotice({
        type: 'error',
        message: (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_3__.__)('Failed to save settings', 'nhrrob-secure')
      });
    } finally {
      setSaving(false);
    }
  };
  const updateSetting = (key, value) => {
    setSettings({
      ...settings,
      [key]: value
    });
  };
  const toggleDarkMode = async () => {
    const newValue = !settings.nhrrob_secure_dark_mode;
    updateSetting('nhrrob_secure_dark_mode', newValue);

    // Save immediately for better UX
    try {
      await _wordpress_api_fetch__WEBPACK_IMPORTED_MODULE_4___default()({
        path: '/nhrrob-secure/v1/settings',
        method: 'POST',
        data: {
          ...settings,
          nhrrob_secure_dark_mode: newValue
        }
      });
    } catch (error) {
      console.error('Failed to save dark mode preference', error);
    }
  };
  (0,_wordpress_element__WEBPACK_IMPORTED_MODULE_1__.useEffect)(() => {
    if (settings?.nhrrob_secure_dark_mode) {
      document.body.classList.add('nhrrob-secure-dark-mode-active');
    } else {
      document.body.classList.remove('nhrrob-secure-dark-mode-active');
    }
  }, [settings?.nhrrob_secure_dark_mode]);
  if (loading) {
    return (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("div", {
      className: "nhrrob-secure-loading"
    }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_2__.Spinner, null));
  }
  return (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("div", {
    className: `nhrrob-secure-settings ${settings.nhrrob_secure_dark_mode ? 'dark-mode' : ''}`
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("div", {
    className: "nhrrob-secure-header"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("div", {
    className: "nhrrob-secure-header-main"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("h1", null, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_3__.__)('NHR Secure Settings', 'nhrrob-secure')), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_2__.Button, {
    className: "nhrrob-secure-dark-mode-toggle",
    icon: settings.nhrrob_secure_dark_mode ? (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("svg", {
      xmlns: "http://www.w3.org/2000/svg",
      viewBox: "0 0 24 24",
      fill: "currentColor",
      width: "20",
      height: "20"
    }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("path", {
      d: "M12 7c-2.76 0-5 2.24-5 5s2.24 5 5 5 5-2.24 5-5-2.24-5-5-5zM2 13h2c.55 0 1-.45 1-1s-.45-1-1-1H2c-.55 0-1 .45-1 1s.45 1 1 1zm18 0h2c.55 0 1-.45 1-1s-.45-1-1-1h-2c-.55 0-1 .45-1 1s.45 1 1 1zM11 2v2c0 .55.45 1 1 1s1-.45 1-1V2c0-.55-.45-1-1-1s-1 .45-1 1zm0 18v2c0 .55.45 1 1 1s1-.45 1-1v-2c0-.55-.45-1-1-1s-1 .45-1 1zM5.99 4.58a.996.996 0 00-1.41 0 .996.996 0 000 1.41l1.06 1.06c.39.39 1.03.39 1.41 0s.39-1.03 0-1.41L5.99 4.58zm12.37 12.37a.996.996 0 00-1.41 0 .996.996 0 000 1.41l1.06 1.06c.39.39 1.03.39 1.41 0s.39-1.03 0-1.41l-1.06-1.06zm1.06-10.96a.996.996 0 00-1.41-1.41l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06zM7.05 18.36a.996.996 0 00-1.41-1.41l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06z"
    })) : (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("svg", {
      xmlns: "http://www.w3.org/2000/svg",
      viewBox: "0 0 24 24",
      fill: "currentColor",
      width: "20",
      height: "20"
    }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("path", {
      d: "M12 3c-4.97 0-9 4.03-9 9s4.03 9 9 9 9-4.03 9-9c0-.46-.04-.92-.1-1.36-.98 1.37-2.58 2.26-4.4 2.26-2.98 0-5.4-2.42-5.4-5.4 0-1.81.89-3.42 2.26-4.4-.44-.06-.9-.1-1.36-.1z"
    })),
    onClick: toggleDarkMode,
    label: (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_3__.__)('Toggle Dark Mode', 'nhrrob-secure')
  })), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("p", {
    className: "nhrrob-secure-subtitle"
  }, (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_3__.__)('Configure security features for your WordPress site', 'nhrrob-secure'))), notice && (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_2__.Notice, {
    status: notice.type,
    isDismissible: true,
    onRemove: () => setNotice(null)
  }, notice.message), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("div", {
    className: "nhrrob-secure-cards"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_components_LoginProtection__WEBPACK_IMPORTED_MODULE_5__["default"], {
    settings: settings,
    updateSetting: updateSetting
  }), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_components_CustomLoginPage__WEBPACK_IMPORTED_MODULE_6__["default"], {
    settings: settings,
    updateSetting: updateSetting
  }), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_components_TwoFactorAuth__WEBPACK_IMPORTED_MODULE_7__["default"], {
    settings: settings,
    updateSetting: updateSetting
  }), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_components_FileProtection__WEBPACK_IMPORTED_MODULE_8__["default"], {
    settings: settings,
    updateSetting: updateSetting
  }), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_components_VulnerabilityChecker__WEBPACK_IMPORTED_MODULE_9__["default"], null), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_components_AuditLog__WEBPACK_IMPORTED_MODULE_10__["default"], {
    settings: settings,
    updateSetting: updateSetting
  })), (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)("div", {
    className: "nhrrob-secure-actions"
  }, (0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(_wordpress_components__WEBPACK_IMPORTED_MODULE_2__.Button, {
    variant: "primary",
    onClick: handleSave,
    isBusy: saving,
    disabled: saving
  }, saving ? (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_3__.__)('Saving...', 'nhrrob-secure') : (0,_wordpress_i18n__WEBPACK_IMPORTED_MODULE_3__.__)('Save Settings', 'nhrrob-secure'))));
};

// Render the app
const rootElement = document.getElementById('nhrrob-secure-settings-root');
if (rootElement) {
  (0,_wordpress_element__WEBPACK_IMPORTED_MODULE_1__.render)((0,react__WEBPACK_IMPORTED_MODULE_0__.createElement)(SettingsApp, null), rootElement);
}

/***/ },

/***/ "./assets/src/style.css"
/*!******************************!*\
  !*** ./assets/src/style.css ***!
  \******************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
// extracted by mini-css-extract-plugin


/***/ },

/***/ "@wordpress/api-fetch"
/*!**********************************!*\
  !*** external ["wp","apiFetch"] ***!
  \**********************************/
(module) {

module.exports = window["wp"]["apiFetch"];

/***/ },

/***/ "@wordpress/components"
/*!************************************!*\
  !*** external ["wp","components"] ***!
  \************************************/
(module) {

module.exports = window["wp"]["components"];

/***/ },

/***/ "@wordpress/element"
/*!*********************************!*\
  !*** external ["wp","element"] ***!
  \*********************************/
(module) {

module.exports = window["wp"]["element"];

/***/ },

/***/ "@wordpress/i18n"
/*!******************************!*\
  !*** external ["wp","i18n"] ***!
  \******************************/
(module) {

module.exports = window["wp"]["i18n"];

/***/ },

/***/ "react"
/*!************************!*\
  !*** external "React" ***!
  \************************/
(module) {

module.exports = window["React"];

/***/ }

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Check if module exists (development only)
/******/ 		if (__webpack_modules__[moduleId] === undefined) {
/******/ 			var e = new Error("Cannot find module '" + moduleId + "'");
/******/ 			e.code = 'MODULE_NOT_FOUND';
/******/ 			throw e;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId](module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = __webpack_modules__;
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/chunk loaded */
/******/ 	(() => {
/******/ 		var deferred = [];
/******/ 		__webpack_require__.O = (result, chunkIds, fn, priority) => {
/******/ 			if(chunkIds) {
/******/ 				priority = priority || 0;
/******/ 				for(var i = deferred.length; i > 0 && deferred[i - 1][2] > priority; i--) deferred[i] = deferred[i - 1];
/******/ 				deferred[i] = [chunkIds, fn, priority];
/******/ 				return;
/******/ 			}
/******/ 			var notFulfilled = Infinity;
/******/ 			for (var i = 0; i < deferred.length; i++) {
/******/ 				var [chunkIds, fn, priority] = deferred[i];
/******/ 				var fulfilled = true;
/******/ 				for (var j = 0; j < chunkIds.length; j++) {
/******/ 					if ((priority & 1 === 0 || notFulfilled >= priority) && Object.keys(__webpack_require__.O).every((key) => (__webpack_require__.O[key](chunkIds[j])))) {
/******/ 						chunkIds.splice(j--, 1);
/******/ 					} else {
/******/ 						fulfilled = false;
/******/ 						if(priority < notFulfilled) notFulfilled = priority;
/******/ 					}
/******/ 				}
/******/ 				if(fulfilled) {
/******/ 					deferred.splice(i--, 1)
/******/ 					var r = fn();
/******/ 					if (r !== undefined) result = r;
/******/ 				}
/******/ 			}
/******/ 			return result;
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/compat get default export */
/******/ 	(() => {
/******/ 		// getDefaultExport function for compatibility with non-harmony modules
/******/ 		__webpack_require__.n = (module) => {
/******/ 			var getter = module && module.__esModule ?
/******/ 				() => (module['default']) :
/******/ 				() => (module);
/******/ 			__webpack_require__.d(getter, { a: getter });
/******/ 			return getter;
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/define property getters */
/******/ 	(() => {
/******/ 		// define getter functions for harmony exports
/******/ 		__webpack_require__.d = (exports, definition) => {
/******/ 			for(var key in definition) {
/******/ 				if(__webpack_require__.o(definition, key) && !__webpack_require__.o(exports, key)) {
/******/ 					Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
/******/ 				}
/******/ 			}
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/hasOwnProperty shorthand */
/******/ 	(() => {
/******/ 		__webpack_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/make namespace object */
/******/ 	(() => {
/******/ 		// define __esModule on exports
/******/ 		__webpack_require__.r = (exports) => {
/******/ 			if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 				Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 			}
/******/ 			Object.defineProperty(exports, '__esModule', { value: true });
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/jsonp chunk loading */
/******/ 	(() => {
/******/ 		// no baseURI
/******/ 		
/******/ 		// object to store loaded and loading chunks
/******/ 		// undefined = chunk not loaded, null = chunk preloaded/prefetched
/******/ 		// [resolve, reject, Promise] = chunk loading, 0 = chunk loaded
/******/ 		var installedChunks = {
/******/ 			"admin": 0,
/******/ 			"./style-admin": 0
/******/ 		};
/******/ 		
/******/ 		// no chunk on demand loading
/******/ 		
/******/ 		// no prefetching
/******/ 		
/******/ 		// no preloaded
/******/ 		
/******/ 		// no HMR
/******/ 		
/******/ 		// no HMR manifest
/******/ 		
/******/ 		__webpack_require__.O.j = (chunkId) => (installedChunks[chunkId] === 0);
/******/ 		
/******/ 		// install a JSONP callback for chunk loading
/******/ 		var webpackJsonpCallback = (parentChunkLoadingFunction, data) => {
/******/ 			var [chunkIds, moreModules, runtime] = data;
/******/ 			// add "moreModules" to the modules object,
/******/ 			// then flag all "chunkIds" as loaded and fire callback
/******/ 			var moduleId, chunkId, i = 0;
/******/ 			if(chunkIds.some((id) => (installedChunks[id] !== 0))) {
/******/ 				for(moduleId in moreModules) {
/******/ 					if(__webpack_require__.o(moreModules, moduleId)) {
/******/ 						__webpack_require__.m[moduleId] = moreModules[moduleId];
/******/ 					}
/******/ 				}
/******/ 				if(runtime) var result = runtime(__webpack_require__);
/******/ 			}
/******/ 			if(parentChunkLoadingFunction) parentChunkLoadingFunction(data);
/******/ 			for(;i < chunkIds.length; i++) {
/******/ 				chunkId = chunkIds[i];
/******/ 				if(__webpack_require__.o(installedChunks, chunkId) && installedChunks[chunkId]) {
/******/ 					installedChunks[chunkId][0]();
/******/ 				}
/******/ 				installedChunks[chunkId] = 0;
/******/ 			}
/******/ 			return __webpack_require__.O(result);
/******/ 		}
/******/ 		
/******/ 		var chunkLoadingGlobal = globalThis["webpackChunknhrrob_secure"] = globalThis["webpackChunknhrrob_secure"] || [];
/******/ 		chunkLoadingGlobal.forEach(webpackJsonpCallback.bind(null, 0));
/******/ 		chunkLoadingGlobal.push = webpackJsonpCallback.bind(null, chunkLoadingGlobal.push.bind(chunkLoadingGlobal));
/******/ 	})();
/******/ 	
/************************************************************************/
/******/ 	
/******/ 	// startup
/******/ 	// Load entry module and return exports
/******/ 	// This entry module depends on other loaded chunks and execution need to be delayed
/******/ 	var __webpack_exports__ = __webpack_require__.O(undefined, ["./style-admin"], () => (__webpack_require__("./assets/src/index.js")))
/******/ 	__webpack_exports__ = __webpack_require__.O(__webpack_exports__);
/******/ 	
/******/ })()
;
//# sourceMappingURL=admin.js.map