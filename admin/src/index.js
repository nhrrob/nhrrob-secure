/**
 * NHR Secure — admin app entry.
 *
 * React and every @wordpress/* package are provided by WordPress and stay out
 * of the bundle.
 */
import { createRoot, render } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';

import App from './app';
import * as ui from './components/ui';
import { useToast } from './components/ToastProvider';
import { useConfirm } from './components/ConfirmProvider';
import './style.scss';

/*
 * Public surface for add-ons. An add-on's bundle loads after this one and
 * before DOMContentLoaded, registers its screens with
 * addFilter( 'nhrrobSecure.screens', … ) and reuses these components.
 */
window.nhrrobSecure = {
	components: ui,
	useToast,
	useConfirm,
	registerIcons: ui.registerIcons,
};

const boot = window.nhrrobSecureApp || {};
if ( boot.nonce ) {
	apiFetch.use( apiFetch.createNonceMiddleware( boot.nonce ) );
}
if ( boot.restRoot ) {
	apiFetch.use( apiFetch.createRootURLMiddleware( boot.restRoot ) );
}

document.addEventListener( 'DOMContentLoaded', () => {
	const el = document.getElementById( 'nhrrob-secure-app' );
	if ( el ) {
		// createRoot() arrived in WordPress 6.2; render() covers 6.0 and 6.1.
		if ( createRoot ) {
			createRoot( el ).render( <App boot={ boot } /> );
		} else {
			render( <App boot={ boot } />, el );
		}
	}
} );
