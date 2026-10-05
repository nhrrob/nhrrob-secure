/**
 * Root component: app shell, section routing and the shared settings state.
 */
import { useState, useEffect, useMemo, useCallback } from '@wordpress/element';
import { applyFilters } from '@wordpress/hooks';
import { __ } from '@wordpress/i18n';

import api from './api';
import AppShell from './components/AppShell';
import { ConfirmProvider } from './components/ConfirmProvider';
import { ToastProvider, useToast } from './components/ToastProvider';
import { Loading, Note } from './components/ui';
import Dashboard from './screens/Dashboard';
import Login from './screens/Login';
import Users from './screens/Users';
import Firewall from './screens/Firewall';
import Hardening from './screens/Hardening';
import Scanner from './screens/Scanner';
import Activity from './screens/Activity';
import Settings from './screens/Settings';

const SCREENS = {
	dashboard: Dashboard,
	login: Login,
	users: Users,
	firewall: Firewall,
	hardening: Hardening,
	scanner: Scanner,
	activity: Activity,
	settings: Settings,
};

/**
 * Holds the settings (loaded once, updated by every save) and renders the
 * active screen. Lives inside the providers so it can raise toasts.
 *
 * @param {Object}   root0          Props.
 * @param {Object}   root0.boot     Boot data from PHP.
 * @param {string}   root0.active   Active section id.
 * @param {Function} root0.navigate Switch section.
 * @param {Object}   root0.screens  Map of section id to component.
 * @return {Object} Screen element.
 */
function Main( { boot, active, navigate, screens } ) {
	const toast = useToast();
	const [ data, setData ] = useState( null );
	const [ failed, setFailed ] = useState( '' );

	useEffect( () => {
		api( '/settings' )
			.then( setData )
			.catch( ( e ) => setFailed( e.message || String( e ) ) );
	}, [] );

	/**
	 * Save a partial settings change. Resolves with the new data, or with
	 * null after showing the server's explanation when it was refused.
	 */
	const save = useCallback(
		async ( patch, message ) => {
			try {
				const next = await api( '/settings', 'POST', patch );
				setData( next );
				toast( message || __( 'Saved', 'nhrrob-secure' ) );
				return next;
			} catch ( e ) {
				toast( e.message || String( e ), 'error' );
				return null;
			}
		},
		[ toast ]
	);

	if ( failed ) {
		return <Note tone="warn">{ failed }</Note>;
	}
	if ( ! data ) {
		return <Loading />;
	}

	const Screen = screens[ active ];
	if ( ! Screen ) {
		return null;
	}
	return (
		<>
			{ data.meta.safe_mode && (
				<Note tone="warn">
					{ __(
						'Safe mode is on. The moved login address, lockouts, the request filter, address and country rules and the two-factor step are paused until you turn it off (remove NHRROB_SECURE_SAFE_MODE from wp-config.php, or run "wp nhrrob-secure safe-mode off").',
						'nhrrob-secure'
					) }
				</Note>
			) }
			<Screen
				boot={ boot }
				settings={ data.settings }
				meta={ data.meta }
				save={ save }
				setData={ setData }
				navigate={ navigate }
			/>
		</>
	);
}

export default function App( { boot } ) {
	const modules = useMemo(
		() =>
			boot.modules && boot.modules.length
				? boot.modules
				: [
						{
							id: 'dashboard',
							label: __( 'Dashboard', 'nhrrob-secure' ),
						},
				  ],
		[ boot.modules ]
	);

	// Add-ons contribute screens for their own modules through this filter.
	const screens = useMemo(
		() => applyFilters( 'nhrrobSecure.screens', { ...SCREENS } ),
		[]
	);

	const fromHash = () => {
		const id = window.location.hash.replace( '#', '' ).split( '/' )[ 0 ];
		return modules.some( ( m ) => m.id === id ) ? id : modules[ 0 ].id;
	};
	const [ active, setActive ] = useState( fromHash );

	/**
	 * Switch section, optionally landing on one panel: Dashboard fixes pass an
	 * anchor so "Protect files" arrives at that panel, not the top of the screen.
	 */
	const navigate = useCallback( ( section, anchor ) => {
		setActive( section );
		try {
			window.history.replaceState( null, '', '#' + section );
		} catch ( e ) {
			/* history unavailable */
		}
		if ( ! anchor ) {
			window.scrollTo( 0, 0 );
			return;
		}
		// The target screen loads its data before the panel exists, so look for it for a moment.
		let tries = 0;
		const timer = setInterval( () => {
			const el = document.getElementById(
				'nhrrob-secure-panel-' + anchor
			);
			tries++;
			if ( el || tries > 30 ) {
				clearInterval( timer );
			}
			if ( el ) {
				window.scrollTo( {
					top: el.getBoundingClientRect().top + window.scrollY - 60,
					behavior: 'smooth',
				} );
				el.classList.add( 'is-focused' );
				setTimeout( () => el.classList.remove( 'is-focused' ), 1600 );
			}
		}, 100 );
	}, [] );

	return (
		<AppShell
			modules={ modules }
			active={ active }
			onNavigate={ navigate }
			title={ boot.pluginName || __( 'Secure', 'nhrrob-secure' ) }
		>
			{ /* Inside AppShell so dialogs and toasts sit within the element that defines the design tokens. */ }
			<ConfirmProvider>
				<ToastProvider>
					<Main
						boot={ boot }
						active={ active }
						navigate={ navigate }
						screens={ screens }
					/>
				</ToastProvider>
			</ConfirmProvider>
		</AppShell>
	);
}
