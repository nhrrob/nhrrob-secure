/**
 * NHR Secure — two-factor setup on the user's own profile.
 *
 * The QR code is drawn here in the browser; the secret is never sent to an
 * outside service.
 */
import { createRoot, useState, useEffect, useRef } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';
import { __, _n, sprintf } from '@wordpress/i18n';
import { generate } from 'lean-qr';

import './profile.scss';

const boot = window.nhrrobSecureProfile || {};
if ( boot.nonce ) {
	apiFetch.use( apiFetch.createNonceMiddleware( boot.nonce ) );
}
if ( boot.restRoot ) {
	apiFetch.use( apiFetch.createRootURLMiddleware( boot.restRoot ) );
}

const api = ( path, data ) =>
	apiFetch( {
		path: 'nhrrob-secure/v1/2fa' + path,
		method: data ? 'POST' : 'GET',
		data,
	} );

function Qr( { text } ) {
	const canvas = useRef( null );
	useEffect( () => {
		if ( canvas.current ) {
			generate( text ).toCanvas( canvas.current );
		}
	}, [ text ] );
	return (
		<canvas
			ref={ canvas }
			className="nhrrob-secure-profile__qr"
			role="img"
			aria-label={ __(
				'QR code for your authenticator app',
				'nhrrob-secure'
			) }
		/>
	);
}

/**
 * Text input that runs an action on Enter instead of submitting the profile form around it.
 *
 * @param {Object}   root0         Props.
 * @param {Function} root0.onEnter Called when Enter is pressed.
 * @return {Object} Input element.
 */
function Input( { onEnter, ...props } ) {
	return (
		<input
			className="regular-text"
			onKeyDown={ ( e ) => {
				if ( e.key === 'Enter' ) {
					e.preventDefault();
					onEnter();
				}
			} }
			{ ...props }
		/>
	);
}

function App() {
	const [ status, setStatus ] = useState( null );
	const [ setup, setSetup ] = useState( null );
	const [ code, setCode ] = useState( '' );
	const [ password, setPassword ] = useState( '' );
	const [ ask, setAsk ] = useState( '' ); // 'disable' | 'recovery'
	const [ codes, setCodes ] = useState( null );
	const [ error, setError ] = useState( '' );
	const [ busy, setBusy ] = useState( false );

	useEffect( () => {
		api( '' )
			.then( setStatus )
			.catch( ( e ) => setError( e.message ) );
	}, [] );

	const call = async ( path, data ) => {
		setBusy( true );
		setError( '' );
		try {
			const res = await api( path, data );
			setBusy( false );
			return res;
		} catch ( e ) {
			setError( e.message || String( e ) );
			setBusy( false );
			return null;
		}
	};

	const begin = async ( method ) => {
		const res = await call( '/begin', { method } );
		if ( res ) {
			setCode( '' );
			setSetup( res );
		}
	};

	const b64 = {
		dec: ( s ) =>
			Uint8Array.from(
				window.atob( s.replace( /-/g, '+' ).replace( /_/g, '/' ) ),
				( c ) => c.charCodeAt( 0 )
			),
		enc: ( buffer ) =>
			window
				.btoa( String.fromCharCode( ...new Uint8Array( buffer ) ) )
				.replace( /\+/g, '-' )
				.replace( /\//g, '_' )
				.replace( /=+$/, '' ),
	};

	const passkey = async () => {
		const res = await call( '/begin', { method: 'passkey' } );
		if ( ! res ) {
			return;
		}
		const o = res.options;
		try {
			const created = await window.navigator.credentials.create( {
				publicKey: {
					...o,
					challenge: b64.dec( o.challenge ),
					user: { ...o.user, id: b64.dec( o.user.id ) },
					excludeCredentials: o.excludeCredentials.map( ( c ) => ( {
						...c,
						id: b64.dec( c.id ),
					} ) ),
				},
			} );
			const done = await call( '/passkey', {
				client: b64.enc( created.response.clientDataJSON ),
				attestation: b64.enc( created.response.attestationObject ),
				label: window.navigator.platform || '',
			} );
			if ( done ) {
				setCodes( done.recovery_codes );
				setStatus( done );
			}
		} catch ( e ) {
			setError(
				__(
					'The passkey was not created. Your browser or device may not support passkeys, or the request was cancelled.',
					'nhrrob-secure'
				)
			);
		}
	};

	const confirm = async () => {
		const res = await call( '/confirm', { code } );
		if ( res ) {
			setSetup( null );
			setCodes( res.recovery_codes );
			setStatus( res );
		}
	};

	const withPassword = async () => {
		const res = await call( '/' + ask, { password } );
		if ( res ) {
			setPassword( '' );
			setAsk( '' );
			setStatus( res );
			if ( res.recovery_codes ) {
				setCodes( res.recovery_codes );
			}
		}
	};

	if ( ! status ) {
		return <p>{ error || __( 'Loading…', 'nhrrob-secure' ) }</p>;
	}

	const notice = error && (
		<div className="notice notice-error inline">
			<p>{ error }</p>
		</div>
	);

	if ( codes ) {
		return (
			<div>
				<div className="notice notice-success inline">
					<p>
						<strong>
							{ __(
								'Save these recovery codes.',
								'nhrrob-secure'
							) }
						</strong>{ ' ' }
						{ __(
							'Each one signs you in once if you lose your phone or cannot get the email. They are shown only now.',
							'nhrrob-secure'
						) }
					</p>
				</div>
				<pre className="nhrrob-secure-profile__codes">
					{ codes.join( '\n' ) }
				</pre>
				<button
					type="button"
					className="button"
					onClick={ () => {
						window.navigator.clipboard
							.writeText( codes.join( '\n' ) )
							.catch( () => {} );
					} }
				>
					{ __( 'Copy', 'nhrrob-secure' ) }
				</button>{ ' ' }
				<button
					type="button"
					className="button button-primary"
					onClick={ () => setCodes( null ) }
				>
					{ __( 'I have saved them', 'nhrrob-secure' ) }
				</button>
			</div>
		);
	}

	if ( setup ) {
		return (
			<div>
				{ notice }
				{ setup.method === 'app' ? (
					<>
						<p>
							{ __(
								'1. Scan this code with your authenticator app (Google Authenticator, Authy, 1Password and others), or type the key in by hand.',
								'nhrrob-secure'
							) }
						</p>
						<Qr text={ setup.uri } />
						<p>
							<code className="nhrrob-secure-profile__secret">
								{ setup.secret
									.replace( /(.{4})/g, '$1 ' )
									.trim() }
							</code>
						</p>
						<p>
							{ __(
								'2. Enter the 6-digit code the app shows.',
								'nhrrob-secure'
							) }
						</p>
					</>
				) : (
					<p>
						{ sprintf(
							/* translators: %s: email address. */
							__(
								'We sent a 6-digit code to %s. Enter it below.',
								'nhrrob-secure'
							),
							status.email
						) }
					</p>
				) }
				<p>
					<Input
						type="text"
						inputMode="numeric"
						autoComplete="one-time-code"
						aria-label={ __( 'Code', 'nhrrob-secure' ) }
						value={ code }
						onChange={ ( e ) => setCode( e.target.value ) }
						onEnter={ confirm }
					/>
				</p>
				<button
					type="button"
					className="button button-primary"
					disabled={ busy || ! code }
					onClick={ confirm }
				>
					{ __( 'Verify and switch on', 'nhrrob-secure' ) }
				</button>{ ' ' }
				<button
					type="button"
					className="button"
					onClick={ () => setSetup( null ) }
				>
					{ __( 'Cancel', 'nhrrob-secure' ) }
				</button>
			</div>
		);
	}

	if ( ask ) {
		return (
			<div>
				{ notice }
				<p>
					{ ask === 'disable'
						? __(
								'Enter your account password to switch two-factor off.',
								'nhrrob-secure'
						  )
						: __(
								'Enter your account password to replace your recovery codes. The old ones stop working.',
								'nhrrob-secure'
						  ) }
				</p>
				<p>
					<Input
						type="password"
						autoComplete="current-password"
						aria-label={ __( 'Account password', 'nhrrob-secure' ) }
						value={ password }
						onChange={ ( e ) => setPassword( e.target.value ) }
						onEnter={ withPassword }
					/>
				</p>
				<button
					type="button"
					className="button button-primary"
					disabled={ busy || ! password }
					onClick={ withPassword }
				>
					{ __( 'Continue', 'nhrrob-secure' ) }
				</button>{ ' ' }
				<button
					type="button"
					className="button"
					onClick={ () => {
						setAsk( '' );
						setError( '' );
					} }
				>
					{ __( 'Cancel', 'nhrrob-secure' ) }
				</button>
			</div>
		);
	}

	if ( status.enabled ) {
		return (
			<div>
				{ notice }
				<p>
					<span className="nhrrob-secure-profile__on">
						{ __( 'On', 'nhrrob-secure' ) }
					</span>{ ' ' }
					{ status.method === 'passkey' &&
						__(
							'You sign in with your password and your passkey.',
							'nhrrob-secure'
						) }
					{ status.method === 'app' &&
						__(
							'You sign in with your password and a code from your authenticator app.',
							'nhrrob-secure'
						) }
					{ status.method === 'email' &&
						sprintf(
							/* translators: %s: email address. */
							__(
								'You sign in with your password and a code emailed to %s.',
								'nhrrob-secure'
							),
							status.email
						) }{ ' ' }
					{ sprintf(
						/* translators: %d: number of recovery codes. */
						_n(
							'%d recovery code left.',
							'%d recovery codes left.',
							status.recovery,
							'nhrrob-secure'
						),
						status.recovery
					) }
				</p>
				{ status.trusted > 0 && (
					<p>
						{ sprintf(
							/* translators: %d: number of browsers. */
							_n(
								'%d browser skips the code.',
								'%d browsers skip the code.',
								status.trusted,
								'nhrrob-secure'
							),
							status.trusted
						) }{ ' ' }
						<button
							type="button"
							className="button-link"
							onClick={ async () => {
								const res = await call(
									'/forget-browsers',
									{}
								);
								if ( res ) {
									setStatus( res );
								}
							} }
						>
							{ __(
								'Ask on every browser again',
								'nhrrob-secure'
							) }
						</button>
					</p>
				) }
				<button
					type="button"
					className="button"
					onClick={ () => setAsk( 'recovery' ) }
				>
					{ __( 'New recovery codes', 'nhrrob-secure' ) }
				</button>{ ' ' }
				{ ! status.required && (
					<button
						type="button"
						className="button"
						onClick={ () => setAsk( 'disable' ) }
					>
						{ __( 'Switch off', 'nhrrob-secure' ) }
					</button>
				) }
				{ status.required && (
					<p className="description">
						{ __(
							'Your role must use two-factor, so it cannot be switched off. To change method or phone, ask another administrator to reset it.',
							'nhrrob-secure'
						) }
					</p>
				) }
			</div>
		);
	}

	return (
		<div>
			{ notice }
			<p>
				{ status.required
					? __(
							'Your role must use two-factor authentication: after your password you enter a short code, so a stolen password alone is not enough.',
							'nhrrob-secure'
					  )
					: __(
							'Add a second step to your sign-in: after your password you enter a short code, so a stolen password alone is not enough.',
							'nhrrob-secure'
					  ) }
			</p>
			{ status.methods.includes( 'app' ) && (
				<button
					type="button"
					className="button button-primary"
					disabled={ busy }
					onClick={ () => begin( 'app' ) }
				>
					{ __(
						'Set up with an authenticator app',
						'nhrrob-secure'
					) }
				</button>
			) }{ ' ' }
			{ status.methods.includes( 'passkey' ) &&
				window.PublicKeyCredential && (
					<button
						type="button"
						className="button"
						disabled={ busy }
						onClick={ passkey }
					>
						{ __( 'Set up with a passkey', 'nhrrob-secure' ) }
					</button>
				) }{ ' ' }
			{ status.methods.includes( 'email' ) && (
				<button
					type="button"
					className="button"
					disabled={ busy }
					onClick={ () => begin( 'email' ) }
				>
					{ __( 'Use emailed codes instead', 'nhrrob-secure' ) }
				</button>
			) }
		</div>
	);
}

document.addEventListener( 'DOMContentLoaded', () => {
	const el = document.getElementById( 'nhrrob-secure-2fa-app' );
	if ( el ) {
		createRoot( el ).render( <App /> );
	}
} );
