/**
 * Hardening: switch off what you don't use, and protect files the server hands out.
 */
import { useState, useEffect } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';

import api from '../api';
import {
	ScreenHeader,
	Panel,
	Pill,
	Button,
	Row,
	Switch,
	TagList,
	Note,
	Loading,
	ago,
} from '../components/ui';
import { useToast } from '../components/ToastProvider';
import { useConfirm } from '../components/ConfirmProvider';

function StatePill( { state, id } ) {
	const open = {
		uploads_php: __( 'PHP can run here', 'nhrrob-secure' ),
		listing: __( 'Contents are listed', 'nhrrob-secure' ),
	};
	const map = {
		protected: [ 'ok', __( 'Protected', 'nhrrob-secure' ) ],
		open: [
			'bad',
			open[ id ] || __( 'Readable by anyone', 'nhrrob-secure' ),
		],
		absent: [ 'off', __( 'No such file', 'nhrrob-secure' ) ],
		unknown: [ 'warn', __( 'Could not check', 'nhrrob-secure' ) ],
	};
	const [ tone, label ] = map[ state ] || map.unknown;
	return <Pill tone={ tone }>{ label }</Pill>;
}

export default function Hardening( { settings, meta, save } ) {
	const toast = useToast();
	const confirm = useConfirm();
	const [ files, setFiles ] = useState( null );
	const [ rotating, setRotating ] = useState( false );
	const [ checking, setChecking ] = useState( false );

	const [ failed, setFailed ] = useState( null );

	useEffect( () => {
		api( '/hardening' ).then( setFiles ).catch( setFailed );
	}, [] );

	const check = async () => {
		setChecking( true );
		try {
			setFiles( await api( '/hardening/check', 'POST' ) );
		} catch ( e ) {
			toast( e.message, 'error' );
		}
		setChecking( false );
	};

	const fixPermissions = async ( id ) => {
		try {
			setFiles( await api( '/hardening/permissions', 'POST', { id } ) );
			toast( __( 'Permissions changed', 'nhrrob-secure' ) );
		} catch ( e ) {
			toast( e.message, 'error' );
		}
	};

	const rotateKeys = async () => {
		if (
			! ( await confirm(
				__( 'Replace the secret keys?', 'nhrrob-secure' ),
				{
					description: __(
						'Everyone is signed out, you included, and trusted browsers are asked for their second step again. Nothing else changes.',
						'nhrrob-secure'
					),
					confirmLabel: __( 'Replace keys', 'nhrrob-secure' ),
				}
			) )
		) {
			return;
		}
		setRotating( true );
		try {
			await api( '/hardening/keys', 'POST' );
			window.location.reload();
		} catch ( e ) {
			toast( e.message, 'error' );
			setRotating( false );
		}
	};

	const toggle = ( key, label, help, risk, recommended ) => (
		<Row
			key={ key }
			label={ label }
			help={ help }
			risk={ risk }
			badge={
				recommended && ! settings[ key ] ? (
					<Pill tone="warn">
						{ __( 'Recommended', 'nhrrob-secure' ) }
					</Pill>
				) : null
			}
			control={
				<Switch
					checked={ settings[ key ] }
					label={ label }
					onChange={ ( v ) => save( { [ key ]: v } ) }
				/>
			}
		/>
	);

	const on = [
		'disable_xmlrpc',
		'disable_file_editor',
		'hide_usernames',
		'disable_app_passwords',
		'hide_wp_version',
		'strong_passwords',
		'breached_passwords',
		'security_headers',
		'rest_signed_in_only',
		'disable_feeds',
		'trim_head',
	].filter( ( key ) => settings[ key ] ).length;

	const copy = async () => {
		try {
			await window.navigator.clipboard.writeText( files.nginx );
			toast( __( 'Copied', 'nhrrob-secure' ) );
		} catch ( e ) {
			toast(
				__(
					'Select the lines and copy them by hand.',
					'nhrrob-secure'
				),
				'error'
			);
		}
	};

	return (
		<>
			<ScreenHeader
				title={ __( 'Hardening', 'nhrrob-secure' ) }
				lede={ __(
					'Switch off what you don’t use. Each line says what could stop working, so you can decide.',
					'nhrrob-secure'
				) }
			/>

			<Panel
				title={ __( 'WordPress features', 'nhrrob-secure' ) }
				icon="hardening"
				meta={ sprintf(
					/* translators: 1: switches that are on, 2: all switches. */
					__( '%1$d of %2$d on', 'nhrrob-secure' ),
					on,
					11
				) }
			>
				{ toggle(
					'disable_xmlrpc',
					__( 'Turn off XML-RPC', 'nhrrob-secure' ),
					__(
						'Closes the old remote API completely, pingbacks included.',
						'nhrrob-secure'
					),
					__(
						'the Jetpack connection and very old mobile or desktop apps.',
						'nhrrob-secure'
					),
					true
				) }
				{ toggle(
					'disable_file_editor',
					__(
						'Turn off the theme and plugin file editor',
						'nhrrob-secure'
					),
					__(
						'Nobody can edit PHP files from wp-admin, even with a stolen administrator session.',
						'nhrrob-secure'
					),
					'',
					true
				) }
				{ toggle(
					'hide_usernames',
					__( 'Hide usernames from visitors', 'nhrrob-secure' ),
					__(
						'Covers the REST users list, /?author=1 probes and the users sitemap. Author pages reached by their normal address keep working.',
						'nhrrob-secure'
					),
					__(
						'front-end features that read the public users list.',
						'nhrrob-secure'
					),
					true
				) }
				{ toggle(
					'disable_app_passwords',
					__( 'Turn off application passwords', 'nhrrob-secure' ),
					__( 'Removes password-based API access.', 'nhrrob-secure' ),
					__(
						'apps and services that connect with an application password.',
						'nhrrob-secure'
					)
				) }
				{ toggle(
					'hide_wp_version',
					__( 'Hide the WordPress version', 'nhrrob-secure' ),
					__(
						'Removes the version from the page source, feeds and asset addresses, and PHP’s own X-Powered-By header.',
						'nhrrob-secure'
					)
				) }
				{ toggle(
					'trim_head',
					__(
						'Remove discovery links from the page head',
						'nhrrob-secure'
					),
					__(
						'The links that tell programs where the REST API, oEmbed data, the short link and the remote-editing endpoint are. Browsers and search engines do not use them.',
						'nhrrob-secure'
					),
					__(
						'previews of your pages when their address is pasted into another WordPress site.',
						'nhrrob-secure'
					)
				) }
				{ toggle(
					'disable_feeds',
					__( 'Turn off RSS and Atom feeds', 'nhrrob-secure' ),
					__(
						'Feed addresses lead to the home page instead.',
						'nhrrob-secure'
					),
					__(
						'feed readers, podcast apps and newsletter services that read your feed.',
						'nhrrob-secure'
					)
				) }
				{ toggle(
					'strong_passwords',
					__(
						'Require strong passwords for administrators and editors',
						'nhrrob-secure'
					),
					__(
						'At least 12 characters, more than one kind of character, and not built from the username. Checked whenever a password is set.',
						'nhrrob-secure'
					),
					'',
					true
				) }
				{ toggle(
					'breached_passwords',
					__(
						'Refuse passwords found in known breaches',
						'nhrrob-secure'
					),
					__(
						'Asks the Have I Been Pwned service when an administrator or editor sets a password. Only the first five characters of a hash are sent, never the password.',
						'nhrrob-secure'
					)
				) }
				{ toggle(
					'rest_signed_in_only',
					__( 'REST API for signed-in users only', 'nhrrob-secure' ),
					__(
						'Visitors who are not signed in get no answer from the REST API, except for the routes you leave public below.',
						'nhrrob-secure'
					),
					__(
						'front-end features that load data in the browser: forms, search, shop blocks, mobile apps.',
						'nhrrob-secure'
					)
				) }
				{ settings.rest_signed_in_only && (
					<Row
						label={ __( 'Routes left public', 'nhrrob-secure' ) }
						help={ __(
							'Beginning of the route after /wp-json/, for example contact-form-7/ or wc/store/.',
							'nhrrob-secure'
						) }
					>
						<TagList
							values={ settings.rest_public }
							placeholder={ __(
								'e.g. my-plugin/v1',
								'nhrrob-secure'
							) }
							onChange={ ( list ) =>
								save( { rest_public: list } )
							}
						/>
					</Row>
				) }
				{ toggle(
					'security_headers',
					__( 'Send security headers', 'nhrrob-secure' ),
					__(
						'X-Content-Type-Options, X-Frame-Options, Referrer-Policy and, on HTTPS, Strict-Transport-Security.',
						'nhrrob-secure'
					),
					__(
						'pages of yours that other sites show inside a frame.',
						'nhrrob-secure'
					)
				) }
			</Panel>

			<Panel
				title={ __( 'File protection', 'nhrrob-secure' ) }
				icon="file"
				anchor="files"
				flush
				meta={
					files
						? sprintf(
								/* translators: %s: relative time, e.g. "5 mins ago". */
								__( 'Checked %s', 'nhrrob-secure' ),
								ago( files.checked )
						  )
						: ''
				}
				actions={
					<Button small disabled={ checking } onClick={ check }>
						{ checking
							? __( 'Checking…', 'nhrrob-secure' )
							: __( 'Check again', 'nhrrob-secure' ) }
					</Button>
				}
			>
				{ ! files && <Loading error={ failed } /> }
				{ files && (
					<>
						<div className="nhrrob-secure-pad">
							<p className="nhrrob-secure-muted">
								{ __(
									'Files that exist are handed out by the web server without WordPress loading, so a plugin cannot guard them from PHP. Each item below was requested from your own site; it only says “Protected” when that request was refused.',
									'nhrrob-secure'
								) }
							</p>
						</div>
						<div className="nhrrob-secure-scroll">
							<table className="nhrrob-secure-grid">
								<thead>
									<tr>
										<th>
											{ __( 'What', 'nhrrob-secure' ) }
										</th>
										<th>
											{ __(
												'We requested',
												'nhrrob-secure'
											) }
										</th>
										<th>
											{ __( 'Result', 'nhrrob-secure' ) }
										</th>
									</tr>
								</thead>
								<tbody>
									{ files.items.map( ( item ) => (
										<tr key={ item.id }>
											<td>{ item.label }</td>
											<td className="is-mono is-wrap">
												{ item.path }
											</td>
											<td>
												<StatePill
													state={ item.state }
													id={ item.id }
												/>
											</td>
										</tr>
									) ) }
								</tbody>
							</table>
						</div>
						<div className="nhrrob-secure-pad">
							{ files.can_write && meta.can_files && (
								<Row
									label={ __(
										'Protect these files',
										'nhrrob-secure'
									) }
									help={ __(
										'Adds a short block of rules to your .htaccess file. If the site stops answering afterwards, the rules are removed again straight away.',
										'nhrrob-secure'
									) }
									control={
										<Switch
											checked={ settings.protect_files }
											label={ __(
												'Protect these files',
												'nhrrob-secure'
											) }
											onChange={ async ( v ) => {
												if (
													await save( {
														protect_files: v,
													} )
												) {
													api( '/hardening' )
														.then( setFiles )
														.catch( setFailed );
												}
											} }
										/>
									}
								/>
							) }
							{ ! files.can_write && (
								<>
									<Note tone="warn">
										{ files.server === 'nginx'
											? __(
													'Your server is nginx, which ignores .htaccess, so a plugin cannot switch this on for you. Add the lines below to your site’s server block (or send them to your host), reload nginx, then check again.',
													'nhrrob-secure'
											  )
											: __(
													'The plugin cannot write these rules on this server. If it runs nginx, add the lines below to your site’s server block (or send them to your host), then check again.',
													'nhrrob-secure'
											  ) }
									</Note>
									<pre className="nhrrob-secure-code">
										{ files.nginx }
									</pre>
									<Button variant="soft" onClick={ copy }>
										{ __( 'Copy lines', 'nhrrob-secure' ) }
									</Button>
								</>
							) }
						</div>
					</>
				) }
			</Panel>

			{ files && files.permissions.length > 0 && (
				<Panel
					title={ __( 'File permissions', 'nhrrob-secure' ) }
					icon="file"
					anchor="permissions"
					flush
				>
					<div className="nhrrob-secure-pad">
						<p className="nhrrob-secure-muted">
							{ __(
								'A file or folder that every account on the server may write to can be changed by a neighbour on shared hosting, or through any other site on the same server. The fix takes away that one permission and leaves the rest as it is.',
								'nhrrob-secure'
							) }
						</p>
					</div>
					<div className="nhrrob-secure-scroll">
						<table className="nhrrob-secure-grid">
							<thead>
								<tr>
									<th>{ __( 'Path', 'nhrrob-secure' ) }</th>
									<th>
										{ __( 'Permissions', 'nhrrob-secure' ) }
									</th>
									<th>{ __( 'Result', 'nhrrob-secure' ) }</th>
									<th />
								</tr>
							</thead>
							<tbody>
								{ files.permissions.map( ( item ) => (
									<tr key={ item.id }>
										<td className="is-mono is-wrap">
											{ item.path }
										</td>
										<td className="is-mono">
											{ item.mode }
										</td>
										<td>
											<Pill
												tone={
													item.open ? 'bad' : 'ok'
												}
											>
												{ item.open
													? __(
															'Anyone can write',
															'nhrrob-secure'
													  )
													: __(
															'Fine',
															'nhrrob-secure'
													  ) }
											</Pill>
										</td>
										<td className="is-actions">
											{ item.open && meta.can_files && (
												<Button
													small
													onClick={ () =>
														fixPermissions(
															item.id
														)
													}
												>
													{ __(
														'Fix',
														'nhrrob-secure'
													) }
												</Button>
											) }
										</td>
									</tr>
								) ) }
							</tbody>
						</table>
					</div>
				</Panel>
			) }

			{ files && files.keys !== null && (
				<Panel
					title={ __( 'Secret keys', 'nhrrob-secure' ) }
					icon="login"
				>
					<Row
						label={ __(
							'Replace the secret keys in wp-config.php',
							'nhrrob-secure'
						) }
						help={
							files.keys ||
							__(
								'Use this after a suspected break-in: every sign-in cookie stops working, so a copied cookie or a copied wp-config.php is worth nothing. The new file is checked before it replaces the old one, and the old one is put back if the site does not answer.',
								'nhrrob-secure'
							)
						}
					>
						<Button
							variant="danger"
							disabled={ !! files.keys || rotating }
							onClick={ rotateKeys }
						>
							{ rotating
								? __( 'Replacing…', 'nhrrob-secure' )
								: __( 'Replace keys', 'nhrrob-secure' ) }
						</Button>
					</Row>
				</Panel>
			) }
		</>
	);
}
