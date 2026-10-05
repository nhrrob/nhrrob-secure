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
	const [ files, setFiles ] = useState( null );
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
					9
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
						'Removes the version from the page source, feeds and asset addresses.',
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
		</>
	);
}
