/**
 * Login: attempt limits, lockouts, login address, two-factor and bot check.
 */
import { useState, useEffect } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';

import api from '../api';
import {
	ScreenHeader,
	Panel,
	Pill,
	Button,
	Row,
	Switch,
	Field,
	Chips,
	TextSetting,
	Note,
	Empty,
	until,
} from '../components/ui';
import { useToast } from '../components/ToastProvider';
import { useConfirm } from '../components/ConfirmProvider';

function OnOff( { on } ) {
	return (
		<Pill tone={ on ? 'ok' : 'off' }>
			{ on ? __( 'On', 'nhrrob-secure' ) : __( 'Off', 'nhrrob-secure' ) }
		</Pill>
	);
}

export default function Login( { boot, settings, meta, save } ) {
	const toast = useToast();
	const confirm = useConfirm();
	const [ locked, setLocked ] = useState( [] );
	const [ slug, setSlug ] = useState( settings.login_slug );
	const [ secret, setSecret ] = useState( '' );

	useEffect( () => {
		api( '/login' ).then( ( res ) => setLocked( res.locked ) );
	}, [] );

	const unlock = async ( ip ) => {
		const res = await api( '/login/unlock', 'POST', { ip } );
		setLocked( res.locked );
		toast(
			ip
				? /* translators: %s: IP address. */
				  sprintf( __( 'Unlocked %s', 'nhrrob-secure' ), ip )
				: __( 'Unlocked every address', 'nhrrob-secure' )
		);
	};

	const moveLogin = async ( on ) => {
		if ( ! on ) {
			save(
				{ login_url_enabled: false },
				__(
					'The sign-in page is back at wp-login.php',
					'nhrrob-secure'
				)
			);
			return;
		}
		const url = meta.home + slug.replace( /^\/+|\/+$/g, '' );
		const ok = await confirm(
			__( 'Move the sign-in page?', 'nhrrob-secure' ),
			{
				description: sprintf(
					/* translators: %s: the new sign-in address. */
					__(
						'You will sign in at %s from now on. wp-login.php and wp-admin will answer "Not found" to anyone who is not signed in. We test the new address first and email it to you.',
						'nhrrob-secure'
					),
					url
				),
				confirmLabel: __( 'Move it', 'nhrrob-secure' ),
				danger: false,
			}
		);
		if ( ok ) {
			save(
				{ login_slug: slug, login_url_enabled: true },
				__(
					'Moved. The new address is in your inbox.',
					'nhrrob-secure'
				)
			);
		}
	};

	const roles = meta.roles;
	const methods = [
		{ value: 'app', label: __( 'Authenticator app', 'nhrrob-secure' ) },
		{ value: 'email', label: __( 'Email code', 'nhrrob-secure' ) },
		{ value: 'passkey', label: __( 'Passkey', 'nhrrob-secure' ) },
	];
	const toggleIn = ( key, value, on ) =>
		save( {
			[ key ]: on
				? [ ...settings[ key ], value ]
				: settings[ key ].filter( ( v ) => v !== value ),
		} );

	return (
		<>
			<ScreenHeader
				title={ __( 'Login', 'nhrrob-secure' ) }
				lede={ __(
					'Everything that stands between a stranger and your sign-in form. Changes save as you make them.',
					'nhrrob-secure'
				) }
			/>

			<Panel
				title={ __( 'Limit login attempts', 'nhrrob-secure' ) }
				icon="login"
				actions={ <OnOff on={ settings.limit_login } /> }
			>
				<Row
					label={ __(
						'Lock out after repeated failures',
						'nhrrob-secure'
					) }
					help={ __(
						'An address is locked when one username fails this many times, or when it tries many different usernames. Addresses on your allow list are never locked.',
						'nhrrob-secure'
					) }
					control={
						<Switch
							checked={ settings.limit_login }
							label={ __(
								'Limit login attempts',
								'nhrrob-secure'
							) }
							onChange={ ( v ) => save( { limit_login: v } ) }
						/>
					}
				>
					<Field label={ __( 'Failed attempts', 'nhrrob-secure' ) }>
						<TextSetting
							type="number"
							min="1"
							max="20"
							className="is-narrow"
							value={ settings.login_attempts }
							onCommit={ ( v ) => save( { login_attempts: v } ) }
						/>
					</Field>
					<Field label={ __( 'First lockout', 'nhrrob-secure' ) }>
						<select
							className="nhrrob-secure-select"
							value={ settings.lockout_minutes }
							onChange={ ( e ) =>
								save( { lockout_minutes: e.target.value } )
							}
						>
							<option value="20">
								{ __( '20 minutes', 'nhrrob-secure' ) }
							</option>
							<option value="60">
								{ __( '1 hour', 'nhrrob-secure' ) }
							</option>
							<option value="1440">
								{ __( '24 hours', 'nhrrob-secure' ) }
							</option>
							{ ! [ 20, 60, 1440 ].includes(
								Number( settings.lockout_minutes )
							) && (
								<option value={ settings.lockout_minutes }>
									{ sprintf(
										/* translators: %d: minutes. */
										__( '%d minutes', 'nhrrob-secure' ),
										settings.lockout_minutes
									) }
								</option>
							) }
						</select>
					</Field>
					<Field label={ __( 'Repeat offenders', 'nhrrob-secure' ) }>
						<select
							className="nhrrob-secure-select"
							value={ settings.lockout_progressive ? '1' : '0' }
							onChange={ ( e ) =>
								save( {
									lockout_progressive: e.target.value === '1',
								} )
							}
						>
							<option value="1">
								{ __(
									'Double each time, up to 24 hours',
									'nhrrob-secure'
								) }
							</option>
							<option value="0">
								{ __(
									'Same length every time',
									'nhrrob-secure'
								) }
							</option>
						</select>
					</Field>
				</Row>
				<Row
					label={ __(
						'Email me when an address is locked out',
						'nhrrob-secure'
					) }
					help={ sprintf(
						/* translators: %s: email address. */
						__(
							'At most one email every 15 minutes, to %s.',
							'nhrrob-secure'
						),
						meta.alert_to
					) }
					control={
						<Switch
							checked={ settings.lockout_email }
							label={ __( 'Email on lockout', 'nhrrob-secure' ) }
							onChange={ ( v ) => save( { lockout_email: v } ) }
						/>
					}
				/>
				<Row
					label={ __(
						'Don’t reveal which part was wrong',
						'nhrrob-secure'
					) }
					help={ __(
						'Shows “The username or password is incorrect” for every failure, so the form does not confirm that a username exists.',
						'nhrrob-secure'
					) }
					control={
						<Switch
							checked={ settings.generic_login_errors }
							label={ __(
								'Generic sign-in errors',
								'nhrrob-secure'
							) }
							onChange={ ( v ) =>
								save( { generic_login_errors: v } )
							}
						/>
					}
				/>
			</Panel>

			<Panel
				title={ __( 'Locked out now', 'nhrrob-secure' ) }
				icon="alert"
				anchor="lockouts"
				flush
				meta={ sprintf(
					/* translators: %d: number of addresses. */
					_n(
						'%d address',
						'%d addresses',
						locked.length,
						'nhrrob-secure'
					),
					locked.length
				) }
				actions={
					locked.length > 1 && (
						<Button small onClick={ () => unlock( '' ) }>
							{ __( 'Unlock all', 'nhrrob-secure' ) }
						</Button>
					)
				}
			>
				{ locked.length ? (
					<div className="nhrrob-secure-scroll">
						<table className="nhrrob-secure-grid">
							<thead>
								<tr>
									<th>
										{ __( 'Address', 'nhrrob-secure' ) }
									</th>
									<th>
										{ __( 'Tried as', 'nhrrob-secure' ) }
									</th>
									<th>
										{ __( 'Attempts', 'nhrrob-secure' ) }
									</th>
									<th>
										{ __( 'Unlocks in', 'nhrrob-secure' ) }
									</th>
									<th />
								</tr>
							</thead>
							<tbody>
								{ locked.map( ( row ) => (
									<tr key={ row.ip }>
										<td className="is-mono">{ row.ip }</td>
										<td className="is-wrap">
											{ row.probing
												? __(
														'Hunting for files (locked out of the whole site)',
														'nhrrob-secure'
												  )
												: row.users.join( ', ' ) }
										</td>
										<td>{ row.attempts }</td>
										<td>{ until( row.until ) }</td>
										<td className="is-actions">
											<Button
												small
												onClick={ () =>
													unlock( row.ip )
												}
											>
												{ __(
													'Unlock',
													'nhrrob-secure'
												) }
											</Button>
										</td>
									</tr>
								) ) }
							</tbody>
						</table>
					</div>
				) : (
					<Empty>
						{ __( 'Nobody is locked out.', 'nhrrob-secure' ) }
					</Empty>
				) }
			</Panel>

			<Panel
				title={ __( 'Login address', 'nhrrob-secure' ) }
				icon="link"
				actions={ <OnOff on={ settings.login_url_enabled } /> }
			>
				<Row
					label={ __( 'Move the sign-in page', 'nhrrob-secure' ) }
					help={ __(
						'wp-login.php and wp-admin answer “Not found” to anyone who is not signed in.',
						'nhrrob-secure'
					) }
					control={
						<Switch
							checked={ settings.login_url_enabled }
							label={ __(
								'Move the sign-in page',
								'nhrrob-secure'
							) }
							disabled={ ! meta.permalinks }
							onChange={ moveLogin }
						/>
					}
				>
					<Field label={ __( 'New address', 'nhrrob-secure' ) }>
						<span className="nhrrob-secure-affix">
							<span>
								{ meta.home.replace( /^https?:\/\//, '' ) }
							</span>
							<input
								type="text"
								value={ slug }
								placeholder="team-door"
								onChange={ ( e ) => setSlug( e.target.value ) }
							/>
						</span>
					</Field>
					{ settings.login_url_enabled &&
						slug !== settings.login_slug && (
							<Button
								variant="soft"
								onClick={ () => moveLogin( true ) }
							>
								{ __( 'Change address', 'nhrrob-secure' ) }
							</Button>
						) }
				</Row>
				{ ! meta.permalinks && (
					<Note tone="warn">
						{ __(
							'This needs pretty permalinks. Choose any structure except “Plain” under Settings → Permalinks first.',
							'nhrrob-secure'
						) }
					</Note>
				) }
				{ meta.login_url && (
					<Note>
						{ __( 'You sign in at', 'nhrrob-secure' ) }{ ' ' }
						<code>{ meta.login_url }</code>
					</Note>
				) }
				<Note>
					{ __(
						'Locked out? Add this line to wp-config.php and wp-login.php works again:',
						'nhrrob-secure'
					) }{ ' ' }
					<code>
						define( &#39;NHRROB_SECURE_SAFE_MODE&#39;, true );
					</code>
				</Note>
			</Panel>

			<Panel
				title={ __( 'Two-factor', 'nhrrob-secure' ) }
				icon="phone"
				anchor="twofa"
				actions={ <OnOff on={ settings.twofa_enabled } /> }
			>
				<Row
					label={ __(
						'Let users add a second step',
						'nhrrob-secure'
					) }
					help={ __(
						'Each user sets it up on their profile and has to enter a working code before it switches on.',
						'nhrrob-secure'
					) }
					control={
						<Switch
							checked={ settings.twofa_enabled }
							label={ __( 'Two-factor', 'nhrrob-secure' ) }
							onChange={ ( v ) => save( { twofa_enabled: v } ) }
						/>
					}
				>
					<Field
						label={ __(
							'Methods users can choose',
							'nhrrob-secure'
						) }
					>
						<Chips
							items={ methods }
							selected={ settings.twofa_methods }
							onToggle={ ( value, on ) =>
								toggleIn( 'twofa_methods', value, on )
							}
						/>
					</Field>
					{ settings.twofa_enabled && (
						<a
							className="nhrrob-secure-btn nhrrob-secure-btn--soft"
							href={ boot.profileUrl }
						>
							{ __( 'Set up yours', 'nhrrob-secure' ) }
						</a>
					) }
				</Row>
				<Row
					label={ __( 'Required for', 'nhrrob-secure' ) }
					help={ __(
						'These roles must set it up. Everyone else can choose.',
						'nhrrob-secure'
					) }
				>
					<Chips
						items={ roles }
						selected={ settings.twofa_roles }
						onToggle={ ( value, on ) =>
							toggleIn( 'twofa_roles', value, on )
						}
					/>
					<Field label={ __( 'Trusted browsers', 'nhrrob-secure' ) }>
						<select
							className="nhrrob-secure-select"
							value={ settings.twofa_trust_days }
							onChange={ ( e ) =>
								save( { twofa_trust_days: e.target.value } )
							}
						>
							<option value="0">
								{ __(
									'Always ask for the code',
									'nhrrob-secure'
								) }
							</option>
							{ [ 7, 30, 90 ].map( ( days ) => (
								<option key={ days } value={ days }>
									{ sprintf(
										/* translators: %d: number of days. */
										__(
											'Let users skip it for %d days',
											'nhrrob-secure'
										),
										days
									) }
								</option>
							) ) }
						</select>
					</Field>
					<Field label={ __( 'Time to set up', 'nhrrob-secure' ) }>
						<select
							className="nhrrob-secure-select"
							value={ settings.twofa_grace_days }
							onChange={ ( e ) =>
								save( { twofa_grace_days: e.target.value } )
							}
						>
							<option value="0">
								{ __( 'At the next sign-in', 'nhrrob-secure' ) }
							</option>
							<option value="3">
								{ __( '3 days', 'nhrrob-secure' ) }
							</option>
							<option value="7">
								{ __( '7 days', 'nhrrob-secure' ) }
							</option>
							<option value="14">
								{ __( '14 days', 'nhrrob-secure' ) }
							</option>
						</select>
					</Field>
				</Row>
			</Panel>

			<Panel
				title={ __( 'Bot check', 'nhrrob-secure' ) }
				icon="bot"
				actions={ <OnOff on={ settings.turnstile_enabled } /> }
			>
				<Row
					label={ __(
						'“I am human” check on sign-in, register and lost password',
						'nhrrob-secure'
					) }
					help={ __(
						'Needs your own keys from the provider you choose. While it is on, the visitor’s browser loads that provider’s script on those three screens.',
						'nhrrob-secure'
					) }
					control={
						<Switch
							checked={ settings.turnstile_enabled }
							label={ __( 'Bot check', 'nhrrob-secure' ) }
							onChange={ ( v ) =>
								save( { turnstile_enabled: v } )
							}
						/>
					}
				>
					<Field label={ __( 'Provider', 'nhrrob-secure' ) }>
						<select
							className="nhrrob-secure-select"
							value={ settings.captcha_provider }
							onChange={ ( e ) =>
								save( { captcha_provider: e.target.value } )
							}
						>
							<option value="turnstile">
								Cloudflare Turnstile
							</option>
							<option value="recaptcha">
								Google reCAPTCHA v2
							</option>
							<option value="hcaptcha">hCaptcha</option>
						</select>
					</Field>
					<Field label={ __( 'Site key', 'nhrrob-secure' ) }>
						<TextSetting
							type="text"
							value={ settings.turnstile_site_key }
							onCommit={ ( v ) =>
								save( { turnstile_site_key: v } )
							}
						/>
					</Field>
					<Field label={ __( 'Secret key', 'nhrrob-secure' ) }>
						<input
							type="password"
							className="nhrrob-secure-input"
							value={ secret }
							autoComplete="off"
							placeholder={
								settings.turnstile_secret_set
									? __(
											'Saved. Type to replace.',
											'nhrrob-secure'
									  )
									: ''
							}
							onChange={ ( e ) => setSecret( e.target.value ) }
							onBlur={ async () => {
								if (
									secret &&
									( await save( {
										turnstile_secret: secret,
									} ) )
								) {
									setSecret( '' );
								}
							} }
						/>
					</Field>
				</Row>
			</Panel>
		</>
	);
}
