/**
 * Users & Sessions: who can sign in, how well each account is protected and
 * where they are signed in.
 */
import { useState, useEffect, useCallback } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';

import api, { query } from '../api';
import {
	ScreenHeader,
	Panel,
	Pill,
	Button,
	Row,
	Switch,
	Field,
	Loading,
	Empty,
	when,
	until,
} from '../components/ui';
import { useToast } from '../components/ToastProvider';
import { useConfirm } from '../components/ConfirmProvider';

/**
 * "Chrome on macOS" from a user-agent string.
 *
 * @param {string} ua User agent.
 * @return {string} Short description.
 */
function device( ua ) {
	const browsers = [
		[ /Edg\//, 'Edge' ],
		[ /OPR\//, 'Opera' ],
		[ /Firefox\//, 'Firefox' ],
		[ /Chrome\//, 'Chrome' ],
		[ /Safari\//, 'Safari' ],
	];
	const systems = [
		[ /iPhone|iPad/, 'iOS' ],
		[ /Android/, 'Android' ],
		[ /Windows/, 'Windows' ],
		[ /Mac OS X/, 'macOS' ],
		[ /Linux/, 'Linux' ],
	];
	const browser = browsers.find( ( b ) => b[ 0 ].test( ua ) );
	const system = systems.find( ( s ) => s[ 0 ].test( ua ) );
	if ( ! browser || ! system ) {
		return __( 'Unknown device', 'nhrrob-secure' );
	}
	return sprintf(
		/* translators: 1: browser, 2: operating system. */
		__( '%1$s on %2$s', 'nhrrob-secure' ),
		browser[ 1 ],
		system[ 1 ]
	);
}

function twofa( user, enabled ) {
	if ( user.twofa === 'app' ) {
		return <Pill tone="ok">{ __( 'App', 'nhrrob-secure' ) }</Pill>;
	}
	if ( user.twofa === 'email' ) {
		return <Pill tone="info">{ __( 'Email code', 'nhrrob-secure' ) }</Pill>;
	}
	if ( enabled && user.required ) {
		const left =
			user.due && user.due * 1000 > Date.now()
				? sprintf(
						/* translators: %s: time left, e.g. "5 days". */
						__( 'Not set · %s left', 'nhrrob-secure' ),
						until( user.due )
				  )
				: __( 'Not set · required', 'nhrrob-secure' );
		return <Pill tone="bad">{ left }</Pill>;
	}
	return <Pill>{ __( 'Off', 'nhrrob-secure' ) }</Pill>;
}

export default function Users( { settings, meta, save } ) {
	const toast = useToast();
	const confirm = useConfirm();
	const [ data, setData ] = useState( null );
	const [ search, setSearch ] = useState( '' );
	const [ role, setRole ] = useState( '' );
	const [ page, setPage ] = useState( 1 );
	const [ scope, setScope ] = useState( '*' );

	const load = useCallback( () => {
		api( '/users' + query( { search, role, page } ) )
			.then( setData )
			.catch( ( e ) => toast( e.message, 'error' ) );
	}, [ search, role, page, toast ] );

	useEffect( () => {
		const timer = setTimeout( load, search ? 300 : 0 );
		return () => clearTimeout( timer );
	}, [ load, search ] );

	const act = async ( path, message ) => {
		try {
			await api( path, 'POST' );
			toast( message );
			load();
		} catch ( e ) {
			toast( e.message, 'error' );
		}
	};

	const signOutAll = async () => {
		if (
			await confirm( __( 'Sign out everyone else?', 'nhrrob-secure' ), {
				description: __(
					'Every session except this one ends. People will have to sign in again.',
					'nhrrob-secure'
				),
				confirmLabel: __( 'Sign everyone out', 'nhrrob-secure' ),
			} )
		) {
			act(
				'/users/signout-all',
				__( 'Everyone else has been signed out', 'nhrrob-secure' )
			);
		}
	};

	const forceScope = async () => {
		if (
			await confirm( __( 'Require new passwords?', 'nhrrob-secure' ), {
				description: __(
					'Every affected user has to choose a new password before they can use the dashboard again.',
					'nhrrob-secure'
				),
				confirmLabel: __( 'Require new passwords', 'nhrrob-secure' ),
			} )
		) {
			try {
				await api( '/users/force-password', 'POST', { scope } );
				toast(
					__( 'New passwords are now required', 'nhrrob-secure' )
				);
				load();
			} catch ( e ) {
				toast( e.message, 'error' );
			}
		}
	};

	const resetTwoFactor = async ( user ) => {
		if (
			await confirm(
				sprintf(
					/* translators: %s: username. */
					__( 'Reset two-factor for %s?', 'nhrrob-secure' ),
					user.login
				),
				{
					description: __(
						'Their authenticator and recovery codes stop working and they sign in with a password until they set it up again.',
						'nhrrob-secure'
					),
					confirmLabel: __( 'Reset', 'nhrrob-secure' ),
				}
			)
		) {
			act(
				'/users/' + user.id + '/reset-2fa',
				sprintf(
					/* translators: %s: username. */
					__( 'Two-factor reset for %s', 'nhrrob-secure' ),
					user.login
				)
			);
		}
	};

	const pages = data ? Math.max( 1, Math.ceil( data.total / 20 ) ) : 1;

	return (
		<>
			<ScreenHeader
				title={ __( 'Users & Sessions', 'nhrrob-secure' ) }
				lede={ __(
					'Who can sign in, how well each account is protected, and where they are signed in right now.',
					'nhrrob-secure'
				) }
			/>

			<Panel flush>
				<div className="nhrrob-secure-toolbar">
					<input
						type="search"
						className="nhrrob-secure-input"
						placeholder={ __( 'Search users', 'nhrrob-secure' ) }
						aria-label={ __( 'Search users', 'nhrrob-secure' ) }
						value={ search }
						onChange={ ( e ) => {
							setPage( 1 );
							setSearch( e.target.value );
						} }
					/>
					<select
						className="nhrrob-secure-select"
						aria-label={ __( 'Role', 'nhrrob-secure' ) }
						value={ role }
						onChange={ ( e ) => {
							setPage( 1 );
							setRole( e.target.value );
						} }
					>
						<option value="">
							{ __( 'All roles', 'nhrrob-secure' ) }
						</option>
						{ meta.roles.map( ( r ) => (
							<option key={ r.value } value={ r.value }>
								{ r.label }
							</option>
						) ) }
					</select>
					{ meta.can_files && (
						<Button variant="danger" onClick={ signOutAll }>
							{ __( 'Sign out everyone else', 'nhrrob-secure' ) }
						</Button>
					) }
				</div>

				{ ! data && <Loading /> }
				{ data && ! data.items.length && (
					<Empty>{ __( 'No users found.', 'nhrrob-secure' ) }</Empty>
				) }
				{ data && data.items.length > 0 && (
					<div className="nhrrob-secure-scroll">
						<table className="nhrrob-secure-grid">
							<thead>
								<tr>
									<th>{ __( 'User', 'nhrrob-secure' ) }</th>
									<th>{ __( 'Role', 'nhrrob-secure' ) }</th>
									<th>
										{ __( 'Two-factor', 'nhrrob-secure' ) }
									</th>
									<th>
										{ __(
											'Last sign-in',
											'nhrrob-secure'
										) }
									</th>
									<th>
										{ __( 'Sessions', 'nhrrob-secure' ) }
									</th>
									<th />
								</tr>
							</thead>
							<tbody>
								{ data.items.map( ( user ) => (
									<tr key={ user.id }>
										<td>
											<div className="nhrrob-secure-who">
												<span className="nhrrob-secure-avatar">
													{ user.login
														.charAt( 0 )
														.toUpperCase() }
												</span>
												<div>
													{ user.login }{ ' ' }
													{ user.is_you && (
														<span className="nhrrob-secure-sub">
															{ __(
																'(you)',
																'nhrrob-secure'
															) }
														</span>
													) }
													<div className="nhrrob-secure-sub">
														{ user.email }
													</div>
												</div>
											</div>
										</td>
										<td>{ user.roles.join( ', ' ) }</td>
										<td>
											{ twofa(
												user,
												settings.twofa_enabled
											) }
											{ user.must_change && (
												<>
													{ ' ' }
													<Pill tone="warn">
														{ __(
															'New password due',
															'nhrrob-secure'
														) }
													</Pill>
												</>
											) }
										</td>
										<td>
											{ user.last_login
												? when( user.last_login )
												: '—' }
										</td>
										<td className="is-wrap">
											{ user.sessions.length
												? sprintf(
														/* translators: 1: number of sessions, 2: list of devices. */
														__(
															'%1$d · %2$s',
															'nhrrob-secure'
														),
														user.sessions.length,
														[
															...new Set(
																user.sessions.map(
																	( s ) =>
																		device(
																			s.ua
																		)
																)
															),
														].join( ', ' )
												  )
												: __(
														'None',
														'nhrrob-secure'
												  ) }
										</td>
										<td className="is-actions">
											{ user.can_edit &&
												user.sessions.length >
													( user.is_you ? 1 : 0 ) && (
													<Button
														small
														onClick={ () =>
															act(
																'/users/' +
																	user.id +
																	'/signout',
																user.is_you
																	? __(
																			'Your other sessions were signed out',
																			'nhrrob-secure'
																	  )
																	: sprintf(
																			/* translators: %s: username. */
																			__(
																				'%s was signed out',
																				'nhrrob-secure'
																			),
																			user.login
																	  )
															)
														}
													>
														{ user.is_you
															? __(
																	'Sign out others',
																	'nhrrob-secure'
															  )
															: __(
																	'Sign out',
																	'nhrrob-secure'
															  ) }
													</Button>
												) }
											{ user.can_edit &&
												! user.is_you &&
												! user.must_change && (
													<Button
														small
														onClick={ () =>
															act(
																'/users/' +
																	user.id +
																	'/force-password',
																sprintf(
																	/* translators: %s: username. */
																	__(
																		'%s must choose a new password',
																		'nhrrob-secure'
																	),
																	user.login
																)
															)
														}
													>
														{ __(
															'Require new password',
															'nhrrob-secure'
														) }
													</Button>
												) }
											{ user.can_edit &&
												! user.is_you &&
												user.twofa && (
													<Button
														small
														onClick={ () =>
															resetTwoFactor(
																user
															)
														}
													>
														{ __(
															'Reset two-factor',
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
				) }
				{ data && pages > 1 && (
					<div className="nhrrob-secure-toolbar is-foot">
						<span className="nhrrob-secure-sub">
							{ sprintf(
								/* translators: 1: current page, 2: number of pages, 3: number of users. */
								_n(
									'Page %1$d of %2$d · %3$d user',
									'Page %1$d of %2$d · %3$d users',
									data.total,
									'nhrrob-secure'
								),
								page,
								pages,
								data.total
							) }
						</span>
						<Button
							small
							disabled={ page <= 1 }
							onClick={ () => setPage( page - 1 ) }
						>
							{ __( 'Previous', 'nhrrob-secure' ) }
						</Button>
						<Button
							small
							disabled={ page >= pages }
							onClick={ () => setPage( page + 1 ) }
						>
							{ __( 'Next', 'nhrrob-secure' ) }
						</Button>
					</div>
				) }
			</Panel>

			<Panel title={ __( 'Passwords', 'nhrrob-secure' ) } icon="login">
				<Row
					label={ __( 'Passwords expire', 'nhrrob-secure' ) }
					help={ __(
						'For administrators and editors. When the time is up they are kept on their profile screen until they choose a new password. The clock starts when you switch this on.',
						'nhrrob-secure'
					) }
				>
					<select
						className="nhrrob-secure-select"
						aria-label={ __( 'Passwords expire', 'nhrrob-secure' ) }
						value={ settings.password_expiry_days }
						onChange={ ( e ) =>
							save( { password_expiry_days: e.target.value } )
						}
					>
						<option value="0">
							{ __( 'Never', 'nhrrob-secure' ) }
						</option>
						{ [ 30, 60, 90, 180, 365 ].map( ( days ) => (
							<option key={ days } value={ days }>
								{ sprintf(
									/* translators: %d: number of days. */
									__( 'After %d days', 'nhrrob-secure' ),
									days
								) }
							</option>
						) ) }
					</select>
				</Row>
				<Row
					label={ __(
						'Require a new password now',
						'nhrrob-secure'
					) }
					help={ __(
						'Use this after a suspected break-in. Each affected user is asked for a new password the next time they open the dashboard. Your own account is left alone.',
						'nhrrob-secure'
					) }
				>
					<select
						className="nhrrob-secure-select"
						aria-label={ __( 'Who', 'nhrrob-secure' ) }
						value={ scope }
						onChange={ ( e ) => setScope( e.target.value ) }
					>
						<option value="*">
							{ __( 'Everyone', 'nhrrob-secure' ) }
						</option>
						{ meta.roles.map( ( r ) => (
							<option key={ r.value } value={ r.value }>
								{ r.label }
							</option>
						) ) }
					</select>
					<Button variant="danger" onClick={ forceScope }>
						{ __( 'Require new passwords', 'nhrrob-secure' ) }
					</Button>
				</Row>
			</Panel>

			<Panel>
				<Row
					label={ __( 'Sign out idle users', 'nhrrob-secure' ) }
					help={ __(
						'Based on real page loads and saves. A tab left open in the background does not count as activity.',
						'nhrrob-secure'
					) }
					control={
						<Switch
							checked={ settings.idle_timeout > 0 }
							label={ __(
								'Sign out idle users',
								'nhrrob-secure'
							) }
							onChange={ ( v ) =>
								save( { idle_timeout: v ? 60 : 0 } )
							}
						/>
					}
				>
					{ settings.idle_timeout > 0 && (
						<Field label={ __( 'After', 'nhrrob-secure' ) }>
							<select
								className="nhrrob-secure-select"
								value={ settings.idle_timeout }
								onChange={ ( e ) =>
									save( { idle_timeout: e.target.value } )
								}
							>
								{ [ 15, 30, 60, 240, 720 ]
									.concat(
										[ 15, 30, 60, 240, 720 ].includes(
											settings.idle_timeout
										)
											? []
											: [ settings.idle_timeout ]
									)
									.map( ( minutes ) => (
										<option
											key={ minutes }
											value={ minutes }
										>
											{ minutes < 60
												? sprintf(
														/* translators: %d: minutes. */
														__(
															'%d minutes',
															'nhrrob-secure'
														),
														minutes
												  )
												: sprintf(
														/* translators: %d: hours. */
														_n(
															'%d hour',
															'%d hours',
															minutes / 60,
															'nhrrob-secure'
														),
														minutes / 60
												  ) }
										</option>
									) ) }
							</select>
						</Field>
					) }
				</Row>
			</Panel>
		</>
	);
}
