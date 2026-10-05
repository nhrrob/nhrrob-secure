/**
 * Firewall: address rules, the request filter, country and user-agent rules.
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
	Seg,
	TagList,
	Note,
	Loading,
	Empty,
	when,
} from '../components/ui';
import { useToast } from '../components/ToastProvider';

const CODES =
	'AD AE AF AG AI AL AM AO AR AT AU AZ BA BB BD BE BF BG BH BI BJ BM BN BO BR BS BT BW BY BZ CA CD CF CG CH CI CL CM CN CO CR CU CV CY CZ DE DJ DK DM DO DZ EC EE EG ER ES ET FI FJ FR GA GB GD GE GH GI GL GM GN GQ GR GT GW GY HK HN HR HT HU ID IE IL IN IQ IR IS IT JM JO JP KE KG KH KM KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MG MK ML MM MN MO MR MT MU MV MW MX MY MZ NA NE NG NI NL NO NP NZ OM PA PE PG PH PK PL PR PS PT PY QA RO RS RU RW SA SB SC SD SE SG SI SK SL SM SN SO SR SS SV SY SZ TD TG TH TJ TL TM TN TO TR TT TW TZ UA UG US UY UZ VA VC VE VN VU WS YE ZA ZM ZW'.split(
		' '
	);

function countryName( code, locale ) {
	try {
		return (
			new Intl.DisplayNames( [ locale || 'en' ], { type: 'region' } ).of(
				code
			) || code
		);
	} catch ( e ) {
		return code;
	}
}

export default function Firewall( { boot, settings, meta, save } ) {
	const toast = useToast();
	const [ data, setData ] = useState( null );
	const [ range, setRange ] = useState( '' );
	const [ type, setType ] = useState( 'block' );
	const [ note, setNote ] = useState( '' );
	const [ country, setCountry ] = useState( '' );

	const [ failed, setFailed ] = useState( null );

	useEffect( () => {
		api( '/firewall' ).then( setData ).catch( setFailed );
	}, [] );

	if ( ! data ) {
		return <Loading error={ failed } />;
	}

	const call = async ( path, method, body, message ) => {
		try {
			const res = await api( path, method, body );
			if ( res.rules ) {
				setData( res );
			}
			toast( message );
			return res;
		} catch ( e ) {
			toast( e.message, 'error' );
			return null;
		}
	};

	const addRule = async () => {
		if (
			await call(
				'/firewall/rules',
				'POST',
				{ range, type, note },
				__( 'Rule added', 'nhrrob-secure' )
			)
		) {
			setRange( '' );
			setNote( '' );
		}
	};

	const mode = settings.request_filter;
	const days = data.since
		? Math.max( 1, Math.ceil( ( Date.now() / 1000 - data.since ) / 86400 ) )
		: 0;
	const allowed = settings.filter_allowed;
	const matches = data.matches.filter(
		( m ) => ! allowed.includes( m.rule + '|' + m.path )
	);

	return (
		<>
			<ScreenHeader
				title={ __( 'Firewall', 'nhrrob-secure' ) }
				lede={ __(
					'Rules that decide who may reach the site at all. Allowed addresses skip every rule on this page and are never locked out.',
					'nhrrob-secure'
				) }
			/>

			<Panel
				title={ __( 'Address rules', 'nhrrob-secure' ) }
				icon="firewall"
				flush
				meta={ sprintf(
					/* translators: %s: IP address. */
					__( 'Your address: %s', 'nhrrob-secure' ),
					meta.your_ip
				) }
			>
				<div className="nhrrob-secure-toolbar">
					<input
						type="text"
						className="nhrrob-secure-input"
						placeholder={ __(
							'Address or range, e.g. 203.0.113.0/24 or 2001:db8::/48',
							'nhrrob-secure'
						) }
						aria-label={ __( 'Address or range', 'nhrrob-secure' ) }
						value={ range }
						onChange={ ( e ) => setRange( e.target.value ) }
					/>
					<select
						className="nhrrob-secure-select"
						aria-label={ __( 'Rule', 'nhrrob-secure' ) }
						value={ type }
						onChange={ ( e ) => setType( e.target.value ) }
					>
						<option value="block">
							{ __( 'Block', 'nhrrob-secure' ) }
						</option>
						<option value="allow">
							{ __( 'Allow', 'nhrrob-secure' ) }
						</option>
					</select>
					<input
						type="text"
						className="nhrrob-secure-input is-short"
						placeholder={ __( 'Note (optional)', 'nhrrob-secure' ) }
						aria-label={ __( 'Note', 'nhrrob-secure' ) }
						value={ note }
						onChange={ ( e ) => setNote( e.target.value ) }
					/>
					<Button
						variant="primary"
						disabled={ ! range.trim() }
						onClick={ addRule }
					>
						{ __( 'Add rule', 'nhrrob-secure' ) }
					</Button>
				</div>
				{ data.rules.length ? (
					<div className="nhrrob-secure-scroll">
						<table className="nhrrob-secure-grid">
							<thead>
								<tr>
									<th>
										{ __(
											'Address or range',
											'nhrrob-secure'
										) }
									</th>
									<th>{ __( 'Rule', 'nhrrob-secure' ) }</th>
									<th>{ __( 'Note', 'nhrrob-secure' ) }</th>
									<th>{ __( 'Added', 'nhrrob-secure' ) }</th>
									<th />
								</tr>
							</thead>
							<tbody>
								{ data.rules.map( ( rule ) => (
									<tr key={ rule.range }>
										<td className="is-mono">
											{ rule.range }
										</td>
										<td>
											<Pill
												tone={
													rule.type === 'allow'
														? 'ok'
														: 'bad'
												}
											>
												{ rule.type === 'allow'
													? __(
															'Allow',
															'nhrrob-secure'
													  )
													: __(
															'Block',
															'nhrrob-secure'
													  ) }
											</Pill>
										</td>
										<td className="is-wrap">
											{ rule.note }
										</td>
										<td>{ when( rule.added ) }</td>
										<td className="is-actions">
											<Button
												small
												onClick={ () =>
													call(
														'/firewall/rules',
														'DELETE',
														{ range: rule.range },
														__(
															'Rule removed',
															'nhrrob-secure'
														)
													)
												}
											>
												{ __(
													'Remove',
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
						{ __(
							'No address rules yet. Add your office or home address as “Allow” so it can never be locked out.',
							'nhrrob-secure'
						) }
					</Empty>
				) }
			</Panel>

			<Panel
				title={ __( 'Request filter', 'nhrrob-secure' ) }
				icon="filter"
				flush
				actions={
					<Seg
						label={ __( 'Request filter mode', 'nhrrob-secure' ) }
						value={ mode }
						onChange={ ( v ) => save( { request_filter: v } ) }
						options={ [
							{
								value: 'off',
								label: __( 'Off', 'nhrrob-secure' ),
							},
							{
								value: 'log',
								label: __( 'Log only', 'nhrrob-secure' ),
							},
							{
								value: 'block',
								label: __( 'Block', 'nhrrob-secure' ),
							},
						] }
					/>
				}
			>
				<div className="nhrrob-secure-pad">
					<p className="nhrrob-secure-muted">
						{ __(
							'Stops requests that look like probing: path traversal, hunts for config and backup files, and SQL or script fragments in the address. It checks the address of visitors who are not signed in and never reads form or comment text. It runs inside WordPress; it is not a network firewall.',
							'nhrrob-secure'
						) }
					</p>
					{ mode === 'log' && (
						<Note>
							<strong>
								{ sprintf(
									/* translators: %d: number of days. */
									__( 'Log only, day %d.', 'nhrrob-secure' ),
									days
								) }
							</strong>{ ' ' }
							{ sprintf(
								/* translators: %d: number of requests. */
								_n(
									'%d request would have been refused.',
									'%d requests would have been refused.',
									matches.length,
									'nhrrob-secure'
								),
								matches.length
							) }{ ' ' }
							{ __(
								'Give it about a week, allow anything below that is yours, then switch to Block.',
								'nhrrob-secure'
							) }
						</Note>
					) }
				</div>
				{ mode !== 'off' && matches.length > 0 && (
					<div className="nhrrob-secure-scroll">
						<table className="nhrrob-secure-grid">
							<thead>
								<tr>
									<th>{ __( 'When', 'nhrrob-secure' ) }</th>
									<th>
										{ __( 'Request', 'nhrrob-secure' ) }
									</th>
									<th>
										{ __( 'Matched', 'nhrrob-secure' ) }
									</th>
									<th>{ __( 'From', 'nhrrob-secure' ) }</th>
									<th />
								</tr>
							</thead>
							<tbody>
								{ matches.map( ( m, index ) => (
									<tr key={ index }>
										<td>{ when( m.time ) }</td>
										<td className="is-mono is-wrap">
											{ m.request }
										</td>
										<td>
											{ m.label }{ ' ' }
											{ m.blocked && (
												<Pill tone="bad">
													{ __(
														'Refused',
														'nhrrob-secure'
													) }
												</Pill>
											) }
										</td>
										<td className="is-mono">{ m.ip }</td>
										<td className="is-actions">
											<Button
												small
												onClick={ () =>
													save(
														{
															filter_allowed: [
																...allowed,
																m.rule +
																	'|' +
																	m.path,
															],
														},
														__(
															'Allowed. That address will not be matched again.',
															'nhrrob-secure'
														)
													)
												}
											>
												{ __(
													'Allow this',
													'nhrrob-secure'
												) }
											</Button>
										</td>
									</tr>
								) ) }
							</tbody>
						</table>
					</div>
				) }
				{ mode !== 'off' && ! matches.length && (
					<Empty>
						{ __( 'Nothing has matched yet.', 'nhrrob-secure' ) }
					</Empty>
				) }
				<div className="nhrrob-secure-pad">
					<Row
						label={ __(
							'Also check submitted forms',
							'nhrrob-secure'
						) }
						help={ __(
							'Looks at what signed-out visitors submit, for path traversal, PHP stream wrappers and PHP code only. SQL and script patterns are not applied to forms, because normal writing can contain them.',
							'nhrrob-secure'
						) }
						risk={ __(
							'comments or forms where visitors post PHP code samples.',
							'nhrrob-secure'
						) }
						control={
							<Switch
								checked={ settings.filter_forms }
								disabled={ mode === 'off' }
								label={ __(
									'Also check submitted forms',
									'nhrrob-secure'
								) }
								onChange={ ( v ) =>
									save( { filter_forms: v } )
								}
							/>
						}
					/>
					<Row
						label={ __(
							'Lock out addresses that hunt for files',
							'nhrrob-secure'
						) }
						help={ __(
							'Ten requests in ten minutes for files that do not exist (.php, .env, backups, archives) lock the address out of the whole site for an hour, longer each time. Missing pages and images do not count, so broken links and search engines are not affected. Locked addresses appear under Login, where you can unlock them.',
							'nhrrob-secure'
						) }
						control={
							<Switch
								checked={ settings.probe_lockout }
								label={ __(
									'Lock out addresses that hunt for files',
									'nhrrob-secure'
								) }
								onChange={ ( v ) =>
									save( { probe_lockout: v } )
								}
							/>
						}
					/>
				</div>
			</Panel>

			<Panel title={ __( 'Countries', 'nhrrob-secure' ) } icon="globe">
				<Row
					label={ __(
						'Limit where people can sign in from',
						'nhrrob-secure'
					) }
					help={ __(
						'By default only the sign-in page is affected and visitors everywhere still see your site. The country comes from Cloudflare, so this works when your site is behind Cloudflare.',
						'nhrrob-secure'
					) }
					control={
						<Switch
							checked={ settings.country_enabled }
							label={ __( 'Country rule', 'nhrrob-secure' ) }
							onChange={ ( v ) => save( { country_enabled: v } ) }
						/>
					}
				>
					<Seg
						label={ __( 'Where it applies', 'nhrrob-secure' ) }
						value={ settings.country_scope }
						onChange={ ( v ) => save( { country_scope: v } ) }
						options={ [
							{
								value: 'login',
								label: __( 'Sign-in page', 'nhrrob-secure' ),
							},
							{
								value: 'site',
								label: __( 'Whole site', 'nhrrob-secure' ),
							},
						] }
					/>
					<Seg
						label={ __( 'Country rule type', 'nhrrob-secure' ) }
						value={ settings.country_mode }
						onChange={ ( v ) => save( { country_mode: v } ) }
						options={ [
							{
								value: 'block',
								label: __( 'Block these', 'nhrrob-secure' ),
							},
							{
								value: 'allow',
								label: __(
									'Allow only these',
									'nhrrob-secure'
								),
							},
						] }
					/>
					<select
						className="nhrrob-secure-select"
						aria-label={ __( 'Add a country', 'nhrrob-secure' ) }
						value={ country }
						onChange={ ( e ) => {
							const code = e.target.value;
							setCountry( '' );
							if (
								code &&
								! settings.country_list.includes( code )
							) {
								save( {
									country_list: [
										...settings.country_list,
										code,
									],
								} );
							}
						} }
					>
						<option value="">
							{ __( '+ Add country', 'nhrrob-secure' ) }
						</option>
						{ CODES.map( ( code ) => [
							code,
							countryName( code, boot.locale ),
						] )
							.sort( ( a, b ) => a[ 1 ].localeCompare( b[ 1 ] ) )
							.map( ( [ code, name ] ) => (
								<option key={ code } value={ code }>
									{ name }
								</option>
							) ) }
					</select>
				</Row>
				{ settings.country_list.length > 0 && (
					<div className="nhrrob-secure-chips nhrrob-secure-gap">
						{ settings.country_list.map( ( code ) => (
							<button
								key={ code }
								type="button"
								className="nhrrob-secure-chip is-on"
								title={ __( 'Remove', 'nhrrob-secure' ) }
								onClick={ () =>
									save( {
										country_list:
											settings.country_list.filter(
												( c ) => c !== code
											),
									} )
								}
							>
								{ countryName( code, boot.locale ) } ×
							</button>
						) ) }
					</div>
				) }
				{ settings.country_enabled && ! meta.cloudflare && (
					<Note tone="warn">
						{ __(
							'This request did not come through Cloudflare, so no country is known and the rule is not applied. Nobody is refused by guesswork.',
							'nhrrob-secure'
						) }
					</Note>
				) }
				{ meta.country && (
					<Note>
						{ sprintf(
							/* translators: %s: country name. */
							__(
								'Cloudflare reports you are in %s.',
								'nhrrob-secure'
							),
							countryName( meta.country, boot.locale )
						) }
					</Note>
				) }
			</Panel>

			<Panel
				title={ __( 'Blocked user agents', 'nhrrob-secure' ) }
				icon="bot"
			>
				<p className="nhrrob-secure-muted">
					{ __(
						'A request is refused when its browser signature contains one of these. Useful for scanners that announce themselves, such as sqlmap, nikto or masscan.',
						'nhrrob-secure'
					) }
				</p>
				<TagList
					values={ settings.blocked_uas }
					placeholder={ __( 'e.g. sqlmap', 'nhrrob-secure' ) }
					onChange={ ( list ) => save( { blocked_uas: list } ) }
				/>
			</Panel>
		</>
	);
}
