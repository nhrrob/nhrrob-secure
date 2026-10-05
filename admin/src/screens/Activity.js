/**
 * Activity: the log, with search, filters and CSV export.
 */
import { useState, useEffect } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';

import api, { query } from '../api';
import {
	ScreenHeader,
	Panel,
	Pill,
	Button,
	Loading,
	Empty,
	when,
} from '../components/ui';
import { useToast } from '../components/ToastProvider';

const TONES = { 1: 'off', 2: 'warn', 3: 'bad' };

export default function Activity( { settings } ) {
	const toast = useToast();
	const [ data, setData ] = useState( null );
	const [ search, setSearch ] = useState( '' );
	const [ type, setType ] = useState( '' );
	const [ severity, setSeverity ] = useState( '' );
	const [ page, setPage ] = useState( 1 );

	useEffect( () => {
		const timer = setTimeout(
			() => {
				api(
					'/activity' + query( { search, type, severity, page } )
				).then( setData );
			},
			search ? 300 : 0
		);
		return () => clearTimeout( timer );
	}, [ search, type, severity, page ] );

	const labels = {
		1: __( 'Info', 'nhrrob-secure' ),
		2: __( 'Warning', 'nhrrob-secure' ),
		3: __( 'Critical', 'nhrrob-secure' ),
	};
	const types = [
		[ 'login', __( 'Sign-in', 'nhrrob-secure' ) ],
		[ 'user', __( 'Users', 'nhrrob-secure' ) ],
		[ 'plugin', __( 'Plugins', 'nhrrob-secure' ) ],
		[ 'theme', __( 'Themes', 'nhrrob-secure' ) ],
		[ 'core', __( 'WordPress', 'nhrrob-secure' ) ],
		[ 'option', __( 'Site settings', 'nhrrob-secure' ) ],
		[ 'setting', __( 'Secure settings', 'nhrrob-secure' ) ],
		[ 'firewall', __( 'Firewall', 'nhrrob-secure' ) ],
		[ 'scan', __( 'Scanner', 'nhrrob-secure' ) ],
	];

	const exportCsv = async () => {
		try {
			const res = await api(
				'/activity/export' + query( { search, type, severity } )
			);
			const url = URL.createObjectURL(
				new Blob( [ res.csv ], { type: 'text/csv' } )
			);
			const link = document.createElement( 'a' );
			link.href = url;
			link.download = 'secure-activity.csv';
			link.click();
			URL.revokeObjectURL( url );
		} catch ( e ) {
			toast( e.message, 'error' );
		}
	};

	const pages = data ? Math.max( 1, Math.ceil( data.total / 20 ) ) : 1;
	const reset = ( setter ) => ( e ) => {
		setPage( 1 );
		setter( e.target.value );
	};

	return (
		<>
			<ScreenHeader
				title={ __( 'Activity', 'nhrrob-secure' ) }
				lede={ sprintf(
					/* translators: %d: number of days. */
					__(
						'What happened on your site and who did it. Events are kept for %d days, up to the newest 1,000.',
						'nhrrob-secure'
					),
					settings.retention_days
				) }
			/>

			<Panel flush>
				<div className="nhrrob-secure-toolbar">
					<input
						type="search"
						className="nhrrob-secure-input"
						placeholder={ __(
							'Search user, address or event',
							'nhrrob-secure'
						) }
						aria-label={ __( 'Search', 'nhrrob-secure' ) }
						value={ search }
						onChange={ reset( setSearch ) }
					/>
					<select
						className="nhrrob-secure-select"
						aria-label={ __( 'Type', 'nhrrob-secure' ) }
						value={ type }
						onChange={ reset( setType ) }
					>
						<option value="">
							{ __( 'All types', 'nhrrob-secure' ) }
						</option>
						{ types.map( ( [ value, label ] ) => (
							<option key={ value } value={ value }>
								{ label }
							</option>
						) ) }
					</select>
					<select
						className="nhrrob-secure-select"
						aria-label={ __( 'Importance', 'nhrrob-secure' ) }
						value={ severity }
						onChange={ reset( setSeverity ) }
					>
						<option value="">
							{ __( 'Any importance', 'nhrrob-secure' ) }
						</option>
						<option value="3">{ labels[ 3 ] }</option>
						<option value="2">{ labels[ 2 ] }</option>
						<option value="1">{ labels[ 1 ] }</option>
					</select>
					<Button onClick={ exportCsv }>
						{ __( 'Export CSV', 'nhrrob-secure' ) }
					</Button>
				</div>

				{ ! data && <Loading /> }
				{ data && ! data.items.length && (
					<Empty>{ __( 'No events match.', 'nhrrob-secure' ) }</Empty>
				) }
				{ data && data.items.length > 0 && (
					<div className="nhrrob-secure-scroll">
						<table className="nhrrob-secure-grid">
							<thead>
								<tr>
									<th>{ __( 'When', 'nhrrob-secure' ) }</th>
									<th>{ __( 'Who', 'nhrrob-secure' ) }</th>
									<th>
										{ __(
											'What happened',
											'nhrrob-secure'
										) }
									</th>
									<th>{ __( 'From', 'nhrrob-secure' ) }</th>
									<th>
										{ __( 'Importance', 'nhrrob-secure' ) }
									</th>
								</tr>
							</thead>
							<tbody>
								{ data.items.map( ( item, index ) => (
									<tr key={ index }>
										<td>{ when( item.time ) }</td>
										<td>{ item.who }</td>
										<td className="is-wrap">
											{ item.text }
										</td>
										<td className="is-mono">{ item.ip }</td>
										<td>
											<Pill
												tone={ TONES[ item.severity ] }
											>
												{ labels[ item.severity ] }
											</Pill>
										</td>
									</tr>
								) ) }
							</tbody>
						</table>
					</div>
				) }
				{ data && data.total > 0 && (
					<div className="nhrrob-secure-toolbar is-foot">
						<span className="nhrrob-secure-sub">
							{ sprintf(
								/* translators: 1: first row, 2: last row, 3: total rows. */
								__(
									'%1$d–%2$d of %3$d events',
									'nhrrob-secure'
								),
								( page - 1 ) * 20 + 1,
								Math.min( page * 20, data.total ),
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
		</>
	);
}
