/**
 * A printable security report: the score, what to fix, what passed, the
 * numbers and the activity that matters. Printed (or saved as a PDF) with the
 * browser's own print dialog.
 */
import { useState, useEffect } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';

import api from '../api';
import { Button, when } from './ui';

export default function Report( { data, onClose } ) {
	const [ events, setEvents ] = useState( [] );

	useEffect( () => {
		// Warnings and critical events only; routine rows would bury them.
		Promise.all( [
			api( '/activity?severity=3' ),
			api( '/activity?severity=2' ),
		] )
			.then( ( [ critical, warnings ] ) =>
				setEvents(
					critical.items
						.concat( warnings.items )
						.sort( ( a, b ) => b.time - a.time )
				)
			)
			.catch( () => setEvents( [] ) );
	}, [] );

	const failed = data.checks.filter( ( check ) => ! check.passed );
	const passed = data.checks.filter( ( check ) => check.passed );
	const stats = data.stats;

	return (
		<div className="nhrrob-secure-report">
			<div className="nhrrob-secure-report__bar">
				<Button onClick={ onClose }>
					{ __( 'Back', 'nhrrob-secure' ) }
				</Button>
				<Button variant="primary" onClick={ () => window.print() }>
					{ __( 'Print or save as PDF', 'nhrrob-secure' ) }
				</Button>
			</div>

			<h1>{ __( 'Security report', 'nhrrob-secure' ) }</h1>
			<p className="nhrrob-secure-sub">
				{ data.site.name } · { data.site.url } ·{ ' ' }
				{ when( Date.now() / 1000 ) }
			</p>

			<h2>
				{ sprintf(
					/* translators: %d: score out of 100. */
					__( 'Score: %d out of 100', 'nhrrob-secure' ),
					data.score
				) }
			</h2>
			<ul>
				<li>
					{ sprintf(
						/* translators: 1: checks passed, 2: all checks. */
						__( '%1$d of %2$d checks passed', 'nhrrob-secure' ),
						passed.length,
						data.checks.length
					) }
				</li>
				<li>
					{ sprintf(
						/* translators: 1: administrators with two-factor, 2: all administrators. */
						__(
							'%1$d of %2$d administrators use two-factor',
							'nhrrob-secure'
						),
						stats.admins_2fa,
						stats.admins
					) }
				</li>
				<li>
					{ sprintf(
						/* translators: 1: vulnerabilities, 2: installed items. */
						__(
							'%1$d known vulnerabilities in %2$d installed items',
							'nhrrob-secure'
						),
						stats.vulnerabilities,
						stats.software
					) }
				</li>
				<li>
					{ sprintf(
						/* translators: %d: number of addresses. */
						__(
							'%d addresses locked out in the last 24 hours',
							'nhrrob-secure'
						),
						stats.lockouts
					) }
				</li>
				<li>
					{ sprintf(
						/* translators: %d: number of requests. */
						__(
							'%d requests refused in the last 7 days',
							'nhrrob-secure'
						),
						stats.blocked
					) }
				</li>
			</ul>

			<h2>{ __( 'To fix', 'nhrrob-secure' ) }</h2>
			{ failed.length ? (
				<ul>
					{ failed.map( ( check ) => (
						<li key={ check.id }>
							<b>{ check.label }</b>
							{ check.detail && <div>{ check.detail }</div> }
						</li>
					) ) }
				</ul>
			) : (
				<p>{ __( 'Nothing needs fixing.', 'nhrrob-secure' ) }</p>
			) }

			<h2>{ __( 'Passed', 'nhrrob-secure' ) }</h2>
			<ul>
				{ passed.map( ( check ) => (
					<li key={ check.id }>{ check.label }</li>
				) ) }
			</ul>

			<h2>{ __( 'Recent warnings and alerts', 'nhrrob-secure' ) }</h2>
			{ events.length ? (
				<table>
					<tbody>
						{ events.map( ( item, index ) => (
							<tr key={ index }>
								<td>{ when( item.time ) }</td>
								<td>{ item.who }</td>
								<td>{ item.text }</td>
							</tr>
						) ) }
					</tbody>
				</table>
			) : (
				<p>{ __( 'Nothing recorded.', 'nhrrob-secure' ) }</p>
			) }
		</div>
	);
}
