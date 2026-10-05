/**
 * Dashboard: the score, what to fix, and recent activity.
 */
import { useState, useEffect } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';

import api from '../api';
import {
	ScreenHeader,
	Panel,
	Pill,
	Button,
	Gauge,
	Icon,
	Note,
	Loading,
	Empty,
	ago,
	when,
} from '../components/ui';

const ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const TONE = { critical: 'bad', high: 'warn', medium: 'info', low: 'off' };

function severityLabel( severity ) {
	return {
		critical: __( 'Critical', 'nhrrob-secure' ),
		high: __( 'High', 'nhrrob-secure' ),
		medium: __( 'Medium', 'nhrrob-secure' ),
		low: __( 'Low', 'nhrrob-secure' ),
	}[ severity ];
}

function headline( score, failed ) {
	if ( ! failed ) {
		return __( 'Everything checks out', 'nhrrob-secure' );
	}
	const things = sprintf(
		/* translators: %d: number of items. */
		_n( '%d thing to fix', '%d things to fix', failed, 'nhrrob-secure' ),
		failed
	);
	if ( score >= 80 ) {
		/* translators: %s: "3 things to fix". */
		return sprintf( __( 'Good, with %s', 'nhrrob-secure' ), things );
	}
	if ( score >= 50 ) {
		/* translators: %s: "3 things to fix". */
		return sprintf( __( 'Fair, with %s', 'nhrrob-secure' ), things );
	}
	/* translators: %s: "3 things to fix". */
	return sprintf( __( 'At risk, with %s', 'nhrrob-secure' ), things );
}

export default function Dashboard( { boot, settings, save, navigate } ) {
	const [ data, setData ] = useState( null );
	const [ showPassed, setShowPassed ] = useState( false );

	const [ loadError, setLoadError ] = useState( null );

	useEffect( () => {
		api( '/dashboard' ).then( setData ).catch( setLoadError );
	}, [] );

	if ( ! data ) {
		return <Loading error={ loadError } />;
	}

	const failed = data.checks
		.filter( ( check ) => ! check.passed )
		.sort( ( a, b ) => ORDER[ a.severity ] - ORDER[ b.severity ] );
	const passed = data.checks.filter( ( check ) => check.passed );
	const stats = data.stats;
	const notices = data.notice ? data.notice.split( ',' ) : [];

	const fix = ( check ) => {
		if ( ! check.fix ) {
			return null;
		}
		if ( check.fix.section === 'updates' ) {
			return (
				<a
					className="nhrrob-secure-btn nhrrob-secure-btn--soft nhrrob-secure-btn--sm"
					href={ boot.updatesUrl }
				>
					{ check.fix.label }
				</a>
			);
		}
		const anchors = { files: 'files', admins_2fa: 'twofa' };
		return (
			<Button
				variant={ check.severity === 'critical' ? 'primary' : 'soft' }
				small
				onClick={ () =>
					navigate( check.fix.section, anchors[ check.id ] )
				}
			>
				{ check.fix.label }
			</Button>
		);
	};

	return (
		<>
			<ScreenHeader
				title={ __( 'Dashboard', 'nhrrob-secure' ) }
				lede={ __(
					'How your site stands right now, and what to fix first.',
					'nhrrob-secure'
				) }
			/>

			{ notices.length > 0 && (
				<Note>
					<strong>
						{ __( 'What changed in 2.0', 'nhrrob-secure' ) }
					</strong>
					{ notices.includes( 'filter' ) && (
						<p>
							{ __(
								'The old "advanced firewall" could block ordinary visitors, so it has been replaced by a smaller request filter. It is now in log-only mode: review what it would have blocked under Firewall, then switch it to Block.',
								'nhrrob-secure'
							) }
						</p>
					) }
					{ notices.includes( 'country' ) && (
						<p>
							{ __(
								'Country rules now apply to the sign-in page only and use the country reported by Cloudflare. Visitors are no longer looked up with an outside service.',
								'nhrrob-secure'
							) }
						</p>
					) }
					<Button
						small
						onClick={ async () => {
							if ( await save( { upgrade_notice: '' } ) ) {
								setData( { ...data, notice: '' } );
							}
						} }
					>
						{ __( 'Got it', 'nhrrob-secure' ) }
					</Button>
				</Note>
			) }

			<Panel>
				<div className="nhrrob-secure-health">
					<Gauge score={ data.score } />
					<div className="nhrrob-secure-health__copy">
						<h3>{ headline( data.score, failed.length ) }</h3>
						<p>
							{ sprintf(
								/* translators: %d: number of checks. */
								__(
									'The score comes from %d checks of your site as it is today, weighted by how serious each one is.',
									'nhrrob-secure'
								),
								data.checks.length
							) }
						</p>
						<div className="nhrrob-secure-stats">
							<span>
								<b>{ passed.length }</b>{ ' ' }
								{ __( 'checks passed', 'nhrrob-secure' ) }
							</span>
							<span>
								<b>{ stats.lockouts }</b>{ ' ' }
								{ __( 'lockouts in 24 h', 'nhrrob-secure' ) }
							</span>
							<span>
								<b>
									{ sprintf(
										/* translators: 1: administrators with two-factor, 2: all administrators. */
										__( '%1$d of %2$d', 'nhrrob-secure' ),
										stats.admins_2fa,
										stats.admins
									) }
								</b>{ ' ' }
								{ __(
									'admins use two-factor',
									'nhrrob-secure'
								) }
							</span>
							<span>
								{ __(
									'Last vulnerability check',
									'nhrrob-secure'
								) }{ ' ' }
								<b>{ ago( stats.scan_checked ) }</b>
							</span>
						</div>
					</div>
				</div>
			</Panel>

			<div className="nhrrob-secure-cards">
				<div className="nhrrob-secure-card">
					<span className="nhrrob-secure-card__label">
						<Icon name="login" size={ 16 } />
						{ __( 'Login protection', 'nhrrob-secure' ) }
					</span>
					<span className="nhrrob-secure-card__metric">
						{ settings.limit_login
							? stats.locked_now
							: __( 'Off', 'nhrrob-secure' ) }
					</span>
					<span className="nhrrob-secure-card__sub">
						{ __( 'addresses locked out now', 'nhrrob-secure' ) }
					</span>
					<Button
						variant="soft"
						small
						onClick={ () => navigate( 'login', 'lockouts' ) }
					>
						{ __( 'View lockouts', 'nhrrob-secure' ) }
					</Button>
				</div>
				<div className="nhrrob-secure-card">
					<span className="nhrrob-secure-card__label">
						<Icon name="users" size={ 16 } />
						{ __( 'Two-factor', 'nhrrob-secure' ) }
					</span>
					<span className="nhrrob-secure-card__metric">
						{ sprintf(
							/* translators: 1: administrators with two-factor, 2: all administrators. */
							__( '%1$d of %2$d', 'nhrrob-secure' ),
							stats.admins_2fa,
							stats.admins
						) }
					</span>
					<span className="nhrrob-secure-card__sub">
						{ __( 'administrators enrolled', 'nhrrob-secure' ) }
					</span>
					<Button
						variant="soft"
						small
						onClick={ () => navigate( 'users' ) }
					>
						{ __( 'See who', 'nhrrob-secure' ) }
					</Button>
				</div>
				<div className="nhrrob-secure-card">
					<span className="nhrrob-secure-card__label">
						<Icon name="scanner" size={ 16 } />
						{ __( 'Vulnerabilities', 'nhrrob-secure' ) }
					</span>
					<span className="nhrrob-secure-card__metric">
						{ stats.scan_checked ? stats.vulnerabilities : '—' }
					</span>
					<span className="nhrrob-secure-card__sub">
						{ stats.scan_checked
							? sprintf(
									/* translators: %d: number of plugins, themes and WordPress itself. */
									__(
										'in %d installed items',
										'nhrrob-secure'
									),
									stats.software
							  )
							: __( 'not checked yet', 'nhrrob-secure' ) }
					</span>
					<Button
						variant="soft"
						small
						onClick={ () => navigate( 'scanner' ) }
					>
						{ __( 'Open scanner', 'nhrrob-secure' ) }
					</Button>
				</div>
				<div className="nhrrob-secure-card">
					<span className="nhrrob-secure-card__label">
						<Icon name="firewall" size={ 16 } />
						{ __( 'Refused requests', 'nhrrob-secure' ) }
					</span>
					<span className="nhrrob-secure-card__metric">
						{ stats.blocked }
					</span>
					<span className="nhrrob-secure-card__sub">
						{ __( 'in the last 7 days', 'nhrrob-secure' ) }
					</span>
					<Button
						variant="soft"
						small
						onClick={ () => navigate( 'firewall' ) }
					>
						{ __( 'Open firewall', 'nhrrob-secure' ) }
					</Button>
				</div>
			</div>

			<Panel
				title={ __( 'To fix', 'nhrrob-secure' ) }
				icon="alert"
				flush
				meta={ sprintf(
					/* translators: %d: number of items. */
					_n( '%d item', '%d items', failed.length, 'nhrrob-secure' ),
					failed.length
				) }
			>
				<ul className="nhrrob-secure-issues">
					{ failed.map( ( check ) => (
						<li
							key={ check.id }
							className={
								'nhrrob-secure-issue is-' +
								TONE[ check.severity ]
							}
						>
							<div className="nhrrob-secure-issue__main">
								<b>{ check.label }</b>
								{ check.detail && <div>{ check.detail }</div> }
							</div>
							<Pill tone={ TONE[ check.severity ] }>
								{ severityLabel( check.severity ) }
							</Pill>
							{ fix( check ) }
						</li>
					) ) }
					<li className="nhrrob-secure-issue is-ok">
						<div className="nhrrob-secure-issue__main">
							<b>
								{ sprintf(
									/* translators: %d: number of checks. */
									_n(
										'%d check passed.',
										'%d checks passed.',
										passed.length,
										'nhrrob-secure'
									),
									passed.length
								) }
							</b>
							{ showPassed && (
								<ul className="nhrrob-secure-passed">
									{ passed.map( ( check ) => (
										<li key={ check.id }>
											<Icon name="check" size={ 14 } />
											{ check.label }
										</li>
									) ) }
								</ul>
							) }
						</div>
						<Button
							small
							onClick={ () => setShowPassed( ! showPassed ) }
						>
							{ showPassed
								? __( 'Hide', 'nhrrob-secure' )
								: __( 'Show all', 'nhrrob-secure' ) }
						</Button>
					</li>
				</ul>
			</Panel>

			<Panel
				title={ __( 'Recent activity', 'nhrrob-secure' ) }
				icon="activity"
				flush
				actions={
					<Button small onClick={ () => navigate( 'activity' ) }>
						{ __( 'View all', 'nhrrob-secure' ) }
					</Button>
				}
			>
				{ data.activity.length ? (
					<ul className="nhrrob-secure-feed">
						{ data.activity.map( ( item, index ) => (
							<li key={ index }>
								<time>{ when( item.time ) }</time>
								<span>
									<b>{ item.who }</b> · { item.text }
								</span>
							</li>
						) ) }
					</ul>
				) : (
					<Empty>
						{ __( 'Nothing recorded yet.', 'nhrrob-secure' ) }
					</Empty>
				) }
			</Panel>
		</>
	);
}
