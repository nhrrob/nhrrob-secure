/**
 * Scanner: known vulnerabilities, file integrity and suspicious code.
 * The long checks are stepped from here, a few seconds per request.
 */
import { useState, useEffect, useRef } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';

import api from '../api';
import {
	ScreenHeader,
	Panel,
	Pill,
	Button,
	Row,
	Note,
	Loading,
	Empty,
	ago,
} from '../components/ui';
import { useToast } from '../components/ToastProvider';
import { useConfirm } from '../components/ConfirmProvider';

function score( value ) {
	let tone = 'info';
	let label = __( 'Medium', 'nhrrob-secure' );
	if ( value >= 9 ) {
		tone = 'bad';
		label = __( 'Critical', 'nhrrob-secure' );
	} else if ( value >= 7 ) {
		tone = 'warn';
		label = __( 'High', 'nhrrob-secure' );
	} else if ( ! value ) {
		tone = 'off';
		label = __( 'Unrated', 'nhrrob-secure' );
	}
	return (
		<Pill tone={ tone }>
			{ label }
			{ value ? ' ' + value.toFixed( 1 ) : '' }
		</Pill>
	);
}

function FileList( { title, files, action } ) {
	if ( ! files || ! files.length ) {
		return null;
	}
	const shown = action ? files : files.slice( 0, 6 );
	return (
		<div className="nhrrob-secure-filelist">
			<b>{ title }</b>
			<ul>
				{ shown.map( ( file ) => (
					<li key={ file }>
						<code>{ file }</code>
						{ action && action( file ) }
					</li>
				) ) }
				{ files.length > shown.length && (
					<li>
						{ sprintf(
							/* translators: %d: number of files not shown. */
							__( 'and %d more', 'nhrrob-secure' ),
							files.length - shown.length
						) }
					</li>
				) }
			</ul>
		</div>
	);
}

export default function Scanner( { boot, settings, save } ) {
	const toast = useToast();
	const confirm = useConfirm();
	const [ data, setData ] = useState( null );
	const [ busy, setBusy ] = useState( {} );
	const [ preview, setPreview ] = useState( null );
	const alive = useRef( true );

	useEffect( () => {
		api( '/scanner' ).then( setData );
		return () => {
			alive.current = false;
		};
	}, [] );

	const setProgress = ( key, value ) =>
		setBusy( ( current ) => ( { ...current, [ key ]: value } ) );

	/**
	 * Drive a batched check to the end, one request per batch.
	 *
	 * @param {string}  key     'vulnerabilities' or 'plugins'.
	 * @param {boolean} restart Start a new run.
	 */
	const run = async ( key, restart = true ) => {
		setProgress( key, { done: 0, total: 0 } );
		try {
			let res = await api( '/scanner/' + key, 'POST', { restart } );
			while ( res.running && alive.current ) {
				setProgress( key, res );
				res = await api( '/scanner/' + key, 'POST', {} );
			}
			if ( res.data && alive.current ) {
				setData( res.data );
			}
		} catch ( e ) {
			toast( e.message, 'error' );
		}
		setProgress( key, null );
	};

	const runCode = async ( restart ) => {
		setProgress( 'code', true );
		try {
			let code = await api( '/scanner/code', 'POST', { restart } );
			while ( code.status === 'running' && alive.current ) {
				// eslint-disable-next-line no-loop-func -- the latest state is what must be stored.
				setData( ( current ) => ( { ...current, code } ) );
				code = await api( '/scanner/code', 'POST', {} );
			}
			if ( alive.current ) {
				setData( ( current ) => ( { ...current, code } ) );
			}
		} catch ( e ) {
			toast( e.message, 'error' );
		}
		setProgress( 'code', null );
	};

	const simple = async ( key, path, body, message ) => {
		setProgress( key, true );
		try {
			const res = await api( path, 'POST', body );
			if ( res.code && res.vulnerabilities ) {
				setData( res );
			} else if ( res.status ) {
				setData( ( current ) => ( { ...current, code: res } ) );
			}
			if ( message ) {
				toast( message );
			}
			setProgress( key, null );
			return res;
		} catch ( e ) {
			toast( e.message, 'error' );
			setProgress( key, null );
			return null;
		}
	};

	if ( ! data ) {
		return <Loading />;
	}

	const vuln = data.vulnerabilities;
	const core = data.core;
	const plugins = data.plugins;
	const code = data.code;
	const monitor = data.monitor;
	const database = data.database;
	const coreIssues = core
		? core.modified.length + core.missing.length + core.unexpected.length
		: 0;

	const repair = async ( file ) => {
		if (
			await confirm(
				__(
					'Replace this file with the official copy?',
					'nhrrob-secure'
				),
				{
					description: file,
					confirmLabel: __( 'Replace file', 'nhrrob-secure' ),
				}
			)
		) {
			simple(
				'core',
				'/scanner/core/repair',
				{ file },
				__( 'File replaced with the official copy', 'nhrrob-secure' )
			);
		}
	};

	const quarantine = async ( finding ) => {
		if (
			await confirm( __( 'Quarantine this file?', 'nhrrob-secure' ), {
				description: finding.plugin
					? sprintf(
							/* translators: 1: file path, 2: plugin folder name. */
							__(
								'%1$s is part of the plugin “%2$s”. Renaming it can break that plugin. You can restore it from this screen.',
								'nhrrob-secure'
							),
							finding.file,
							finding.plugin
					  )
					: sprintf(
							/* translators: %s: file path. */
							__(
								'%s will be renamed so it cannot run. Nothing is deleted, and you can restore it from this screen.',
								'nhrrob-secure'
							),
							finding.file
					  ),
				confirmLabel: __( 'Quarantine', 'nhrrob-secure' ),
			} )
		) {
			simple(
				'code',
				'/scanner/code/quarantine',
				{ file: finding.file },
				__( 'Quarantined. Restore it below any time.', 'nhrrob-secure' )
			);
		}
	};

	const progressText = ( p ) =>
		p && p.total
			? sprintf(
					/* translators: 1: items checked, 2: total items. */
					__( 'Checking %1$d of %2$d…', 'nhrrob-secure' ),
					p.done,
					p.total
			  )
			: __( 'Starting…', 'nhrrob-secure' );

	return (
		<>
			<ScreenHeader
				title={ __( 'Scanner', 'nhrrob-secure' ) }
				lede={ __(
					'Checks your software against known problems and your files against the originals. It finds things for you to review; it is not a malware cleaner.',
					'nhrrob-secure'
				) }
			/>

			<Panel>
				<Row
					label={ __( 'Scan on a schedule', 'nhrrob-secure' ) }
					help={
						__(
							'Runs the file comparisons, the change check and the code review in the background and emails you when something new turns up. The vulnerability check always runs daily.',
							'nhrrob-secure'
						) +
						( data.scheduled_last
							? ' ' +
							  sprintf(
									/* translators: %s: relative time. */
									__( 'Last run: %s.', 'nhrrob-secure' ),
									ago( data.scheduled_last )
							  )
							: '' )
					}
					control={
						<select
							className="nhrrob-secure-select"
							aria-label={ __(
								'Scan schedule',
								'nhrrob-secure'
							) }
							value={ settings.scan_schedule }
							onChange={ ( e ) =>
								save( { scan_schedule: e.target.value } )
							}
						>
							<option value="off">
								{ __( 'Off', 'nhrrob-secure' ) }
							</option>
							<option value="daily">
								{ __( 'Daily', 'nhrrob-secure' ) }
							</option>
							<option value="weekly">
								{ __( 'Weekly', 'nhrrob-secure' ) }
							</option>
						</select>
					}
				/>
			</Panel>

			<Panel
				title={ __( 'Known vulnerabilities', 'nhrrob-secure' ) }
				icon="alert"
				flush
				meta={
					busy.vulnerabilities
						? progressText( busy.vulnerabilities )
						: sprintf(
								/* translators: %s: relative time, e.g. "2 hours ago". */
								__( 'Checked %s', 'nhrrob-secure' ),
								ago( vuln.checked )
						  )
				}
				actions={
					<Button
						small
						disabled={ !! busy.vulnerabilities }
						onClick={ () => run( 'vulnerabilities' ) }
					>
						{ __( 'Check now', 'nhrrob-secure' ) }
					</Button>
				}
			>
				{ vuln.items.length > 0 && (
					<div className="nhrrob-secure-scroll">
						<table className="nhrrob-secure-grid">
							<thead>
								<tr>
									<th>
										{ __( 'Software', 'nhrrob-secure' ) }
									</th>
									<th>
										{ __( 'Installed', 'nhrrob-secure' ) }
									</th>
									<th>
										{ __( 'Problem', 'nhrrob-secure' ) }
									</th>
									<th>
										{ __( 'Severity', 'nhrrob-secure' ) }
									</th>
									<th>
										{ __( 'Fixed in', 'nhrrob-secure' ) }
									</th>
								</tr>
							</thead>
							<tbody>
								{ vuln.items.map( ( item ) => (
									<tr key={ item.id }>
										<td>{ item.name }</td>
										<td>{ item.version }</td>
										<td className="is-wrap">
											{ item.link ? (
												<a
													href={ item.link }
													target="_blank"
													rel="noreferrer noopener"
												>
													{ item.title }
												</a>
											) : (
												item.title
											) }
										</td>
										<td>{ score( item.score ) }</td>
										<td>
											{ item.fixed_in ||
												( item.unfixed
													? __(
															'No fix yet',
															'nhrrob-secure'
													  )
													: __(
															'A later version',
															'nhrrob-secure'
													  ) ) }
										</td>
									</tr>
								) ) }
							</tbody>
						</table>
					</div>
				) }
				{ ! vuln.items.length && (
					<Empty>
						{ vuln.checked
							? sprintf(
									/* translators: %d: number of plugins, themes and WordPress itself. */
									__(
										'No known vulnerabilities in %d installed items.',
										'nhrrob-secure'
									),
									vuln.total
							  )
							: __(
									'Not checked yet. The first check runs within a day, or press “Check now”.',
									'nhrrob-secure'
							  ) }
					</Empty>
				) }
				{ ( vuln.items.length > 0 || vuln.closed.length > 0 ) && (
					<div className="nhrrob-secure-pad">
						{ vuln.closed.length > 0 && (
							<Note tone="warn">
								{ sprintf(
									/* translators: %s: list of plugin names. */
									__(
										'Closed on WordPress.org, so no more updates will come: %s.',
										'nhrrob-secure'
									),
									vuln.closed.join( ', ' )
								) }
							</Note>
						) }
						{ vuln.items.length > 0 && (
							<a
								className="nhrrob-secure-btn nhrrob-secure-btn--primary"
								href={ boot.updatesUrl }
							>
								{ __( 'Go to Updates', 'nhrrob-secure' ) }
							</a>
						) }
					</div>
				) }
			</Panel>

			<div className="nhrrob-secure-two">
				<Panel
					title={ __( 'WordPress files', 'nhrrob-secure' ) }
					icon="file"
					actions={
						core && (
							<Pill tone={ coreIssues ? 'bad' : 'ok' }>
								{ coreIssues
									? sprintf(
											/* translators: %d: number of files. */
											_n(
												'%d to review',
												'%d to review',
												coreIssues,
												'nhrrob-secure'
											),
											coreIssues
									  )
									: __( 'All match', 'nhrrob-secure' ) }
							</Pill>
						)
					}
				>
					{ core ? (
						<>
							<p>
								{ sprintf(
									/* translators: 1: number of files, 2: WordPress version. */
									__(
										'%1$d core files compared with the official WordPress %2$s release.',
										'nhrrob-secure'
									),
									core.total,
									core.version
								) }{ ' ' }
								{ ! coreIssues &&
									__(
										'Nothing changed, nothing missing, nothing added.',
										'nhrrob-secure'
									) }
							</p>
							<FileList
								title={ __( 'Changed', 'nhrrob-secure' ) }
								files={ core.modified }
								action={
									data.can_repair
										? ( file ) => (
												<Button
													small
													onClick={ () =>
														repair( file )
													}
												>
													{ __(
														'Replace',
														'nhrrob-secure'
													) }
												</Button>
										  )
										: null
								}
							/>
							<FileList
								title={ __( 'Missing', 'nhrrob-secure' ) }
								files={ core.missing }
								action={
									data.can_repair
										? ( file ) => (
												<Button
													small
													onClick={ () =>
														repair( file )
													}
												>
													{ __(
														'Restore',
														'nhrrob-secure'
													) }
												</Button>
										  )
										: null
								}
							/>
							<FileList
								title={ __(
									'Not part of WordPress',
									'nhrrob-secure'
								) }
								files={ core.unexpected }
							/>
						</>
					) : (
						<p>
							{ __(
								'Compares every WordPress core file with the official release and lists files that were changed, are missing, or do not belong.',
								'nhrrob-secure'
							) }
						</p>
					) }
					<p className="nhrrob-secure-sub">
						{ core
							? sprintf(
									/* translators: %s: relative time. */
									__( 'Checked %s.', 'nhrrob-secure' ),
									ago( core.checked )
							  ) + ' '
							: '' }
						{ __(
							'Your themes, plugins and uploads are not part of this check.',
							'nhrrob-secure'
						) }
					</p>
					<Button
						small
						disabled={ !! busy.core }
						onClick={ () => simple( 'core', '/scanner/core' ) }
					>
						{ busy.core
							? __( 'Comparing…', 'nhrrob-secure' )
							: __( 'Compare now', 'nhrrob-secure' ) }
					</Button>
				</Panel>

				<Panel
					title={ __( 'Plugin files', 'nhrrob-secure' ) }
					icon="file"
					actions={
						plugins && (
							<Pill
								tone={ plugins.changed.length ? 'warn' : 'ok' }
							>
								{ plugins.changed.length
									? sprintf(
											/* translators: %d: number of plugins. */
											_n(
												'%d changed',
												'%d changed',
												plugins.changed.length,
												'nhrrob-secure'
											),
											plugins.changed.length
									  )
									: __( 'All match', 'nhrrob-secure' ) }
							</Pill>
						)
					}
				>
					{ plugins ? (
						<>
							<p>
								{ sprintf(
									/* translators: %d: number of plugins. */
									_n(
										'%d plugin matches its WordPress.org original.',
										'%d plugins match their WordPress.org originals.',
										plugins.ok,
										'nhrrob-secure'
									),
									plugins.ok
								) }
							</p>
							{ plugins.changed.map( ( plugin ) => (
								<div key={ plugin.slug }>
									<FileList
										title={ sprintf(
											/* translators: 1: plugin name, 2: version. */
											__(
												'%1$s %2$s — changed files',
												'nhrrob-secure'
											),
											plugin.name,
											plugin.version
										) }
										files={ plugin.files }
									/>
									<FileList
										title={ sprintf(
											/* translators: %s: plugin name. */
											__(
												'%s — PHP files that are not in the release',
												'nhrrob-secure'
											),
											plugin.name
										) }
										files={ plugin.extra }
									/>
								</div>
							) ) }
							{ plugins.unknown.length > 0 && (
								<p className="nhrrob-secure-sub">
									{ sprintf(
										/* translators: %s: list of plugin names. */
										__(
											'Cannot be compared (not from WordPress.org, or that version is not published there): %s.',
											'nhrrob-secure'
										),
										plugins.unknown.join( ', ' )
									) }
								</p>
							) }
						</>
					) : (
						<p>
							{ __(
								'Compares each plugin with the release published on WordPress.org. Themes have no official checksums, so they cannot be compared.',
								'nhrrob-secure'
							) }
						</p>
					) }
					<p className="nhrrob-secure-sub">
						{ busy.plugins && progressText( busy.plugins ) }
						{ ! busy.plugins &&
							plugins &&
							sprintf(
								/* translators: %s: relative time. */
								__( 'Checked %s.', 'nhrrob-secure' ),
								ago( plugins.checked )
							) }
					</p>
					<Button
						small
						disabled={ !! busy.plugins }
						onClick={ () => run( 'plugins' ) }
					>
						{ __( 'Compare now', 'nhrrob-secure' ) }
					</Button>
				</Panel>
			</div>

			<Panel
				title={ __( 'Code changes outside updates', 'nhrrob-secure' ) }
				icon="file"
				flush
				meta={
					busy.monitor
						? progressText( busy.monitor )
						: sprintf(
								/* translators: 1: number of plugins and themes, 2: relative time. */
								__(
									'%1$d plugins and themes watched · checked %2$s',
									'nhrrob-secure'
								),
								monitor.watched,
								ago( monitor.checked )
						  )
				}
				actions={
					<Button
						small
						disabled={ !! busy.monitor }
						onClick={ () => run( 'monitor' ) }
					>
						{ __( 'Check now', 'nhrrob-secure' ) }
					</Button>
				}
			>
				<div className="nhrrob-secure-pad">
					<p className="nhrrob-secure-muted">
						{ __(
							'Remembers a fingerprint of the code of every plugin and theme, including themes and plugins WordPress.org cannot verify. If the code changes while the version stays the same, it is listed here.',
							'nhrrob-secure'
						) }
					</p>
				</div>
				{ monitor.changed.length > 0 ? (
					<div className="nhrrob-secure-scroll">
						<table className="nhrrob-secure-grid">
							<thead>
								<tr>
									<th>
										{ __( 'Changed', 'nhrrob-secure' ) }
									</th>
									<th>{ __( 'Type', 'nhrrob-secure' ) }</th>
									<th>
										{ __( 'Noticed', 'nhrrob-secure' ) }
									</th>
									<th />
								</tr>
							</thead>
							<tbody>
								{ monitor.changed.map( ( item ) => (
									<tr key={ item.key }>
										<td className="is-wrap">
											{ item.name }
										</td>
										<td>
											{ item.type === 'theme'
												? __( 'Theme', 'nhrrob-secure' )
												: __(
														'Plugin',
														'nhrrob-secure'
												  ) }
										</td>
										<td>{ ago( item.since ) }</td>
										<td className="is-actions">
											{ data.can_files && (
												<Button
													small
													onClick={ () =>
														simple(
															'monitor',
															'/scanner/monitor/accept',
															{ key: item.key },
															__(
																'Accepted as the current code',
																'nhrrob-secure'
															)
														)
													}
												>
													{ __(
														'I made this change',
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
				) : (
					<Empty>
						{ monitor.checked
							? __(
									'No code has changed outside an update.',
									'nhrrob-secure'
							  )
							: __(
									'Not checked yet. The first check records the fingerprints.',
									'nhrrob-secure'
							  ) }
					</Empty>
				) }
			</Panel>

			<Panel
				title={ __( 'Database content', 'nhrrob-secure' ) }
				icon="scanner"
				flush
				meta={
					database
						? sprintf(
								/* translators: %s: relative time. */
								__( 'Checked %s', 'nhrrob-secure' ),
								ago( database.checked )
						  )
						: ''
				}
				actions={
					<Button
						small
						disabled={ !! busy.database }
						onClick={ () =>
							simple( 'database', '/scanner/database' )
						}
					>
						{ busy.database
							? __( 'Checking…', 'nhrrob-secure' )
							: __( 'Check now', 'nhrrob-secure' ) }
					</Button>
				}
			>
				<div className="nhrrob-secure-pad">
					<p className="nhrrob-secure-muted">
						{ __(
							'Looks through posts, pages and stored settings for invisible iframes and for JavaScript that hides what it does — the usual shape of injected spam and redirects. Ordinary scripts and embeds are not reported.',
							'nhrrob-secure'
						) }
					</p>
				</div>
				{ database && database.findings.length > 0 && (
					<div className="nhrrob-secure-scroll">
						<table className="nhrrob-secure-grid">
							<thead>
								<tr>
									<th>{ __( 'Where', 'nhrrob-secure' ) }</th>
									<th>
										{ __(
											'Why it stands out',
											'nhrrob-secure'
										) }
									</th>
									<th />
								</tr>
							</thead>
							<tbody>
								{ database.findings.map( ( finding, index ) => (
									<tr key={ index }>
										<td className="is-wrap">
											{ finding.where }
										</td>
										<td className="is-wrap">
											{ finding.reason }
										</td>
										<td className="is-actions">
											{ finding.link && (
												<a
													className="nhrrob-secure-btn nhrrob-secure-btn--ghost nhrrob-secure-btn--sm"
													href={ finding.link }
												>
													{ __(
														'Open',
														'nhrrob-secure'
													) }
												</a>
											) }
										</td>
									</tr>
								) ) }
							</tbody>
						</table>
					</div>
				) }
				{ database && ! database.findings.length && (
					<Empty>
						{ __(
							'Nothing stood out in the database.',
							'nhrrob-secure'
						) }
					</Empty>
				) }
			</Panel>

			<Panel
				title={ __( 'Suspicious code', 'nhrrob-secure' ) }
				icon="scanner"
				flush
				meta={
					code.status === 'done'
						? sprintf(
								/* translators: 1: number of files, 2: relative time. */
								__(
									'%1$d PHP files checked %2$s',
									'nhrrob-secure'
								),
								code.files,
								ago( code.finished )
						  )
						: ''
				}
				actions={
					<Button
						small
						disabled={ !! busy.code }
						onClick={ () => runCode( code.status !== 'running' ) }
					>
						{ code.status === 'running' && ! busy.code
							? __( 'Continue scan', 'nhrrob-secure' )
							: __( 'Scan now', 'nhrrob-secure' ) }
					</Button>
				}
			>
				<div className="nhrrob-secure-pad">
					<p className="nhrrob-secure-muted">
						{ __(
							'Goes through every PHP file in wp-content looking for a few patterns typical of backdoors. A finding is a reason to look, not proof: security plugins and developer tools can match too.',
							'nhrrob-secure'
						) }
					</p>
					{ code.status === 'running' && (
						<>
							<div className="nhrrob-secure-progress">
								<i />
							</div>
							<p className="nhrrob-secure-sub">
								{ sprintf(
									/* translators: 1: number of files, 2: number of folders. */
									__(
										'%1$d PHP files checked, %2$d folders still queued. Keep this screen open; if you leave, “Continue scan” picks up where it stopped.',
										'nhrrob-secure'
									),
									code.files,
									code.folders
								) }
							</p>
						</>
					) }
					{ code.capped && (
						<Note tone="warn">
							{ __(
								'The scan stopped at 200 findings. Deal with these, then scan again.',
								'nhrrob-secure'
							) }
						</Note>
					) }
				</div>
				{ code.findings.length > 0 && (
					<div className="nhrrob-secure-scroll">
						<table className="nhrrob-secure-grid">
							<thead>
								<tr>
									<th>{ __( 'File', 'nhrrob-secure' ) }</th>
									<th>
										{ __(
											'Why it stands out',
											'nhrrob-secure'
										) }
									</th>
									<th />
								</tr>
							</thead>
							<tbody>
								{ code.findings.map( ( finding ) => (
									<tr key={ finding.file }>
										<td className="is-mono is-wrap">
											wp-content/{ finding.file }
										</td>
										<td className="is-wrap">
											{ finding.reason }
										</td>
										<td className="is-actions">
											<Button
												small
												onClick={ async () => {
													const res = await simple(
														'view',
														'/scanner/code/view',
														{ file: finding.file }
													);
													if ( res ) {
														setPreview( res );
													}
												} }
											>
												{ __(
													'View',
													'nhrrob-secure'
												) }
											</Button>
											{ data.can_files && (
												<Button
													small
													variant="danger"
													onClick={ () =>
														quarantine( finding )
													}
												>
													{ __(
														'Quarantine',
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
				{ code.status === 'done' && ! code.findings.length && (
					<Empty>
						{ __(
							'Nothing stood out in the last scan.',
							'nhrrob-secure'
						) }
					</Empty>
				) }
				{ preview && (
					<div className="nhrrob-secure-pad">
						<b>wp-content/{ preview.file }</b>{ ' ' }
						<Button small onClick={ () => setPreview( null ) }>
							{ __( 'Close', 'nhrrob-secure' ) }
						</Button>
						<pre className="nhrrob-secure-code">
							{ preview.lines
								.map(
									( line, index ) =>
										String(
											preview.start + index
										).padStart( 5 ) +
										'  ' +
										line
								)
								.join( '\n' ) }
						</pre>
					</div>
				) }
				{ code.quarantined.length > 0 && (
					<div className="nhrrob-secure-pad">
						<FileList
							title={ __( 'In quarantine', 'nhrrob-secure' ) }
							files={ code.quarantined }
							action={
								data.can_files
									? ( file ) => (
											<Button
												small
												onClick={ () =>
													simple(
														'code',
														'/scanner/code/restore',
														{ file },
														__(
															'File restored',
															'nhrrob-secure'
														)
													)
												}
											>
												{ __(
													'Restore',
													'nhrrob-secure'
												) }
											</Button>
									  )
									: null
							}
						/>
					</div>
				) }
			</Panel>
		</>
	);
}
