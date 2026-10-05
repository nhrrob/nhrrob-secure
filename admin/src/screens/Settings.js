/**
 * Settings: how the plugin itself behaves.
 */
import { useRef } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';

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
	TextSetting,
	Note,
} from '../components/ui';
import { useToast } from '../components/ToastProvider';

export default function Settings( { settings, meta, save, setData } ) {
	const toast = useToast();
	const fileInput = useRef( null );

	const exportSettings = () => {
		const { turnstile_secret_set: omitted, ...rest } = settings; // eslint-disable-line no-unused-vars
		const url = URL.createObjectURL(
			new Blob(
				[
					JSON.stringify(
						{ plugin: 'nhrrob-secure', settings: rest },
						null,
						2
					),
				],
				{ type: 'application/json' }
			)
		);
		const link = document.createElement( 'a' );
		link.href = url;
		link.download = 'secure-settings.json';
		link.click();
		URL.revokeObjectURL( url );
	};

	const importSettings = async ( event ) => {
		const file = event.target.files[ 0 ];
		event.target.value = '';
		if ( ! file ) {
			return;
		}
		try {
			const parsed = JSON.parse( await file.text() );
			const next = await api( '/settings/import', 'POST', {
				settings: parsed.settings || {},
			} );
			setData( next );
			toast( __( 'Settings imported', 'nhrrob-secure' ) );
		} catch ( e ) {
			toast(
				e.message ||
					__( 'That file could not be read.', 'nhrrob-secure' ),
				'error'
			);
		}
	};

	const kb = Math.max( 1, Math.round( meta.activity.bytes / 1024 ) );

	return (
		<>
			<ScreenHeader
				title={ __( 'Settings', 'nhrrob-secure' ) }
				lede={ __( 'How the plugin itself behaves.', 'nhrrob-secure' ) }
			/>

			<Panel
				title={ __( 'Visitor address', 'nhrrob-secure' ) }
				icon="globe"
			>
				<Row
					label={ __(
						'How visitors reach this site',
						'nhrrob-secure'
					) }
					help={ __(
						'Getting this right is what makes lockouts and address rules hit the right person. A forwarded address is only believed when the request really comes from Cloudflare or from a proxy you trust.',
						'nhrrob-secure'
					) }
				>
					<Seg
						label={ __( 'Connection type', 'nhrrob-secure' ) }
						value={ settings.ip_source }
						onChange={ ( v ) => save( { ip_source: v } ) }
						options={ [
							{
								value: 'direct',
								label: __( 'Directly', 'nhrrob-secure' ),
							},
							{
								value: 'cloudflare',
								label: __(
									'Through Cloudflare',
									'nhrrob-secure'
								),
							},
							{
								value: 'proxy',
								label: __( 'Another proxy', 'nhrrob-secure' ),
							},
						] }
					/>
				</Row>
				{ settings.ip_source === 'proxy' && (
					<Row
						label={ __( 'Trusted proxies', 'nhrrob-secure' ) }
						help={ __(
							'The addresses of your proxy or load balancer. Leave empty to trust only proxies on the local network.',
							'nhrrob-secure'
						) }
					>
						<TagList
							values={ settings.trusted_proxies }
							placeholder={ __(
								'e.g. 10.0.0.0/8',
								'nhrrob-secure'
							) }
							onChange={ ( list ) =>
								save( { trusted_proxies: list } )
							}
						/>
					</Row>
				) }
				<Note
					tone={
						settings.ip_source === 'direct' && meta.forwarded
							? 'warn'
							: 'info'
					}
				>
					{ sprintf(
						/* translators: %s: IP address. */
						__(
							'You appear as %s. If that is not your own address, this setting is wrong.',
							'nhrrob-secure'
						),
						meta.your_ip
					) }{ ' ' }
					{ settings.ip_source === 'direct' &&
						meta.cloudflare &&
						__(
							'This request came through Cloudflare, so “Through Cloudflare” is the right choice.',
							'nhrrob-secure'
						) }
					{ settings.ip_source === 'direct' &&
						! meta.cloudflare &&
						meta.forwarded &&
						__(
							'This request carried a forwarded address, so your site is probably behind a proxy.',
							'nhrrob-secure'
						) }
				</Note>
			</Panel>

			<Panel title={ __( 'Email alerts', 'nhrrob-secure' ) } icon="mail">
				<Row
					label={ __( 'Send alerts to', 'nhrrob-secure' ) }
					help={ sprintf(
						/* translators: %s: email address. */
						__( 'Leave empty to use %s.', 'nhrrob-secure' ),
						meta.alert_to
					) }
				>
					<TextSetting
						type="email"
						className="is-wide"
						value={ settings.alert_email }
						aria-label={ __( 'Alert email', 'nhrrob-secure' ) }
						onCommit={ ( v ) => save( { alert_email: v } ) }
					/>
				</Row>
				<Row
					label={ __( 'Also post alerts to', 'nhrrob-secure' ) }
					help={ __(
						'A webhook address (https) of Slack or any service that accepts the same format. Every alert is posted there as well as emailed.',
						'nhrrob-secure'
					) }
				>
					<TextSetting
						type="url"
						className="is-wide"
						placeholder="https://hooks.slack.com/services/…"
						value={ settings.alert_webhook }
						aria-label={ __( 'Webhook address', 'nhrrob-secure' ) }
						onCommit={ ( v ) => save( { alert_webhook: v } ) }
					/>
					<Button
						onClick={ async () => {
							try {
								await api( '/settings/test-alert', 'POST' );
								toast(
									__( 'Test alert sent', 'nhrrob-secure' )
								);
							} catch ( e ) {
								toast( e.message, 'error' );
							}
						} }
					>
						{ __( 'Send a test alert', 'nhrrob-secure' ) }
					</Button>
				</Row>
				<Row
					label={ __(
						'A new administrator is created, or a role is raised to administrator',
						'nhrrob-secure'
					) }
					control={
						<Switch
							checked={ settings.alert_new_admin }
							label={ __(
								'Alert on new administrator',
								'nhrrob-secure'
							) }
							onChange={ ( v ) => save( { alert_new_admin: v } ) }
						/>
					}
				/>
				<Row
					label={ __(
						'A new vulnerability is found',
						'nhrrob-secure'
					) }
					help={ __(
						'Once per finding, not every day.',
						'nhrrob-secure'
					) }
					control={
						<Switch
							checked={ settings.alert_vulnerability }
							label={ __(
								'Alert on vulnerability',
								'nhrrob-secure'
							) }
							onChange={ ( v ) =>
								save( { alert_vulnerability: v } )
							}
						/>
					}
				/>
				<Row
					label={ __(
						'A scheduled scan finds something new',
						'nhrrob-secure'
					) }
					control={
						<Switch
							checked={ settings.alert_scan }
							label={ __(
								'Alert on scan findings',
								'nhrrob-secure'
							) }
							onChange={ ( v ) => save( { alert_scan: v } ) }
						/>
					}
				/>
				<Row
					label={ __( 'Weekly summary', 'nhrrob-secure' ) }
					help={ __(
						'One email a week: the score, what needs fixing, and sign-ins, lockouts, refused requests and findings of the week.',
						'nhrrob-secure'
					) }
					control={
						<Switch
							checked={ settings.weekly_summary }
							label={ __( 'Weekly summary', 'nhrrob-secure' ) }
							onChange={ ( v ) => save( { weekly_summary: v } ) }
						/>
					}
				/>
				<Row
					label={ __( 'A burst of lockouts', 'nhrrob-secure' ) }
					help={ __(
						'Five or more addresses locked out within an hour; at most one email an hour.',
						'nhrrob-secure'
					) }
					control={
						<Switch
							checked={ settings.alert_lockouts }
							label={ __( 'Alert on lockouts', 'nhrrob-secure' ) }
							onChange={ ( v ) => save( { alert_lockouts: v } ) }
						/>
					}
				/>
			</Panel>

			<Panel title={ __( 'Data', 'nhrrob-secure' ) } icon="settings">
				<Row
					label={ __( 'Keep activity for', 'nhrrob-secure' ) }
					help={ sprintf(
						/* translators: 1: number of events, 2: size in KB. */
						__(
							'Currently %1$d events, %2$d KB. Everything is stored in a few capped options; the plugin creates no database tables.',
							'nhrrob-secure'
						),
						meta.activity.rows,
						kb
					) }
				>
					<select
						className="nhrrob-secure-select"
						aria-label={ __( 'Retention', 'nhrrob-secure' ) }
						value={ settings.retention_days }
						onChange={ ( e ) =>
							save( { retention_days: e.target.value } )
						}
					>
						{ [ 7, 30, 90, 180, 365 ]
							.concat(
								[ 7, 30, 90, 180, 365 ].includes(
									settings.retention_days
								)
									? []
									: [ settings.retention_days ]
							)
							.sort( ( a, b ) => a - b )
							.map( ( days ) => (
								<option key={ days } value={ days }>
									{ sprintf(
										/* translators: %d: number of days. */
										__( '%d days', 'nhrrob-secure' ),
										days
									) }
								</option>
							) ) }
					</select>
				</Row>
				<Row
					label={ __( 'Also log content changes', 'nhrrob-secure' ) }
					help={ __(
						'Posts and pages published, changed, trashed or deleted, media, menus, widgets, comment moderation and, with WooCommerce, order status and shop settings. Only what a signed-in user did; these rows make room first when the log is full.',
						'nhrrob-secure'
					) }
					control={
						<Switch
							checked={ settings.log_content }
							label={ __(
								'Log content changes',
								'nhrrob-secure'
							) }
							onChange={ ( v ) => save( { log_content: v } ) }
						/>
					}
				/>
				<Row
					label={ __(
						'Move settings between sites',
						'nhrrob-secure'
					) }
					help={ __(
						'The export leaves out the Turnstile secret key.',
						'nhrrob-secure'
					) }
				>
					<Button onClick={ exportSettings }>
						{ __( 'Export settings', 'nhrrob-secure' ) }
					</Button>
					<Button onClick={ () => fileInput.current.click() }>
						{ __( 'Import settings', 'nhrrob-secure' ) }
					</Button>
					<input
						ref={ fileInput }
						type="file"
						accept="application/json,.json"
						hidden
						onChange={ importSettings }
					/>
				</Row>
				<Row
					label={ __(
						'Delete everything when the plugin is deleted',
						'nhrrob-secure'
					) }
					help={ __(
						'Settings, activity, lockouts, scan results and every user’s two-factor setup.',
						'nhrrob-secure'
					) }
					control={
						<Switch
							checked={ settings.delete_on_uninstall }
							label={ __(
								'Delete data on uninstall',
								'nhrrob-secure'
							) }
							onChange={ ( v ) =>
								save( { delete_on_uninstall: v } )
							}
						/>
					}
				/>
			</Panel>

			<Panel
				title={ __( 'If you get locked out', 'nhrrob-secure' ) }
				icon="login"
				actions={
					<Pill tone={ meta.safe_mode ? 'warn' : 'off' }>
						{ meta.safe_mode
							? __( 'Safe mode on', 'nhrrob-secure' )
							: __( 'Safe mode off', 'nhrrob-secure' ) }
					</Pill>
				}
			>
				<p className="nhrrob-secure-muted">
					{ __(
						'Safe mode pauses the moved login address, lockouts, the request filter, address and country rules and the two-factor step, and leaves every setting as it is. Keep these lines somewhere you can find them.',
						'nhrrob-secure'
					) }
				</p>
				<pre className="nhrrob-secure-code">
					{ `// wp-config.php
define( 'NHRROB_SECURE_SAFE_MODE', true );

# or from the command line
wp nhrrob-secure safe-mode on
wp nhrrob-secure unlock ${ meta.your_ip }
wp nhrrob-secure reset-2fa <username>` }
				</pre>
			</Panel>
		</>
	);
}
