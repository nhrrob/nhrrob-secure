/**
 * Shared building blocks: icons, panels, setting rows, controls and time helpers.
 * Hand-rolled on purpose — no component or icon library enters the bundle.
 */
import { useState, useEffect } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { dateI18n, humanTimeDiff } from '@wordpress/date';

const P = 'nhrrob-secure-';

const PATHS = {
	menu: 'M4 6h16M4 12h16M4 18h16',
	shield: 'M12 3l8 3v6c0 5-3.4 8.3-8 9-4.6-.7-8-4-8-9V6zM9 12l2 2 4-4',
	moon: 'M20 14.5A8 8 0 019.5 4 8 8 0 1020 14.5z',
	sun: 'M12 8a4 4 0 100 8 4 4 0 000-8zM12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4',
	dashboard: 'M3 3h7v9H3zM14 3h7v5h-7zM14 12h7v9h-7zM3 16h7v5H3z',
	login: 'M12 15a4 4 0 11-8 0 4 4 0 018 0zM11 12l9-9M16 7l3 3',
	users: 'M12.5 8a3.5 3.5 0 11-7 0 3.5 3.5 0 017 0zM2.5 20a6.5 6.5 0 0113 0M16 4.6a3.5 3.5 0 010 6.8M18 14.5a6.5 6.5 0 013.5 5.5',
	firewall:
		'M4.5 4h15A1.5 1.5 0 0121 5.5v13a1.5 1.5 0 01-1.5 1.5h-15A1.5 1.5 0 013 18.5v-13A1.5 1.5 0 014.5 4zM3 9.3h18M3 14.7h18M9 4v5.3M15 9.3v5.4M9 14.7V20',
	hardening:
		'M7 11h10a2 2 0 012 2v6a2 2 0 01-2 2H7a2 2 0 01-2-2v-6a2 2 0 012-2zM8 11V8a4 4 0 018 0v3',
	scanner:
		'M4 8V5a1 1 0 011-1h3M16 4h3a1 1 0 011 1v3M20 16v3a1 1 0 01-1 1h-3M8 20H5a1 1 0 01-1-1v-3M4 12h16',
	activity: 'M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01',
	settings:
		'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065zM9 12a3 3 0 106 0 3 3 0 00-6 0',
	alert: 'M12 4l9 16H3zM12 10v4M12 17h.01',
	info: 'M12 3a9 9 0 100 18 9 9 0 000-18zM12 11v5M12 8h.01',
	check: 'M5 12.5l4.5 4.5L19 7.5',
	link: 'M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1-1',
	phone: 'M9 3h6a2 2 0 012 2v14a2 2 0 01-2 2H9a2 2 0 01-2-2V5a2 2 0 012-2zM11 18h2',
	bot: 'M7 8h10a2 2 0 012 2v7a2 2 0 01-2 2H7a2 2 0 01-2-2v-7a2 2 0 012-2zM12 8V4M9 13h.01M15 13h.01M9.5 16h5',
	filter: 'M4 5h16l-6 7v6l-4 2v-8z',
	globe: 'M12 3a9 9 0 100 18 9 9 0 000-18zM3 12h18M12 3c3 3.2 3 14.8 0 18M12 3c-3 3.2-3 14.8 0 18',
	file: 'M7 3h7l4 4v14H7zM14 3v4h4',
	mail: 'M5 5h14a2 2 0 012 2v10a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2zM3 7l9 6 9-6',
	x: 'M6 6l12 12M18 6L6 18',
};

const extraIcons = {};

/**
 * Let an add-on register icons for its own sections.
 *
 * @param {Object} icons Map of name to SVG path data.
 */
export function registerIcons( icons ) {
	Object.assign( extraIcons, icons );
}

export function Icon( { name, size = 18, className = '' } ) {
	const d = PATHS[ name ] || extraIcons[ name ] || PATHS.shield;
	return (
		<svg
			className={ P + 'icon ' + className }
			width={ size }
			height={ size }
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth="1.8"
			strokeLinecap="round"
			strokeLinejoin="round"
			aria-hidden="true"
		>
			<path d={ d } />
		</svg>
	);
}

export function ScreenHeader( { title, lede } ) {
	return (
		<div className={ P + 'screen__head' }>
			<h1 className={ P + 'screen__title' }>{ title }</h1>
			{ lede && <p className={ P + 'screen__lede' }>{ lede }</p> }
		</div>
	);
}

export function Panel( {
	title,
	icon,
	meta,
	actions,
	anchor,
	flush,
	children,
} ) {
	return (
		<section
			className={ P + 'panel' }
			id={ anchor ? P + 'panel-' + anchor : undefined }
		>
			{ ( title || meta || actions ) && (
				<header className={ P + 'panel__head' }>
					<h2 className={ P + 'panel__title' }>
						{ icon && <Icon name={ icon } /> }
						{ title }
					</h2>
					{ meta && (
						<span className={ P + 'panel__meta' }>{ meta }</span>
					) }
					{ actions }
				</header>
			) }
			<div className={ P + 'panel__body' + ( flush ? ' is-flush' : '' ) }>
				{ children }
			</div>
		</section>
	);
}

export function Pill( { tone = 'off', children } ) {
	return (
		<span className={ P + 'pill ' + P + 'pill--' + tone }>
			{ children }
		</span>
	);
}

export function Button( {
	variant = 'ghost',
	small,
	className = '',
	...props
} ) {
	return (
		<button
			type="button"
			className={
				P +
				'btn ' +
				P +
				'btn--' +
				variant +
				( small ? ' ' + P + 'btn--sm' : '' ) +
				' ' +
				className
			}
			{ ...props }
		/>
	);
}

export function Switch( { checked, onChange, label, disabled } ) {
	return (
		<button
			type="button"
			role="switch"
			aria-checked={ !! checked }
			aria-label={ label }
			disabled={ disabled }
			className={ P + 'switch' }
			onClick={ () => onChange( ! checked ) }
		/>
	);
}

/**
 * One setting: label, help, optional "could break" line, extra controls
 * underneath, and a control (usually a Switch) on the right.
 *
 * @param {Object} root0          Props.
 * @param {string} root0.label    Setting name.
 * @param {Object} root0.badge    Optional pill next to the label.
 * @param {string} root0.help     Explanation.
 * @param {string} root0.risk     What could stop working.
 * @param {Object} root0.control  Control shown on the right.
 * @param {Object} root0.children Extra controls under the text.
 * @return {Object} Row element.
 */
export function Row( { label, badge, help, risk, control, children } ) {
	return (
		<div className={ P + 'row' }>
			<div className={ P + 'row__main' }>
				<div className={ P + 'row__label' }>
					{ label }
					{ badge }
				</div>
				{ help && <div className={ P + 'row__help' }>{ help }</div> }
				{ risk && (
					<div className={ P + 'row__risk' }>
						{ sprintf(
							/* translators: %s: what could stop working. */
							__( 'Could break: %s', 'nhrrob-secure' ),
							risk
						) }
					</div>
				) }
				{ children && (
					<div className={ P + 'row__sub' }>{ children }</div>
				) }
			</div>
			{ control }
		</div>
	);
}

export function Field( { label, children } ) {
	return (
		// eslint-disable-next-line jsx-a11y/label-has-associated-control -- the control is passed in as a child.
		<label className={ P + 'field' }>
			<span>{ label }</span>
			{ children }
		</label>
	);
}

export function Seg( { value, options, onChange, label } ) {
	return (
		<div className={ P + 'seg' } role="group" aria-label={ label }>
			{ options.map( ( option ) => (
				<button
					key={ option.value }
					type="button"
					className={ option.value === value ? 'is-on' : '' }
					aria-pressed={ option.value === value }
					onClick={ () => onChange( option.value ) }
				>
					{ option.label }
				</button>
			) ) }
		</div>
	);
}

export function Chips( { items, selected, onToggle } ) {
	return (
		<div className={ P + 'chips' }>
			{ items.map( ( item ) => {
				const on = selected.includes( item.value );
				return (
					<button
						key={ item.value }
						type="button"
						className={ P + 'chip' + ( on ? ' is-on' : '' ) }
						aria-pressed={ on }
						onClick={ () => onToggle( item.value, ! on ) }
					>
						{ item.label }
					</button>
				);
			} ) }
		</div>
	);
}

/**
 * A list the owner edits by adding and removing short text entries.
 *
 * @param {Object}   root0             Props.
 * @param {string[]} root0.values      Current entries.
 * @param {Function} root0.onChange    Called with the new list.
 * @param {string}   root0.placeholder Input placeholder.
 * @param {string}   root0.addLabel    Add button label.
 * @param {Function} root0.format      Optional display formatter.
 * @return {Object} Element.
 */
export function TagList( { values, onChange, placeholder, addLabel, format } ) {
	const [ draft, setDraft ] = useState( '' );
	const add = () => {
		const value = draft.trim();
		if ( value && ! values.includes( value ) ) {
			onChange( [ ...values, value ] );
		}
		setDraft( '' );
	};
	return (
		<div className={ P + 'taglist' }>
			<div className={ P + 'chips' }>
				{ values.map( ( value ) => (
					<span key={ value } className={ P + 'chip is-on' }>
						{ format ? format( value ) : value }
						<button
							type="button"
							className={ P + 'chip__x' }
							aria-label={ sprintf(
								/* translators: %s: entry being removed. */
								__( 'Remove %s', 'nhrrob-secure' ),
								value
							) }
							onClick={ () =>
								onChange(
									values.filter( ( v ) => v !== value )
								)
							}
						>
							<Icon name="x" size={ 12 } />
						</button>
					</span>
				) ) }
			</div>
			<div className={ P + 'inline' }>
				<input
					type="text"
					className={ P + 'input' }
					value={ draft }
					placeholder={ placeholder }
					aria-label={ placeholder }
					onChange={ ( e ) => setDraft( e.target.value ) }
					onKeyDown={ ( e ) => {
						if ( e.key === 'Enter' ) {
							e.preventDefault();
							add();
						}
					} }
				/>
				<Button variant="soft" onClick={ add }>
					{ addLabel || __( 'Add', 'nhrrob-secure' ) }
				</Button>
			</div>
		</div>
	);
}

/**
 * Text or number input that saves when the owner leaves the field or presses Enter.
 *
 * @param {Object}   root0           Props.
 * @param {string}   root0.value     Stored value.
 * @param {Function} root0.onCommit  Called with the new value when it changed.
 * @param {string}   root0.className Extra class names.
 * @return {Object} Input element.
 */
export function TextSetting( { value, onCommit, className = '', ...props } ) {
	const [ draft, setDraft ] = useState( value );
	useEffect( () => setDraft( value ), [ value ] );
	const commit = () => {
		if ( String( draft ) !== String( value ) ) {
			onCommit( draft );
		}
	};
	return (
		<input
			className={ P + 'input ' + className }
			value={ draft }
			onChange={ ( e ) => setDraft( e.target.value ) }
			onBlur={ commit }
			onKeyDown={ ( e ) => {
				if ( e.key === 'Enter' ) {
					e.target.blur();
				}
			} }
			{ ...props }
		/>
	);
}

export function Note( { tone = 'info', children } ) {
	return (
		<div className={ P + 'note ' + P + 'note--' + tone }>
			<Icon name={ tone === 'info' ? 'info' : 'alert' } />
			<div>{ children }</div>
		</div>
	);
}

export function Empty( { children } ) {
	return <p className={ P + 'empty' }>{ children }</p>;
}

/**
 * "Loading…", or what went wrong when the request failed — a failed request
 * must not leave the screen waiting forever.
 *
 * @param {Object} root0
 * @param {Object} root0.error The rejected request, if any.
 */
export function Loading( { error } ) {
	if ( error ) {
		return (
			<Note tone="warn">
				{ error.message ||
					__(
						'This could not be loaded. Reload the page to try again.',
						'nhrrob-secure'
					) }
			</Note>
		);
	}
	return (
		<p className={ P + 'empty' }>{ __( 'Loading…', 'nhrrob-secure' ) }</p>
	);
}

export function Gauge( { score } ) {
	const r = 56;
	const c = 2 * Math.PI * r;
	let tone = 'bad';
	if ( score >= 80 ) {
		tone = 'ok';
	} else if ( score >= 50 ) {
		tone = 'warn';
	}
	return (
		<div className={ P + 'gauge ' + P + 'gauge--' + tone }>
			<svg
				viewBox="0 0 132 132"
				width="132"
				height="132"
				aria-hidden="true"
			>
				<circle
					className={ P + 'gauge__track' }
					cx="66"
					cy="66"
					r={ r }
					fill="none"
					strokeWidth="12"
				/>
				<circle
					className={ P + 'gauge__arc' }
					cx="66"
					cy="66"
					r={ r }
					fill="none"
					strokeWidth="12"
					strokeLinecap="round"
					strokeDasharray={ c }
					strokeDashoffset={ c * ( 1 - score / 100 ) }
					transform="rotate(-90 66 66)"
				/>
			</svg>
			<div className={ P + 'gauge__value' }>
				<strong>{ score }</strong>
				<span>{ __( 'out of 100', 'nhrrob-secure' ) }</span>
			</div>
		</div>
	);
}

/**
 * "5 mins ago" for a unix timestamp.
 *
 * @param {number} ts Unix time in seconds.
 * @return {string} Relative time.
 */
export function ago( ts ) {
	if ( ! ts ) {
		return __( 'never', 'nhrrob-secure' );
	}
	// Older WordPress versions have no humanTimeDiff(); show the date there.
	return humanTimeDiff
		? humanTimeDiff( new Date( ts * 1000 ) )
		: dateI18n( 'M j, H:i', new Date( ts * 1000 ) );
}

/**
 * Time left until a unix timestamp, e.g. "18 min" or "2 h 5 min".
 *
 * @param {number} ts Unix time in seconds.
 * @return {string} Time span.
 */
export function until( ts ) {
	const minutes = Math.max(
		1,
		Math.ceil( ( ts * 1000 - Date.now() ) / 60000 )
	);
	if ( minutes < 60 ) {
		/* translators: %d: minutes. */
		return sprintf( __( '%d min', 'nhrrob-secure' ), minutes );
	}
	if ( minutes < 2880 ) {
		return sprintf(
			/* translators: 1: hours, 2: minutes. */
			__( '%1$d h %2$d min', 'nhrrob-secure' ),
			Math.floor( minutes / 60 ),
			minutes % 60
		);
	}
	return sprintf(
		/* translators: %d: days. */
		__( '%d days', 'nhrrob-secure' ),
		Math.ceil( minutes / 1440 )
	);
}

/**
 * Short date and time in the site's timezone.
 *
 * @param {number} ts Unix time in seconds.
 * @return {string} Formatted date.
 */
export function when( ts ) {
	return ts ? dateI18n( 'M j, H:i', new Date( ts * 1000 ) ) : '—';
}
