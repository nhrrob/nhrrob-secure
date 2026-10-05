/**
 * Confirmation modal — replaces window.confirm() with UI that matches the
 * rest of the app instead of the browser's native dialog chrome.
 */
import { useEffect, useRef } from '@wordpress/element';
import { __ } from '@wordpress/i18n';

/**
 * @param {Object}   root0                Props.
 * @param {string}   root0.message        Question shown as the dialog title.
 * @param {string}   [root0.description]  Supporting detail shown below the title.
 * @param {string}   [root0.confirmLabel] Confirm button label.
 * @param {string}   [root0.cancelLabel]  Cancel button label.
 * @param {boolean}  [root0.danger]       Whether the confirm button reads as destructive (default true).
 * @param {Function} root0.onConfirm      Called when the user confirms.
 * @param {Function} root0.onCancel       Called when the user cancels/dismisses.
 * @return {Object} Modal element.
 */
export default function ConfirmDialog( {
	message,
	description,
	confirmLabel,
	cancelLabel,
	danger = true,
	onConfirm,
	onCancel,
} ) {
	// Cancel is the safe default focus target — pressing Enter right after
	// the dialog opens (e.g. a stray keypress from the action that opened it)
	// should never land on the destructive action.
	const cancelRef = useRef( null );
	useEffect( () => {
		if ( cancelRef.current ) {
			cancelRef.current.focus();
		}
	}, [] );

	return (
		<div
			className="nhrrob-secure-modal__overlay"
			role="presentation"
			onMouseDown={ ( e ) => {
				if ( e.target === e.currentTarget ) {
					onCancel();
				}
			} }
			onKeyDown={ ( e ) => {
				if ( e.key === 'Escape' ) {
					onCancel();
				}
			} }
		>
			<div
				className="nhrrob-secure-modal nhrrob-secure-modal--sm"
				role="alertdialog"
				aria-modal="true"
				aria-label={ message }
			>
				<header className="nhrrob-secure-modal__head">
					<h2>{ message }</h2>
					<button
						type="button"
						className="nhrrob-secure-modal__close"
						aria-label={ __( 'Close', 'nhrrob-secure' ) }
						onClick={ onCancel }
					>
						×
					</button>
				</header>

				{ description && (
					<div className="nhrrob-secure-modal__body">
						<p className="nhrrob-secure-modal__confirm-text">
							{ description }
						</p>
					</div>
				) }

				<footer className="nhrrob-secure-modal__foot">
					<button
						ref={ cancelRef }
						type="button"
						className="nhrrob-secure-btn nhrrob-secure-btn--soft"
						onClick={ onCancel }
					>
						{ cancelLabel || __( 'Cancel', 'nhrrob-secure' ) }
					</button>
					<button
						type="button"
						className={
							'nhrrob-secure-btn ' +
							( danger
								? 'nhrrob-secure-btn--danger'
								: 'nhrrob-secure-btn--primary' )
						}
						onClick={ onConfirm }
					>
						{ confirmLabel || __( 'Confirm', 'nhrrob-secure' ) }
					</button>
				</footer>
			</div>
		</div>
	);
}
