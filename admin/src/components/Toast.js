/**
 * Toast stack — fixed-position, non-blocking success/error feedback.
 * Rendered by ToastProvider; doesn't shift any surrounding layout the way
 * an inline notice does.
 */
import { Icon } from './ui';

/**
 * @param {Object} root0        Props.
 * @param {Array}  root0.toasts List of { id, message, type }.
 * @return {Object} Toast stack element.
 */
export default function Toast( { toasts } ) {
	if ( ! toasts.length ) {
		return null;
	}
	return (
		<div className="nhrrob-secure-toasts" role="status" aria-live="polite">
			{ toasts.map( ( t ) => (
				<div
					key={ t.id }
					className={
						'nhrrob-secure-toast' +
						( t.type === 'error'
							? ' nhrrob-secure-toast--error'
							: '' )
					}
				>
					<Icon
						name={ t.type === 'error' ? 'alert' : 'check' }
						size={ 15 }
					/>
					{ t.message }
				</div>
			) ) }
		</div>
	);
}
