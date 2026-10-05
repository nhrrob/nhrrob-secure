/**
 * App-wide toast() — a fixed-position, auto-dismissing success/error message,
 * backed by one shared <Toast> stack, so any screen can call
 * `toast('Option added.')` instead of rolling its own inline notice.
 */
import {
	createContext,
	useContext,
	useState,
	useCallback,
} from '@wordpress/element';

import Toast from './Toast';

const ToastContext = createContext( null );
const AUTO_DISMISS_MS = 3000;

export function ToastProvider( { children } ) {
	const [ toasts, setToasts ] = useState( [] );

	const dismiss = useCallback( ( id ) => {
		setToasts( ( list ) => list.filter( ( t ) => t.id !== id ) );
	}, [] );

	const toast = useCallback(
		( message, type = 'success' ) => {
			const id = Date.now() + Math.random();
			setToasts( ( list ) => [ ...list, { id, message, type } ] );
			setTimeout( () => dismiss( id ), AUTO_DISMISS_MS );
		},
		[ dismiss ]
	);

	return (
		<ToastContext.Provider value={ toast }>
			{ children }
			<Toast toasts={ toasts } />
		</ToastContext.Provider>
	);
}

/**
 * @return {Function} toast(message, type = 'success' | 'error')
 */
export function useToast() {
	return useContext( ToastContext );
}
