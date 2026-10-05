/**
 * App-wide confirm() replacement — a promise-based hook backed by one shared
 * <ConfirmDialog>, so every screen can `await confirm(...)` instead of
 * reaching for window.confirm().
 */
import {
	createContext,
	useContext,
	useState,
	useCallback,
	useRef,
} from '@wordpress/element';

import ConfirmDialog from './ConfirmDialog';

const ConfirmContext = createContext( null );

export function ConfirmProvider( { children } ) {
	const [ dialog, setDialog ] = useState( null );
	const resolverRef = useRef( null );

	const confirm = useCallback( ( message, options = {} ) => {
		return new Promise( ( resolve ) => {
			resolverRef.current = resolve;
			setDialog( { message, ...options } );
		} );
	}, [] );

	const settle = ( result ) => {
		setDialog( null );
		if ( resolverRef.current ) {
			resolverRef.current( result );
			resolverRef.current = null;
		}
	};

	return (
		<ConfirmContext.Provider value={ confirm }>
			{ children }
			{ dialog && (
				<ConfirmDialog
					{ ...dialog }
					onConfirm={ () => settle( true ) }
					onCancel={ () => settle( false ) }
				/>
			) }
		</ConfirmContext.Provider>
	);
}

/**
 * @return {Function} confirm(message, { confirmLabel, cancelLabel, danger }) => Promise<boolean>
 */
export function useConfirm() {
	return useContext( ConfirmContext );
}
