/**
 * REST helper: every call goes to nhrrob-secure/v1.
 */
import apiFetch from '@wordpress/api-fetch';

const ROOT = 'nhrrob-secure/v1';

/**
 * @param {string} path   Route path, e.g. '/settings'.
 * @param {string} method HTTP method.
 * @param {Object} data   JSON body.
 * @return {Promise<Object>} Parsed response.
 */
export default function api( path, method = 'GET', data ) {
	return apiFetch( { path: ROOT + path, method, data } );
}

/**
 * Build a query string from an object, skipping empty values.
 *
 * @param {Object} params Query parameters.
 * @return {string} Query string, with leading '?' when not empty.
 */
export function query( params ) {
	const parts = Object.keys( params )
		.filter(
			( key ) => params[ key ] !== '' && params[ key ] !== undefined
		)
		.map(
			( key ) =>
				encodeURIComponent( key ) +
				'=' +
				encodeURIComponent( params[ key ] )
		);
	return parts.length ? '?' + parts.join( '&' ) : '';
}
