/**
 * Generates tests/fixtures/passkey.json: WebAuthn registration and sign-in
 * responses made with Node's own crypto, independent of the PHP code that
 * has to verify them. Run with `node tests/fixtures/make-passkey-vectors.js`.
 */
const crypto = require( 'crypto' );
const fs = require( 'fs' );
const path = require( 'path' );

const b64u = ( buf ) => Buffer.from( buf ).toString( 'base64url' );
const head = ( major, n ) => {
	if ( n < 24 ) return Buffer.from( [ ( major << 5 ) | n ] );
	if ( n < 256 ) return Buffer.from( [ ( major << 5 ) | 24, n ] );
	return Buffer.from( [ ( major << 5 ) | 25, n >> 8, n & 255 ] );
};
const cbor = ( v ) => {
	if ( typeof v === 'number' ) return v >= 0 ? head( 0, v ) : head( 1, -1 - v );
	if ( Buffer.isBuffer( v ) ) return Buffer.concat( [ head( 2, v.length ), v ] );
	if ( typeof v === 'string' ) return Buffer.concat( [ head( 3, Buffer.byteLength( v ) ), Buffer.from( v ) ] );
	if ( v instanceof Map ) return Buffer.concat( [ head( 5, v.size ), ...[ ...v ].flatMap( ( [ k, x ] ) => [ cbor( k ), cbor( x ) ] ) ] );
	throw new Error( 'unsupported' );
};

const rpId = 'example.test';
const origin = 'https://example.test';
const rpHash = crypto.createHash( 'sha256' ).update( rpId ).digest();
const u32 = ( n ) => { const b = Buffer.alloc( 4 ); b.writeUInt32BE( n ); return b; };

function vector( kind ) {
	const pair = kind === 'ec'
		? crypto.generateKeyPairSync( 'ec', { namedCurve: 'P-256' } )
		: crypto.generateKeyPairSync( 'rsa', { modulusLength: 2048 } );
	const jwk = pair.publicKey.export( { format: 'jwk' } );
	const cose = kind === 'ec'
		? new Map( [ [ 1, 2 ], [ 3, -7 ], [ -1, 1 ], [ -2, Buffer.from( jwk.x, 'base64url' ) ], [ -3, Buffer.from( jwk.y, 'base64url' ) ] ] )
		: new Map( [ [ 1, 3 ], [ 3, -257 ], [ -1, Buffer.from( jwk.n, 'base64url' ) ], [ -2, Buffer.from( jwk.e, 'base64url' ) ] ] );

	const credId = crypto.randomBytes( 32 );
	const idLen = Buffer.alloc( 2 ); idLen.writeUInt16BE( credId.length );
	const regChallenge = b64u( crypto.randomBytes( 32 ) );
	const regAuth = Buffer.concat( [ rpHash, Buffer.from( [ 0x45 ] ), u32( 0 ), Buffer.alloc( 16 ), idLen, credId, cbor( cose ) ] );
	const attestation = cbor( new Map( [ [ 'fmt', 'none' ], [ 'attStmt', new Map() ], [ 'authData', regAuth ] ] ) );
	const regClient = Buffer.from( JSON.stringify( { type: 'webauthn.create', challenge: regChallenge, origin, crossOrigin: false } ) );

	const getChallenge = b64u( crypto.randomBytes( 32 ) );
	const getAuth = Buffer.concat( [ rpHash, Buffer.from( [ 0x05 ] ), u32( 7 ) ] );
	const getClient = Buffer.from( JSON.stringify( { type: 'webauthn.get', challenge: getChallenge, origin, crossOrigin: false } ) );
	const signed = Buffer.concat( [ getAuth, crypto.createHash( 'sha256' ).update( getClient ).digest() ] );
	const signature = crypto.sign( 'sha256', signed, pair.privateKey );

	return {
		rpId, origin,
		credentialId: b64u( credId ),
		spki: pair.publicKey.export( { type: 'spki', format: 'pem' } ),
		register: { challenge: regChallenge, client: b64u( regClient ), attestation: b64u( attestation ) },
		signin: { challenge: getChallenge, client: b64u( getClient ), auth: b64u( getAuth ), sig: b64u( signature ) },
	};
}

fs.writeFileSync( path.join( __dirname, 'passkey.json' ), JSON.stringify( { ec: vector( 'ec' ), rsa: vector( 'rsa' ) }, null, 1 ) + '\n' );
console.log( 'written' );
