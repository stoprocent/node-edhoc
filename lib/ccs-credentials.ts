import {
    EDHOC,
    EdhocCredentialManager,
    EdhocCredentials,
    EdhocCredentialsFormat,
    EdhocCredentialsKID,
} from './edhoc';

interface OwnCredential {
    kid: number | Buffer;
    ccsBytes: Buffer;
    publicKey: Buffer;
    privateKey: Buffer;
}

interface PeerCredential {
    kid: number | Buffer;
    ccsBytes: Buffer;
    publicKey: Buffer;
}

/**
 * Credential manager for CCS (CWT Claims Set) credentials identified by kid.
 *
 * Use `addOwnCredential()` to register the local party's credential (returned
 * by `fetch()`) and `addPeerCredential()` for each remote party whose
 * credentials should be accepted (matched during `verify()`).
 */
export class CCSCredentialManager implements EdhocCredentialManager {
    private ownCredential: OwnCredential | null = null;
    private peerCredentials: PeerCredential[] = [];

    /**
     * Register the local party's CCS credential.
     *
     * @param kid        - Key identifier (integer or Buffer)
     * @param ccsBytes   - Raw CBOR-encoded CCS map
     * @param publicKey  - Public key bytes (e.g. P-256 x-coordinate or x||y)
     * @param privateKey - Private key bytes
     */
    addOwnCredential(
        kid: number | Buffer,
        ccsBytes: Buffer,
        publicKey: Buffer,
        privateKey: Buffer,
    ): void {
        this.ownCredential = { kid, ccsBytes, publicKey, privateKey };
    }

    /**
     * Register a peer's CCS credential for verification.
     *
     * @param kid       - Key identifier (integer or Buffer)
     * @param ccsBytes  - Raw CBOR-encoded CCS map
     * @param publicKey - Public key bytes
     */
    addPeerCredential(
        kid: number | Buffer,
        ccsBytes: Buffer,
        publicKey: Buffer,
    ): void {
        this.peerCredentials.push({ kid, ccsBytes, publicKey });
    }

    /**
     * Return the local party's credentials for inclusion in an EDHOC message.
     */
    async fetch(_edhoc: EDHOC): Promise<EdhocCredentials> {
        if (!this.ownCredential) {
            throw new Error('No own credential configured. Call addOwnCredential() first.');
        }

        return {
            format: EdhocCredentialsFormat.kid,
            privateKey: this.ownCredential.privateKey,
            publicKey: this.ownCredential.publicKey,
            kid: {
                kid: this.ownCredential.kid,
                credentials: this.ownCredential.ccsBytes,
                isCBOR: true,
            },
        } as EdhocCredentialsKID;
    }

    /**
     * Verify received peer credentials by looking up the kid value among
     * registered peer credentials.
     */
    async verify(_edhoc: EDHOC, credentials: EdhocCredentials): Promise<EdhocCredentials> {
        if (credentials.format !== EdhocCredentialsFormat.kid) {
            throw new Error('CCSCredentialManager only supports kid credentials format');
        }

        const kidCred = credentials as EdhocCredentialsKID;
        const receivedKid = kidCred.kid.kid;

        const peer = this.peerCredentials.find(p => {
            if (typeof p.kid === 'number' && typeof receivedKid === 'number') {
                return p.kid === receivedKid;
            }
            if (Buffer.isBuffer(p.kid) && Buffer.isBuffer(receivedKid)) {
                return p.kid.equals(receivedKid);
            }
            return false;
        });

        if (!peer) {
            throw new Error(`Unknown peer kid: ${receivedKid}`);
        }

        return {
            format: EdhocCredentialsFormat.kid,
            publicKey: peer.publicKey,
            kid: {
                kid: peer.kid,
                credentials: peer.ccsBytes,
                isCBOR: true,
            },
        } as EdhocCredentialsKID;
    }
}
