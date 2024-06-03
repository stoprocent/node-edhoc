import { DefaultEdhocCryptoManager } from './crypto';
import { EDHOC, EdhocCredentialManager, EdhocCredentials, EdhocCredentialsFormat, EdhocCredentialsCertificateChain } from './edhoc';
import { X509Certificate } from 'crypto';

export class X509Credentials {
    
    public certificate: Buffer;
    public privateKey: Buffer;
    
    constructor(certificate: Buffer, privateKey: Buffer) {
        this.certificate = certificate;
        this.privateKey = privateKey;
    }
}

export class DefaultEdhocCredentialManager implements EdhocCredentialManager {
    
    private credentials: Map<string, EdhocCredentials> = new Map<string, EdhocCredentials>();
    private trustRoots: X509Certificate[] = [];

    setCredentials(cryptoManager: DefaultEdhocCryptoManager, credentials: X509Credentials, keyID: Buffer = Buffer.from('00000001', 'hex')) {
        cryptoManager.addKey(keyID, credentials.privateKey);
        let chain: EdhocCredentialsCertificateChain = {
            format: EdhocCredentialsFormat.x5chain,
            privateKeyID: keyID,
            x5chain: { 
                certificates: [ credentials.certificate ]
            }
        };
        this.credentials.set(keyID.toString('hex'), chain);
    }

    addTrustRoot(certificate: Buffer) {
        this.trustRoots.push(new X509Certificate(certificate));
    }

    async fetch(edhoc: EDHOC): Promise<EdhocCredentials> {
        const credential = this.credentials.values().next().value;
        return credential;
    }

    async verify(edhoc: EDHOC, credentials: EdhocCredentials) {
        if (credentials.format === EdhocCredentialsFormat.x5chain) {
            const x5chain = (credentials as EdhocCredentialsCertificateChain).x5chain;
            const certificates = x5chain.certificates;
            const numCerts = certificates.length;

            if (numCerts < 1) {
                throw new Error('Certificate chain must contain at least one certificate.');
            }

            let verified = false;

            // Step 1: Verify each certificate against the next one in the chain, if there are multiple certificates
            for (let i = 0; i < numCerts - 1; i++) {
                const currentCert = new X509Certificate(certificates[i]);
                const nextCert = new X509Certificate(certificates[i + 1]);

                if (!currentCert.verify(nextCert.publicKey)) {
                    throw new Error(`Verification failed: Certificate at index ${i} is not signed by the next certificate in the chain.`);
                }
            }

            // Step 2: Verify the last certificate in the chain against the trust roots
            const lastCert = new X509Certificate(certificates[numCerts - 1]);

            for (let trustRoot of this.trustRoots) {
                if (lastCert.verify(trustRoot.publicKey)) {
                    verified = true;
                    break; // Exit the loop once verified
                }
            }

            if (!verified) {
                throw new Error('Certificate chain not verified');
            }
            
            let token = new X509Certificate(certificates[0]).publicKey.export({ format: 'jwk' });
            if (token.crv === 'P-256') {
                credentials.publicKey = Buffer.concat([
                    Buffer.from(token.x!, 'base64'),
                    Buffer.from(token.y!, 'base64')
                ]);
                return credentials;
            }
            else if (token.crv === 'Ed25519') {
                let publicKey = Buffer.from(token.x!, 'base64');
                credentials.publicKey = publicKey;
                return credentials;
            }
            else {
                throw new Error('Unsupported curve');
            }
        }
        throw new Error('Credentials format not supported');
    }
}
