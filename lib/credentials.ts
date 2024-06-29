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
                certificate: credentials.certificate 
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
            const x509 = new X509Certificate((credentials as EdhocCredentialsCertificateChain).x5chain.certificate);

            let verified = false;
            for (let trustRoot of this.trustRoots) {
                if (x509.verify(trustRoot.publicKey)) {
                    verified = true;
                }
            }

            if (!verified) {
                throw new Error('Certificate chain not verified');
            }
            
            let token = x509.publicKey.export({ format: 'jwk' });
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
