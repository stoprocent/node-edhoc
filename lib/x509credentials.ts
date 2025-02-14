import { DefaultEdhocCryptoManager } from './crypto';
import { EDHOC, EdhocCredentialManager, EdhocCredentials, EdhocCredentialsFormat, EdhocCredentialsCertificateChain } from './edhoc';
import { X509Certificate } from 'crypto';

export class X509CertificateCredentialManager implements EdhocCredentialManager {

    private certificates: X509Certificate[] = [];
    private otherPartyCertificates: X509Certificate[] = [];
    private trustedCAs: X509Certificate[] = [];
    private cryptoKeyID: Buffer;

    constructor(credentials: X509Certificate[] | Buffer[], cryptoKeyID: Buffer) {
        this.cryptoKeyID = cryptoKeyID;
        this.certificates = this.convertAndValidateCredentials(credentials);
    }

    addOtherPartyCredentials(credentials: X509Certificate[] | Buffer[]) {
        this.otherPartyCertificates.push(...this.convertAndValidateCredentials(credentials));
    }

    addTrustCA(certificate: X509Certificate | Buffer) {
        this.trustedCAs.push(this.convertAndValidateSingleCredential(certificate));
    }

    private convertAndValidateCredentials(credentials: X509Certificate[] | Buffer[]): X509Certificate[] {
        return credentials.map(cred => this.convertAndValidateSingleCredential(cred));
    }

    private convertAndValidateSingleCredential(cred: X509Certificate | Buffer): X509Certificate {
        if (cred instanceof X509Certificate) {
            return cred;
        } else if (cred instanceof Buffer) {
            return new X509Certificate(cred);
        } else {
            throw new Error('Invalid credentials');
        }
    }

    async fetch(edhoc: EDHOC): Promise<EdhocCredentials> {
        const chain: EdhocCredentialsCertificateChain = {
            format: EdhocCredentialsFormat.x5chain,
            privateKeyID: this.cryptoKeyID,
            x5chain: { 
                certificates: this.certificates.map(cert => cert.raw)
            }
        };
        return chain;
    }

    async verify(edhoc: EDHOC, credentials: EdhocCredentials) {
        if (credentials.format !== EdhocCredentialsFormat.x5chain) {
            throw new Error('Credentials format not supported');
        }

        const x5chain = (credentials as EdhocCredentialsCertificateChain).x5chain;
        const certificates = x5chain.certificates;
        if (certificates.length < 1) {
            throw new Error('Certificate chain must contain at least one certificate.');
        }

        this.verifyCertificateChain(certificates);
        this.verifyAgainstTrustRoots(certificates[certificates.length - 1]);

        const token = new X509Certificate(certificates[0]).publicKey.export({ format: 'jwk' });
        credentials.publicKey = this.extractPublicKey(token);
        return credentials;
    }

    private verifyCertificateChain(certificates: Buffer[]) {
        for (let i = 0; i < certificates.length - 1; i++) {
            const currentCert = new X509Certificate(certificates[i]);
            const nextCert = new X509Certificate(certificates[i + 1]);
            if (!currentCert.verify(nextCert.publicKey)) {
                throw new Error(`Verification failed: Certificate at index ${i} is not signed by the next certificate in the chain.`);
            }
        }
    }

    private verifyAgainstTrustRoots(lastCertBuffer: Buffer) {
        const lastCert = new X509Certificate(lastCertBuffer);
        for (const trustRoot of this.trustedCAs) {
            if (lastCert.verify(trustRoot.publicKey)) {
                return;
            }
        }
        throw new Error('Certificate chain not verified');
    }

    private extractPublicKey(token: any): Buffer {
        if (token.crv === 'P-256') {
            return Buffer.concat([
                Buffer.from(token.x!, 'base64'),
                Buffer.from(token.y!, 'base64')
            ]);
        } else if (token.crv === 'Ed25519') {
            return Buffer.from(token.x!, 'base64');
        } else {
            throw new Error('Unsupported curve');
        }
    }
}
