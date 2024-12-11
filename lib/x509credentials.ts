import { EDHOC, EdhocCredentialManager, EdhocCredentials, EdhocCredentialsFormat, EdhocCredentialsCertificateChain, EdhocCredentialsCertificateHash, EdhocCredentialsCertificateHashAlgorithm } from './edhoc';
import { JsonWebKey, X509Certificate } from 'crypto';

export class X509CertificateCredentialManager implements EdhocCredentialManager {

    private certificates: X509Certificate[] = [];
    private peerCertificates: X509Certificate[] = [];
    private trustedCAs: X509Certificate[] = [];
    private cryptoKeyID: Buffer;

    fetchFormat: EdhocCredentialsFormat = EdhocCredentialsFormat.x5chain;

    constructor(credentials: X509Certificate[] | Buffer[], cryptoKeyID: Buffer) {
        this.cryptoKeyID = cryptoKeyID;
        this.certificates = this.convertAndValidateCredentials(credentials);
    }

    addPeerCertificate(certificate: X509Certificate | Buffer) {
        this.peerCertificates.push(this.convertAndValidateSingleCredential(certificate));
    }

    addTrustedCA(certificate: X509Certificate | Buffer) {
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
        if (this.certificates.length === 0) {
            throw new Error('No certificates found');
        }
        switch (this.fetchFormat) {
            case EdhocCredentialsFormat.x5chain: {
                const chain: EdhocCredentialsCertificateChain = {
                    format: EdhocCredentialsFormat.x5chain,
                    privateKeyID: this.cryptoKeyID,
                    x5chain: { 
                        certificates: this.certificates.map(cert => cert.raw)
                    }
                };
                return chain;
            }
            case EdhocCredentialsFormat.x5t: {
                if (this.certificates.length > 1) {
                    throw new Error('x5t format only supports a single certificate');
                }
                const hash: EdhocCredentialsCertificateHash = {
                    format: EdhocCredentialsFormat.x5t,
                    privateKeyID: this.cryptoKeyID,
                    x5t: {
                        certificate: this.certificates[0].raw,
                        hash: Buffer.from(this.certificates[0].fingerprint256.replace(/:/g, ''), 'hex').subarray(0, 8),
                        hashAlgorithm: EdhocCredentialsCertificateHashAlgorithm.Sha256_64
                    }
                };
                return hash;
            }
            default:
                throw new Error('Unsupported credentials format');
        }
    }

    async verify(edhoc: EDHOC, credentials: EdhocCredentials) {
        if (credentials.format !== EdhocCredentialsFormat.x5chain && 
            credentials.format !== EdhocCredentialsFormat.x5t) 
        {
            throw new Error('Credentials format not supported');
        }

        let certificates: Buffer[] = [];
        if (credentials.format === EdhocCredentialsFormat.x5chain) {
            const x5chain = (credentials as EdhocCredentialsCertificateChain).x5chain;
            certificates = x5chain.certificates;
        } else if (credentials.format === EdhocCredentialsFormat.x5t) {
            const x5t = (credentials as EdhocCredentialsCertificateHash).x5t;
            certificates = this.peerCertificates
                .filter(certificate => {
                    const checksum = Buffer.from(certificate.fingerprint256.replace(/:/g, ''), 'hex');
                    if (x5t.hashAlgorithm == EdhocCredentialsCertificateHashAlgorithm.Sha256_64) {
                        return checksum.subarray(0, 8).equals(x5t.hash);
                    } else if (x5t.hashAlgorithm == EdhocCredentialsCertificateHashAlgorithm.Sha256) {
                        return checksum.equals(x5t.hash);
                    } else {
                        throw new Error('Unsupported hash algorithm');
                    }
                })
                .flatMap(certificate => certificate.raw);
            x5t.certificate = certificates[0];
        }

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

    private extractPublicKey(token: JsonWebKey): Buffer {
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
