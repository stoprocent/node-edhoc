"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DefaultEdhocCredentialManager = exports.X509Credentials = void 0;
const edhoc_1 = require("./edhoc");
const crypto_1 = require("crypto");
class X509Credentials {
    certificate;
    privateKey;
    constructor(certificate, privateKey) {
        this.certificate = certificate;
        this.privateKey = privateKey;
    }
}
exports.X509Credentials = X509Credentials;
class DefaultEdhocCredentialManager {
    credentials = new Map();
    trustRoots = [];
    setCredentials(cryptoManager, credentials, keyID = Buffer.from('00000001', 'hex')) {
        cryptoManager.addKey(keyID, credentials.privateKey);
        let chain = {
            format: edhoc_1.EdhocCredentialsFormat.x5chain,
            privateKeyID: keyID,
            x5chain: {
                certificates: [credentials.certificate]
            }
        };
        this.credentials.set(keyID.toString('hex'), chain);
    }
    addTrustRoot(certificate) {
        this.trustRoots.push(new crypto_1.X509Certificate(certificate));
    }
    async fetch(edhoc) {
        const credential = this.credentials.values().next().value;
        return credential;
    }
    async verify(edhoc, credentials) {
        if (credentials.format === edhoc_1.EdhocCredentialsFormat.x5chain) {
            const x5chain = credentials.x5chain;
            const certificates = x5chain.certificates;
            const numCerts = certificates.length;
            if (numCerts < 1) {
                throw new Error('Certificate chain must contain at least one certificate.');
            }
            let verified = false;
            // Step 1: Verify each certificate against the next one in the chain, if there are multiple certificates
            for (let i = 0; i < numCerts - 1; i++) {
                const currentCert = new crypto_1.X509Certificate(certificates[i]);
                const nextCert = new crypto_1.X509Certificate(certificates[i + 1]);
                if (!currentCert.verify(nextCert.publicKey)) {
                    throw new Error(`Verification failed: Certificate at index ${i} is not signed by the next certificate in the chain.`);
                }
            }
            // Step 2: Verify the last certificate in the chain against the trust roots
            const lastCert = new crypto_1.X509Certificate(certificates[numCerts - 1]);
            for (let trustRoot of this.trustRoots) {
                if (lastCert.verify(trustRoot.publicKey)) {
                    verified = true;
                    break; // Exit the loop once verified
                }
            }
            if (!verified) {
                throw new Error('Certificate chain not verified');
            }
            let token = new crypto_1.X509Certificate(certificates[0]).publicKey.export({ format: 'jwk' });
            if (token.crv === 'P-256') {
                credentials.publicKey = Buffer.concat([
                    Buffer.from(token.x, 'base64'),
                    Buffer.from(token.y, 'base64')
                ]);
                return credentials;
            }
            else if (token.crv === 'Ed25519') {
                let publicKey = Buffer.from(token.x, 'base64');
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
exports.DefaultEdhocCredentialManager = DefaultEdhocCredentialManager;
