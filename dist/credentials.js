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
                certificate: credentials.certificate
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
            const x509 = new crypto_1.X509Certificate(credentials.x5chain.certificate);
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
