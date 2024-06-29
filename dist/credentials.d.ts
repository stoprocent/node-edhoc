/// <reference types="node" />
import { DefaultEdhocCryptoManager } from './crypto';
import { EDHOC, EdhocCredentialManager, EdhocCredentials } from './edhoc';
export declare class X509Credentials {
    certificate: Buffer;
    privateKey: Buffer;
    constructor(certificate: Buffer, privateKey: Buffer);
}
export declare class DefaultEdhocCredentialManager implements EdhocCredentialManager {
    private credentials;
    private trustRoots;
    setCredentials(cryptoManager: DefaultEdhocCryptoManager, credentials: X509Credentials, keyID?: Buffer): void;
    addTrustRoot(certificate: Buffer): void;
    fetch(edhoc: EDHOC): Promise<EdhocCredentials>;
    verify(edhoc: EDHOC, credentials: EdhocCredentials): Promise<EdhocCredentials>;
}
//# sourceMappingURL=credentials.d.ts.map