import { EDHOC, EdhocCredentialManager, EdhocCredentials, EdhocCredentialsFormat } from './edhoc';

export class DefaultEdhocCredentialManager implements EdhocCredentialManager {
    
    fetch(edhoc: EDHOC): Promise<EdhocCredentials> {
        return Promise.resolve({ format: EdhocCredentialsFormat.kid, privateKeyID: Buffer.alloc(0) });
    }

    verify(edhoc: EDHOC, credentials: EdhocCredentials): Promise<EdhocCredentials> {
        return Promise.resolve(credentials);
    }
}
