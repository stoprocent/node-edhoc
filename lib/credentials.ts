import { EDHOC, EdhocCredentialManager, EdhocCredentials } from './edhoc';

export class DefaultEdhocCredentialManager extends EdhocCredentialManager {
    

    public fetch = async (edhoc: EDHOC) => {
        return Promise.resolve({ format: 0, privateKeyID: Buffer.alloc(0) });
    }

    public verify = async (edhoc: EDHOC, credentials: EdhocCredentials) => {
        return Promise.resolve(credentials);
    }

}
