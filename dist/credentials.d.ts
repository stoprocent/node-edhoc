import { EDHOC, EdhocCredentialManager, EdhocCredentials } from './edhoc';
export declare class DefaultEdhocCredentialManager implements EdhocCredentialManager {
    fetch(edhoc: EDHOC): Promise<EdhocCredentials>;
    verify(edhoc: EDHOC, credentials: EdhocCredentials): Promise<EdhocCredentials>;
}
//# sourceMappingURL=credentials.d.ts.map