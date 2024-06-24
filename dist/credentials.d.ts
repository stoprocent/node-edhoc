/// <reference types="node" />
import { EDHOC, EdhocCredentialManager, EdhocCredentials } from './edhoc';
export declare class DefaultEdhocCredentialManager extends EdhocCredentialManager {
    fetch: (edhoc: EDHOC) => Promise<{
        format: number;
        privateKeyID: Buffer;
    }>;
    verify: (edhoc: EDHOC, credentials: EdhocCredentials) => Promise<EdhocCredentials>;
}
//# sourceMappingURL=credentials.d.ts.map