/// <reference types="node" />
import { EDHOC, EdhocCryptoManager } from './edhoc';
export declare class DefaultEdhocCryptoManager extends EdhocCryptoManager {
    constructor();
    generateKey2: (edhoc: EDHOC, keyType: number, key: Buffer) => Promise<Buffer>;
    destroyKey: (edhoc: EDHOC, keyID: Buffer) => Promise<boolean>;
    makeKeyPair(edhoc: EDHOC, keyID: Buffer, privateKeySize: number, publicKeySize: number): Promise<{
        publicKey: Buffer;
        privateKey: Buffer;
    }>;
    keyAgreement: (edhoc: EDHOC, keyID: Buffer, publicKey: Buffer, privateKeySize: number) => Promise<Buffer>;
    sign: (edhoc: EDHOC, keyID: Buffer, input: Buffer, signatureSize: number) => Promise<Buffer>;
    verify: (edhoc: EDHOC, keyID: Buffer, input: Buffer, signature: Buffer) => Promise<boolean>;
    extract: (edhoc: EDHOC, keyID: Buffer, salt: Buffer, keySize: number) => Promise<Buffer>;
    expand: (edhoc: EDHOC, keyID: Buffer, info: Buffer, keySize: number) => Promise<Buffer>;
    encrypt: (edhoc: EDHOC, keyID: Buffer, plaintext: Buffer) => Promise<Buffer>;
    decrypt: (edhoc: EDHOC, keyID: Buffer, ciphertext: Buffer) => Promise<Buffer>;
    hash: (edhoc: EDHOC, data: Buffer, hashSize: number) => Promise<Buffer>;
}
//# sourceMappingURL=crypto.d.ts.map