/// <reference types="node" />
import { EDHOC, EdhocCryptoManager, EdhocKeyType } from './edhoc';
export declare class DefaultEdhocCryptoManager implements EdhocCryptoManager {
    private keys;
    private keyIdentifier;
    constructor();
    addKey(keyID: Buffer, key: Buffer): void;
    generateKey(edhoc: EDHOC, keyType: EdhocKeyType, key: Buffer): Promise<Buffer>;
    destroyKey(edhoc: EDHOC, keyID: Buffer): boolean;
    makeKeyPair(edhoc: EDHOC, keyID: Buffer, privateKeySize: number, publicKeySize: number): {
        privateKey: Buffer;
        publicKey: Buffer;
    };
    keyAgreement(edhoc: EDHOC, keyID: Buffer, publicKey: Buffer, privateKeySize: number): Buffer;
    sign(edhoc: EDHOC, keyID: Buffer, input: Buffer, signatureSize: number): Buffer;
    verify(edhoc: EDHOC, keyID: Buffer, input: Buffer, signature: Buffer): boolean;
    extract(edhoc: EDHOC, keyID: Buffer, salt: Buffer, keySize: number): Buffer;
    expand(edhoc: EDHOC, keyID: Buffer, info: Buffer, keySize: number): Buffer;
    encrypt(edhoc: EDHOC, keyID: Buffer, nonce: Buffer, aad: Buffer, plaintext: Buffer, size: number): Buffer;
    decrypt(edhoc: EDHOC, keyID: Buffer, nonce: Buffer, aad: Buffer, ciphertext: Buffer, size: number): Buffer;
    hash(edhoc: EDHOC, data: Buffer, hashSize: number): Promise<Buffer>;
}
//# sourceMappingURL=crypto.d.ts.map