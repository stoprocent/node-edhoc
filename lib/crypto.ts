import { EDHOC, EdhocCryptoManager } from './edhoc';
import { ec, eddsa } from 'elliptic';

export class DefaultEdhocCryptoManager implements EdhocCryptoManager {

    generateKey(edhoc: EDHOC, keyType: number, key: Buffer) {
        console.log(edhoc, edhoc.selectedSuite);
        console.log(edhoc);
        return Promise.resolve(Buffer.alloc(key.length));
    }

    destroyKey(edhoc: EDHOC, keyID: Buffer) {
        console.log(edhoc);
        return Promise.resolve(true);
    }

    makeKeyPair(edhoc: EDHOC, keyID: Buffer, privateKeySize: number, publicKeySize: number) {
        console.log(edhoc);
        return Promise.resolve({ publicKey: Buffer.alloc(publicKeySize), privateKey: Buffer.alloc(privateKeySize) });
    }

    keyAgreement(edhoc: EDHOC, keyID: Buffer, publicKey: Buffer, privateKeySize: number) {
        console.log(edhoc);
        return Promise.resolve(Buffer.alloc(privateKeySize));
    }

    sign(edhoc: EDHOC, keyID: Buffer, input: Buffer, signatureSize: number) {
        console.log(edhoc);
        return Promise.resolve(Buffer.alloc(signatureSize));
    }

    verify(edhoc: EDHOC, keyID: Buffer, input: Buffer, signature: Buffer) {
        console.log(edhoc);
        return Promise.resolve(true);
    }

    extract(edhoc: EDHOC, keyID: Buffer, salt: Buffer, keySize: number) {
        console.log(edhoc);
        return Promise.resolve(Buffer.alloc(keySize));
    }

    expand(edhoc: EDHOC, keyID: Buffer, info: Buffer, keySize: number) {
        console.log(edhoc);
        return Promise.resolve(Buffer.alloc(keySize));
    }

    encrypt(edhoc: EDHOC, keyID: Buffer, plaintext: Buffer) {
        console.log(edhoc);
        return Promise.resolve(Buffer.alloc(plaintext.length));
    }

    decrypt(edhoc: EDHOC, keyID: Buffer, ciphertext: Buffer) {
        console.log(edhoc);
        return Promise.resolve(Buffer.alloc(ciphertext.length));
    }

    hash(edhoc: EDHOC, data: Buffer, hashSize: number) {
        console.log(edhoc);
        return Promise.resolve(Buffer.alloc(hashSize));
    }
}
