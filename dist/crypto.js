"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DefaultEdhocCryptoManager = void 0;
class DefaultEdhocCryptoManager {
    generateKey(edhoc, keyType, key) {
        console.log(edhoc, edhoc.selectedSuite);
        console.log(edhoc);
        return Promise.resolve(Buffer.alloc(key.length));
    }
    destroyKey(edhoc, keyID) {
        console.log(edhoc);
        return Promise.resolve(true);
    }
    makeKeyPair(edhoc, keyID, privateKeySize, publicKeySize) {
        console.log(edhoc);
        return Promise.resolve({ publicKey: Buffer.alloc(publicKeySize), privateKey: Buffer.alloc(privateKeySize) });
    }
    keyAgreement(edhoc, keyID, publicKey, privateKeySize) {
        console.log(edhoc);
        return Promise.resolve(Buffer.alloc(privateKeySize));
    }
    sign(edhoc, keyID, input, signatureSize) {
        console.log(edhoc);
        return Promise.resolve(Buffer.alloc(signatureSize));
    }
    verify(edhoc, keyID, input, signature) {
        console.log(edhoc);
        return Promise.resolve(true);
    }
    extract(edhoc, keyID, salt, keySize) {
        console.log(edhoc);
        return Promise.resolve(Buffer.alloc(keySize));
    }
    expand(edhoc, keyID, info, keySize) {
        console.log(edhoc);
        return Promise.resolve(Buffer.alloc(keySize));
    }
    encrypt(edhoc, keyID, plaintext) {
        console.log(edhoc);
        return Promise.resolve(Buffer.alloc(plaintext.length));
    }
    decrypt(edhoc, keyID, ciphertext) {
        console.log(edhoc);
        return Promise.resolve(Buffer.alloc(ciphertext.length));
    }
    hash(edhoc, data, hashSize) {
        console.log(edhoc);
        return Promise.resolve(Buffer.alloc(hashSize));
    }
}
exports.DefaultEdhocCryptoManager = DefaultEdhocCryptoManager;
