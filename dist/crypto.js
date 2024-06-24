"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DefaultEdhocCryptoManager = void 0;
const edhoc_1 = require("./edhoc");
class DefaultEdhocCryptoManager extends edhoc_1.EdhocCryptoManager {
    constructor() {
        super();
        this.generateKey = this.generateKey2;
    }
    generateKey2 = async (edhoc, keyType, key) => {
        console.log(edhoc, edhoc.selectedSuite);
        return Promise.resolve(Buffer.alloc(key.length));
    };
    destroyKey = async (edhoc, keyID) => {
        return Promise.resolve(true);
    };
    makeKeyPair(edhoc, keyID, privateKeySize, publicKeySize) {
        return Promise.resolve({ publicKey: Buffer.alloc(publicKeySize), privateKey: Buffer.alloc(privateKeySize) });
    }
    // public makeKeyPair = async (edhoc: EDHOC, keyID: Buffer, privateKeySize: number, publicKeySize: number) => {
    //     return Promise.resolve({ publicKey: Buffer.alloc(publicKeySize), privateKey: Buffer.alloc(privateKeySize) });
    // }
    keyAgreement = async (edhoc, keyID, publicKey, privateKeySize) => {
        return Promise.resolve(Buffer.alloc(privateKeySize));
    };
    sign = async (edhoc, keyID, input, signatureSize) => {
        return Promise.resolve(Buffer.alloc(signatureSize));
    };
    verify = async (edhoc, keyID, input, signature) => {
        return Promise.resolve(true);
    };
    extract = async (edhoc, keyID, salt, keySize) => {
        return Promise.resolve(Buffer.alloc(keySize));
    };
    expand = async (edhoc, keyID, info, keySize) => {
        return Promise.resolve(Buffer.alloc(keySize));
    };
    encrypt = async (edhoc, keyID, plaintext) => {
        return Promise.resolve(Buffer.alloc(plaintext.length));
    };
    decrypt = async (edhoc, keyID, ciphertext) => {
        return Promise.resolve(Buffer.alloc(ciphertext.length));
    };
    hash = async (edhoc, data, hashSize) => {
        return Promise.resolve(Buffer.alloc(hashSize));
    };
}
exports.DefaultEdhocCryptoManager = DefaultEdhocCryptoManager;
