import { EDHOC, EdhocCryptoManager } from './edhoc';
import { ec, eddsa } from 'elliptic';

export class DefaultEdhocCryptoManager extends EdhocCryptoManager {
    
    constructor() {
        super();
        this.generateKey = this.generateKey2;
    }

    public generateKey2 = async (edhoc: EDHOC, keyType: number, key: Buffer) => {
        console.log(edhoc, edhoc.selectedSuite);
        return Promise.resolve(Buffer.alloc(key.length));
    }

    public destroyKey = async (edhoc: EDHOC, keyID: Buffer) => {
        return Promise.resolve(true);
    }

    public makeKeyPair(edhoc: EDHOC, keyID: Buffer, privateKeySize: number, publicKeySize: number): Promise<{ publicKey: Buffer; privateKey: Buffer; }> {
        return Promise.resolve({ publicKey: Buffer.alloc(publicKeySize), privateKey: Buffer.alloc(privateKeySize) });
    }

    // public makeKeyPair = async (edhoc: EDHOC, keyID: Buffer, privateKeySize: number, publicKeySize: number) => {
    //     return Promise.resolve({ publicKey: Buffer.alloc(publicKeySize), privateKey: Buffer.alloc(privateKeySize) });
    // }

    public keyAgreement = async (edhoc: EDHOC, keyID: Buffer, publicKey: Buffer, privateKeySize: number) => {
        return Promise.resolve(Buffer.alloc(privateKeySize));
    }

    public sign = async (edhoc: EDHOC, keyID: Buffer, input: Buffer, signatureSize: number) => {
        return Promise.resolve(Buffer.alloc(signatureSize));
    }

    public verify = async (edhoc: EDHOC, keyID: Buffer, input: Buffer, signature: Buffer) => {
        return Promise.resolve(true);
    }

    public extract = async (edhoc: EDHOC, keyID: Buffer, salt: Buffer, keySize: number) => {
        return Promise.resolve(Buffer.alloc(keySize));
    }

    public expand = async (edhoc: EDHOC, keyID: Buffer, info: Buffer, keySize: number) => {
        return Promise.resolve(Buffer.alloc(keySize));
    }

    public encrypt = async (edhoc: EDHOC, keyID: Buffer, plaintext: Buffer) => {
        return Promise.resolve(Buffer.alloc(plaintext.length));
    }

    public decrypt = async (edhoc: EDHOC, keyID: Buffer, ciphertext: Buffer) => {
        return Promise.resolve(Buffer.alloc(ciphertext.length));
    }

    public hash = async (edhoc: EDHOC, data: Buffer, hashSize: number) => {
        return Promise.resolve(Buffer.alloc(hashSize));
    }
}
