import { EDHOC, EdhocCryptoManager, EdhocKeyType, EdhocSuite } from './edhoc';
import { ed25519, x25519 } from '@noble/curves/ed25519';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { extract, expand } from '@noble/hashes/hkdf';
import { RecoveredSignatureType } from '@noble/curves/abstract/weierstrass';
import { createCipheriv, createDecipheriv, CipherCCM, CipherGCM, DecipherCCM, DecipherGCM } from 'crypto';

type KeyEntry = {
    [key: string]: Buffer;
};

type KeyUtils = {
    utils: any;
    getPublicKey: (privateKey: Uint8Array, compressed?: boolean) => Uint8Array;
    getSharedSecret?: (privateKey: Uint8Array, publicKey: Uint8Array) => Uint8Array;
    sign?: (msg: Uint8Array, privateKey: Uint8Array) => Uint8Array | RecoveredSignatureType;
    verify?: (signature: Uint8Array, msgHash: Uint8Array, publicKey: Uint8Array) => boolean;
};

export class DefaultEdhocCryptoManager implements EdhocCryptoManager {

    private keys: KeyEntry = { };
    private keyIdentifier: number = 1000;

    constructor() {
        this.keys = { };
    }

    public addKey(keyID: Buffer, key: Buffer) {
        const kid = keyID.toString('hex');
        this.keys[kid] = key;
    }

    async importKey(edhoc: EDHOC, keyType: EdhocKeyType, key: Buffer) {
        const keyBuffer = Buffer.alloc(4);
        keyBuffer.writeInt32LE(this.keyIdentifier++);
        const keyID = keyBuffer.toString('hex');

        const curveKE: KeyUtils = this.getCurveForKeyAgreement(edhoc.selectedSuite);
        const curveSIG: KeyUtils = this.getCurveForSignature(edhoc.selectedSuite);

        switch (keyType) {
            case EdhocKeyType.MakeKeyPair:
                this.keys[keyID] = curveKE.utils.randomPrivateKey();
                break;
            case EdhocKeyType.KeyAgreement:
                this.keys[keyID] = key.byteLength > 0 ? Buffer.from(key) : curveKE.utils.randomPrivateKey();
                break;
            case EdhocKeyType.Signature:
                this.keys[keyID] = key.byteLength > 0 ? Buffer.from(key) : curveSIG.utils.randomPrivateKey()
                break;
            default:
                this.keys[keyID] = Buffer.from(key);
        }
        return keyBuffer;
    }

    destroyKey(edhoc: EDHOC, keyID: Buffer) {
        const kid = keyID.toString('hex');
        if (kid in this.keys === false) {
            throw new Error(`Key '${kid}' not found`);
        }
        delete this.keys[kid];
        return true;
    }

    makeKeyPair(edhoc: EDHOC, keyID: Buffer, privateKeySize: number, publicKeySize: number) {
        const key = this.getKey(keyID);
        
        try {
            const curveKE: KeyUtils = this.getCurveForKeyAgreement(edhoc.selectedSuite);
            return {
                privateKey: Buffer.from(key),
                publicKey: Buffer.from(curveKE!.getPublicKey(key)).subarray(curveKE === p256 ? 1 : 0)
            };
        }
        catch (error) {
            throw new Error(`Wrong key type`);
        }
    }

    keyAgreement(edhoc: EDHOC, keyID: Buffer, publicKey: Buffer, privateKeySize: number) {
        const key = this.getKey(keyID);
        const curveKE: KeyUtils = this.getCurveForKeyAgreement(edhoc.selectedSuite);
        const publicKeyBuffer = (curveKE === p256) ? Buffer.concat([Buffer.from([publicKey.byteLength == 64 ? 0x04 : 0x02]), publicKey]) : publicKey;
        const sharedSecrect = Buffer.from(curveKE!.getSharedSecret!(key, new Uint8Array(publicKeyBuffer)));
        return sharedSecrect.subarray(curveKE === p256 ? 1 : 0);
    }

    sign(edhoc: EDHOC, keyID: Buffer, input: Buffer, signatureSize: number) {
        const key = this.getKey(keyID);
        const curveSIG: KeyUtils = this.getCurveForSignature(edhoc.selectedSuite);
        const signature = curveSIG.sign!(sha256(input), new Uint8Array(key));
        
        if (signature instanceof Uint8Array) {
            return Buffer.from(signature);
        }
        else if ('toCompactRawBytes' in signature) {
            return Buffer.from((signature as RecoveredSignatureType).toCompactRawBytes());
        }
        else {
            throw new Error('Unsupported signature type');
        }
    }

    async verify(edhoc: EDHOC, keyID: Buffer, input: Buffer, signature: Buffer): Promise<boolean> {
        await new Promise(resolve => setTimeout(resolve, 1));
        throw new Error('Not implemented');
        const key = this.getKey(keyID);

        // Signature Curve
        const curveSIG: KeyUtils = this.getCurveForSignature(edhoc.selectedSuite);
        const publicKeyBuffer = (curveSIG === p256) ? 
            Buffer.concat([Buffer.from([key.byteLength == 64 ? 0x04 : 0x02]), key]) : key;

        if (!curveSIG.verify!(new Uint8Array(signature), sha256(input), new Uint8Array(publicKeyBuffer))) {
            throw new Error('Signature not verified');
        }
        
        return true;
    }

    extract(edhoc: EDHOC, keyID: Buffer, salt: Buffer, keySize: number) {
        const key = this.getKey(keyID);
        return Buffer.from(extract(sha256, new Uint8Array(key), new Uint8Array(salt)));
    }

    expand(edhoc: EDHOC, keyID: Buffer, info: Buffer, keySize: number) {
        const key = this.getKey(keyID);
        const expanded =  Buffer.from(expand(sha256, new Uint8Array(key), new Uint8Array(info), keySize));
        return expanded;
    }

    encrypt(edhoc: EDHOC, keyID: Buffer, nonce: Buffer, aad: Buffer, plaintext: Buffer, size: number) {
        const key = this.getKey(keyID);
        const tagLength = this.getTagLength(edhoc.selectedSuite);
        const algorithm = this.getAlgorithm(edhoc.selectedSuite);

        const cipher = createCipheriv(algorithm, key, nonce, { authTagLength: tagLength } as any) as CipherCCM | CipherGCM; 
        cipher.setAAD(aad, { plaintextLength: Buffer.byteLength(plaintext) });

        const encrypted = Buffer.concat([
            cipher.update(plaintext), 
            cipher.final(), 
            cipher.getAuthTag()
        ]);
        return encrypted;
    }

    decrypt(edhoc: EDHOC, keyID: Buffer, nonce: Buffer, aad: Buffer, ciphertext: Buffer, size: number) {
        const key = this.getKey(keyID);
        const tagLength = this.getTagLength(edhoc.selectedSuite);
        const algorithm = this.getAlgorithm(edhoc.selectedSuite);

        const decipher = createDecipheriv(algorithm, key, nonce, { authTagLength: tagLength } as any) as DecipherCCM | DecipherGCM; 
        
        decipher.setAuthTag(ciphertext.subarray(ciphertext.length - tagLength));
        decipher.setAAD(aad, { plaintextLength: ciphertext.length - tagLength });
        
        let decrypted = decipher.update(ciphertext.subarray(0, ciphertext.length - tagLength));
        decipher.final();

        return decrypted;
    }

    async hash(edhoc: EDHOC, data: Buffer, hashSize: number) {
        return Buffer.from(sha256(data));
    }

    private getKey(keyID: Buffer): Buffer {
        const kid = keyID.toString('hex');
        if (kid in this.keys === false) {
            throw new Error(`Key '${kid}' not found`);
        }
        return this.keys[kid];
    }

    private getCurveForSignature(suite: EdhocSuite): KeyUtils {
        if ([EdhocSuite.Suite2, EdhocSuite.Suite3, EdhocSuite.Suite5, EdhocSuite.Suite6].includes(suite)) {
            return p256;
        }
        else if ([EdhocSuite.Suite0, EdhocSuite.Suite1, EdhocSuite.Suite4].includes(suite)) {
            return ed25519;
        }
        else {
            throw new Error(`Unsupported EDHOC suite ${suite} for signature.`);
        }
    }

    private getCurveForKeyAgreement(suite: EdhocSuite): KeyUtils {
        if ([EdhocSuite.Suite2, EdhocSuite.Suite3, EdhocSuite.Suite5].includes(suite)) {
            return p256;
        }
        else if ([EdhocSuite.Suite0, EdhocSuite.Suite1, EdhocSuite.Suite4, EdhocSuite.Suite6].includes(suite)) {
            return x25519;
        }
        else {
            throw new Error(`Unsupported EDHOC suite ${suite} for key agreement.`);
        }
    }

    private getTagLength(suite: EdhocSuite): number {
        return [EdhocSuite.Suite0, EdhocSuite.Suite2].includes(suite) ? 8 : 16;
    }

    private getAlgorithm(suite: EdhocSuite): string {
        if ([EdhocSuite.Suite4, EdhocSuite.Suite5, EdhocSuite.Suite25].includes(suite)) {
            return 'chacha20-poly1305';
        }
        else if ([EdhocSuite.Suite6].includes(suite)) {
            return 'aes-128-gcm';
        }
        else if ([EdhocSuite.Suite24].includes(suite)) {
            return 'aes-256-gcm';
        }
        else if ([EdhocSuite.Suite0, EdhocSuite.Suite1, EdhocSuite.Suite2, EdhocSuite.Suite3].includes(suite)) {
            return 'aes-128-ccm';
        }
        else {
            throw new Error(`Unsupported EDHOC suite ${suite} for encryption.`);
        }
    }
}
