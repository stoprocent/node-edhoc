import { EDHOC, EdhocCryptoManager, EdhocSuite, PublicPrivateTuple } from './edhoc';
import { ed25519, x25519 } from '@noble/curves/ed25519';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { extract, expand } from '@noble/hashes/hkdf';
import { RecoveredSignatureType } from '@noble/curves/abstract/weierstrass';
import { createCipheriv, createDecipheriv, CipherCCM, CipherGCM, DecipherCCM, DecipherGCM, CipherCCMOptions, CipherGCMOptions } from 'crypto';

type KeyUtils = {
    utils: { randomPrivateKey: () => Uint8Array };
    getPublicKey: (privateKey: Uint8Array, compressed?: boolean) => Uint8Array;
    getSharedSecret?: (privateKey: Uint8Array, publicKey: Uint8Array) => Uint8Array;
    sign?: (msg: Uint8Array, privateKey: Uint8Array) => Uint8Array | RecoveredSignatureType;
    verify?: (signature: Uint8Array, msgHash: Uint8Array, publicKey: Uint8Array) => boolean;
};

export class DefaultEdhocCryptoManager implements EdhocCryptoManager {

    generateKeyPair(edhoc: EDHOC): PublicPrivateTuple {
        const curveKE: KeyUtils = this.getCurveForKeyAgreement(edhoc.selectedSuite);
        const privateKey = Buffer.from(curveKE.utils.randomPrivateKey());
        const publicKey = Buffer.from(curveKE.getPublicKey(privateKey)).subarray(curveKE === p256 ? 1 : 0);
        return { publicKey, privateKey };
    }

    keyAgreement(edhoc: EDHOC, privateKey: Buffer, peerPublicKey: Buffer) {
        const curveKE: KeyUtils = this.getCurveForKeyAgreement(edhoc.selectedSuite);
        const publicKeyBuffer = this.formatPublicKey(curveKE, peerPublicKey);
        const sharedSecret = Buffer.from(curveKE!.getSharedSecret!(privateKey, new Uint8Array(publicKeyBuffer)));
        return sharedSecret.subarray(curveKE === p256 ? 1 : 0);
    }

    sign(edhoc: EDHOC, privateKey: Buffer, input: Buffer) {
        const curveSIG: KeyUtils = this.getCurveForSignature(edhoc.selectedSuite);
        const payload = this.formatToBeSigned(curveSIG, input);
        const signature = curveSIG.sign!(payload, new Uint8Array(privateKey));

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

    async verify(edhoc: EDHOC, publicKey: Buffer, input: Buffer, signature: Buffer): Promise<boolean> {
        const curveSIG: KeyUtils = this.getCurveForSignature(edhoc.selectedSuite);
        const publicKeyBuffer = this.formatPublicKey(curveSIG, publicKey);
        const payload = this.formatToBeSigned(curveSIG, input);

        if (!curveSIG.verify!(new Uint8Array(signature), payload, new Uint8Array(publicKeyBuffer))) {
            throw new Error('Signature not verified');
        }

        return true;
    }

    hkdfExtract(_edhoc: EDHOC, ikm: Buffer, salt: Buffer) {
        return Buffer.from(extract(sha256, new Uint8Array(ikm), new Uint8Array(salt)));
    }

    hkdfExpand(_edhoc: EDHOC, prk: Buffer, info: Buffer, length: number) {
        return Buffer.from(expand(sha256, new Uint8Array(prk), new Uint8Array(info), length));
    }

    async encrypt(edhoc: EDHOC, key: Buffer, nonce: Buffer, aad: Buffer, plaintext: Buffer): Promise<Buffer> {
        const algorithm = this.getAlgorithm(edhoc.selectedSuite);
        const options: CipherCCMOptions | CipherGCMOptions = {
            authTagLength: this.getTagLength(edhoc.selectedSuite)
        };

        const cipher = createCipheriv(algorithm, key, nonce, options) as CipherCCM | CipherGCM;
        cipher.setAAD(aad, { plaintextLength: Buffer.byteLength(plaintext) });

        const update = Buffer.byteLength(plaintext) === 0 ? Buffer.alloc(0) : plaintext;
        const encrypted = Buffer.concat([
            cipher.update(update),
            cipher.final(),
            cipher.getAuthTag()
        ]);
        return encrypted;
    }

    async decrypt(edhoc: EDHOC, key: Buffer, nonce: Buffer, aad: Buffer, ciphertext: Buffer): Promise<Buffer> {
        const tagLength = this.getTagLength(edhoc.selectedSuite);
        const algorithm = this.getAlgorithm(edhoc.selectedSuite);

        const options: CipherCCMOptions | CipherGCMOptions = { authTagLength: tagLength };
        const decipher = createDecipheriv(algorithm, key, nonce, options) as DecipherCCM | DecipherGCM;

        decipher.setAuthTag(ciphertext.subarray(ciphertext.length - tagLength));
        decipher.setAAD(aad, { plaintextLength: ciphertext.length - tagLength });

        const decrypted = decipher.update(ciphertext.subarray(0, ciphertext.length - tagLength));
        decipher.final();

        return decrypted;
    }

    async hash(_edhoc: EDHOC, input: Buffer) {
        return Buffer.from(sha256(input));
    }

    private formatToBeSigned(curve: KeyUtils, payload: Buffer): Buffer {
        if (curve === p256) {
            return Buffer.from(sha256(payload));
        }
        else if (curve === ed25519) {
            return payload;
        }
        else {
            throw new Error(`Unsupported curve ${curve}`);
        }
    }

    private formatPublicKey(curve: KeyUtils, key: Buffer): Buffer {
        if (curve === p256) {
            const prefix = key.byteLength === 64 ? 0x04 : (key[key.length - 1] & 1) ? 0x03 : 0x02;
            return Buffer.concat([Buffer.from([prefix]), key]);
        }
        else if (curve === ed25519 || curve === x25519) {
            return key;
        }
        else {
            throw new Error(`Unsupported curve ${curve}`);
        }
    }

    protected getCurveForSignature(suite: EdhocSuite): KeyUtils {
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

    protected getCurveForKeyAgreement(suite: EdhocSuite): KeyUtils {
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
