"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DefaultEdhocCryptoManager = void 0;
const edhoc_1 = require("./edhoc");
const ed25519_1 = require("@noble/curves/ed25519");
const p256_1 = require("@noble/curves/p256");
const sha256_1 = require("@noble/hashes/sha256");
const hkdf_1 = require("@noble/hashes/hkdf");
const crypto_1 = require("crypto");
class DefaultEdhocCryptoManager {
    keys = {};
    keyIdentifier = 1000;
    constructor() {
        this.keys = {};
    }
    addKey(keyID, key) {
        const kid = keyID.toString('hex');
        this.keys[kid] = key;
    }
    async generateKey(edhoc, keyType, key) {
        // Key Identifier
        const keyBuffer = Buffer.alloc(4);
        keyBuffer.writeInt32LE(this.keyIdentifier++);
        const keyID = keyBuffer.toString('hex');
        // Key Exchange Curve
        const curveKE = [edhoc_1.EdhocSuite.Suite2, edhoc_1.EdhocSuite.Suite3, edhoc_1.EdhocSuite.Suite5].includes(edhoc.selectedSuite) ? p256_1.p256 :
            [edhoc_1.EdhocSuite.Suite0, edhoc_1.EdhocSuite.Suite1, edhoc_1.EdhocSuite.Suite4, edhoc_1.EdhocSuite.Suite6].includes(edhoc.selectedSuite) ? ed25519_1.x25519 : null;
        // Signature Curve
        const curveSIG = [edhoc_1.EdhocSuite.Suite2, edhoc_1.EdhocSuite.Suite3, edhoc_1.EdhocSuite.Suite5, edhoc_1.EdhocSuite.Suite6].includes(edhoc.selectedSuite) ? p256_1.p256 :
            [edhoc_1.EdhocSuite.Suite0, edhoc_1.EdhocSuite.Suite1, edhoc_1.EdhocSuite.Suite4].includes(edhoc.selectedSuite) ? ed25519_1.ed25519 : null;
        if (null == curveKE || null == curveSIG) {
            throw new Error('Unsupported suite');
        }
        switch (keyType) {
            case edhoc_1.EdhocKeyType.MakeKeyPair:
                this.keys[keyID] = curveKE.utils.randomPrivateKey();
                break;
            case edhoc_1.EdhocKeyType.KeyAgreement:
                this.keys[keyID] = key.byteLength > 0 ? Buffer.from(key) : curveKE.utils.randomPrivateKey();
                break;
            case edhoc_1.EdhocKeyType.Signature:
                this.keys[keyID] = key.byteLength > 0 ? Buffer.from(key) : curveSIG.utils.randomPrivateKey();
                break;
            default:
                this.keys[keyID] = Buffer.from(key);
        }
        return keyBuffer;
    }
    destroyKey(edhoc, keyID) {
        const kid = keyID.toString('hex');
        if (kid in this.keys === false) {
            throw new Error(`Key '${kid}' not found`);
        }
        delete this.keys[kid];
        return true;
    }
    makeKeyPair(edhoc, keyID, privateKeySize, publicKeySize) {
        const kid = keyID.toString('hex');
        if (kid in this.keys === false) {
            throw new Error(`Key '${kid}' not found`);
        }
        try {
            const curveKE = [edhoc_1.EdhocSuite.Suite2, edhoc_1.EdhocSuite.Suite3, edhoc_1.EdhocSuite.Suite5].includes(edhoc.selectedSuite) ? p256_1.p256 :
                [edhoc_1.EdhocSuite.Suite0, edhoc_1.EdhocSuite.Suite1, edhoc_1.EdhocSuite.Suite4, edhoc_1.EdhocSuite.Suite6].includes(edhoc.selectedSuite) ? ed25519_1.x25519 : null;
            return {
                privateKey: Buffer.from(this.keys[kid]),
                publicKey: Buffer.from(curveKE.getPublicKey(this.keys[kid])).subarray(curveKE === p256_1.p256 ? 1 : 0)
            };
        }
        catch (error) {
            throw new Error(`Wrong key type`);
        }
    }
    keyAgreement(edhoc, keyID, publicKey, privateKeySize) {
        const kid = keyID.toString('hex');
        if (kid in this.keys === false) {
            throw new Error(`Key '${kid}' not found`);
        }
        // Key Exchange Curve
        const curveKE = [edhoc_1.EdhocSuite.Suite2, edhoc_1.EdhocSuite.Suite3, edhoc_1.EdhocSuite.Suite5].includes(edhoc.selectedSuite) ? p256_1.p256 :
            [edhoc_1.EdhocSuite.Suite0, edhoc_1.EdhocSuite.Suite1, edhoc_1.EdhocSuite.Suite4, edhoc_1.EdhocSuite.Suite6].includes(edhoc.selectedSuite) ? ed25519_1.x25519 : null;
        const publicKeyBuffer = (curveKE === p256_1.p256) ? Buffer.concat([Buffer.from([publicKey.byteLength == 64 ? 0x04 : 0x02]), publicKey]) : publicKey;
        const sharedSecrect = Buffer.from(curveKE.getSharedSecret(this.keys[kid], new Uint8Array(publicKeyBuffer)));
        return sharedSecrect.subarray(curveKE === p256_1.p256 ? 1 : 0);
    }
    sign(edhoc, keyID, input, signatureSize) {
        const kid = keyID.toString('hex');
        if (kid in this.keys === false) {
            throw new Error(`Key '${kid}' not found`);
        }
        // Signature Curve
        const curveSIG = [edhoc_1.EdhocSuite.Suite2, edhoc_1.EdhocSuite.Suite3, edhoc_1.EdhocSuite.Suite5, edhoc_1.EdhocSuite.Suite6].includes(edhoc.selectedSuite) ? p256_1.p256 :
            [edhoc_1.EdhocSuite.Suite0, edhoc_1.EdhocSuite.Suite1, edhoc_1.EdhocSuite.Suite4].includes(edhoc.selectedSuite) ? ed25519_1.ed25519 : null;
        if (null === curveSIG) {
            throw new Error('Unsupported suite');
        }
        const signature = curveSIG.sign((0, sha256_1.sha256)(input), new Uint8Array(this.keys[kid]));
        if (signature instanceof Uint8Array) {
            return Buffer.from(signature);
        }
        else if ('toCompactRawBytes' in signature) {
            return Buffer.from(signature.toCompactRawBytes());
        }
        else {
            throw new Error('Unsupported signature type');
        }
    }
    verify(edhoc, keyID, input, signature) {
        const kid = keyID.toString('hex');
        if (kid in this.keys === false) {
            throw new Error(`Key '${kid}' not found`);
        }
        // Signature Curve
        const curveSIG = [edhoc_1.EdhocSuite.Suite2, edhoc_1.EdhocSuite.Suite3, edhoc_1.EdhocSuite.Suite5, edhoc_1.EdhocSuite.Suite6].includes(edhoc.selectedSuite) ? p256_1.p256 :
            [edhoc_1.EdhocSuite.Suite0, edhoc_1.EdhocSuite.Suite1, edhoc_1.EdhocSuite.Suite4].includes(edhoc.selectedSuite) ? ed25519_1.ed25519 : null;
        if (null === curveSIG) {
            throw new Error('Unsupported suite');
        }
        const publicKey = this.keys[kid];
        const publicKeyBuffer = (curveSIG === p256_1.p256) ? Buffer.concat([Buffer.from([publicKey.byteLength == 64 ? 0x04 : 0x02]), publicKey]) : publicKey;
        if (!curveSIG.verify(new Uint8Array(signature), (0, sha256_1.sha256)(input), new Uint8Array(publicKeyBuffer))) {
            throw new Error('Signature not verified');
        }
        return true;
    }
    extract(edhoc, keyID, salt, keySize) {
        const kid = keyID.toString('hex');
        if (kid in this.keys === false) {
            throw new Error(`Key '${kid}' not found`);
        }
        return Buffer.from((0, hkdf_1.extract)(sha256_1.sha256, new Uint8Array(this.keys[kid]), new Uint8Array(salt)));
    }
    expand(edhoc, keyID, info, keySize) {
        const kid = keyID.toString('hex');
        if (kid in this.keys === false) {
            throw new Error(`Key '${kid}' not found`);
        }
        const expanded = Buffer.from((0, hkdf_1.expand)(sha256_1.sha256, new Uint8Array(this.keys[kid]), new Uint8Array(info), keySize));
        return expanded;
    }
    encrypt(edhoc, keyID, nonce, aad, plaintext, size) {
        const kid = keyID.toString('hex');
        if (kid in this.keys === false) {
            throw new Error(`Key '${kid}' not found`);
        }
        const tagLength = [edhoc_1.EdhocSuite.Suite0, edhoc_1.EdhocSuite.Suite2].includes(edhoc.selectedSuite) ? 8 : 16;
        const algorithm = [edhoc_1.EdhocSuite.Suite4, edhoc_1.EdhocSuite.Suite5].includes(edhoc.selectedSuite) ? 'chacha20-poly1305' :
            [edhoc_1.EdhocSuite.Suite6].includes(edhoc.selectedSuite) ? 'aes-128-gcm' : 'aes-128-ccm';
        const cipher = (0, crypto_1.createCipheriv)(algorithm, this.keys[kid], nonce, { authTagLength: tagLength });
        cipher.setAAD(aad, { plaintextLength: Buffer.byteLength(plaintext) });
        const encrypted = Buffer.concat([
            cipher.update(plaintext),
            cipher.final(),
            cipher.getAuthTag()
        ]);
        return encrypted;
    }
    decrypt(edhoc, keyID, nonce, aad, ciphertext, size) {
        const kid = keyID.toString('hex');
        if (kid in this.keys === false) {
            throw new Error(`Key '${kid}' not found`);
        }
        const tagLength = [edhoc_1.EdhocSuite.Suite0, edhoc_1.EdhocSuite.Suite2].includes(edhoc.selectedSuite) ? 8 : 16;
        const algorithm = [edhoc_1.EdhocSuite.Suite4, edhoc_1.EdhocSuite.Suite5].includes(edhoc.selectedSuite) ? 'chacha20-poly1305' :
            [edhoc_1.EdhocSuite.Suite6].includes(edhoc.selectedSuite) ? 'aes-128-gcm' : 'aes-128-ccm';
        const decipher = (0, crypto_1.createDecipheriv)(algorithm, this.keys[kid], nonce, { authTagLength: tagLength });
        decipher.setAuthTag(ciphertext.subarray(ciphertext.length - tagLength));
        decipher.setAAD(aad, { plaintextLength: ciphertext.length - tagLength });
        let decrypted = decipher.update(ciphertext.subarray(0, ciphertext.length - tagLength));
        decipher.final();
        return decrypted;
    }
    async hash(edhoc, data, hashSize) {
        return Buffer.from((0, sha256_1.sha256)(data));
    }
}
exports.DefaultEdhocCryptoManager = DefaultEdhocCryptoManager;
