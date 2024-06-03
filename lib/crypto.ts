import { EDHOC, EdhocCryptoManager, EdhocKeyType, EdhocSuite } from './edhoc';
import { ed25519, ed25519ph, ed25519ctx, x25519, edwardsToMontgomeryPriv } from '@noble/curves/ed25519';
import { ed448, ed448ph, x448 } from '@noble/curves/ed448';
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

    async generateKey(edhoc: EDHOC, keyType: EdhocKeyType, key: Buffer) {

        // Key Identifier
        const keyBuffer = Buffer.alloc(4);
        keyBuffer.writeInt32LE(this.keyIdentifier++);
        const keyID = keyBuffer.toString('hex');

        // Key Exchange Curve
        const curveKE: KeyUtils | null = 
            [EdhocSuite.Suite2, EdhocSuite.Suite3, EdhocSuite.Suite5].includes(edhoc.selectedSuite) ? p256 : 
            [EdhocSuite.Suite0, EdhocSuite.Suite1, EdhocSuite.Suite4, EdhocSuite.Suite6].includes(edhoc.selectedSuite) ? x25519 : null;

        // Signature Curve
        const curveSIG: KeyUtils | null = 
            [EdhocSuite.Suite2, EdhocSuite.Suite3, EdhocSuite.Suite5, EdhocSuite.Suite6].includes(edhoc.selectedSuite) ? p256 :
            [EdhocSuite.Suite0, EdhocSuite.Suite1, EdhocSuite.Suite4].includes(edhoc.selectedSuite) ? ed25519 : null;

        if (null == curveKE || null == curveSIG) {
            throw new Error('Unsupported suite');
        }

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
        const kid = keyID.toString('hex');
        if (kid in this.keys === false) {
            throw new Error(`Key '${kid}' not found`);
        }
        
        try {
            const curveKE: KeyUtils | null = 
                [EdhocSuite.Suite2, EdhocSuite.Suite3, EdhocSuite.Suite5].includes(edhoc.selectedSuite) ? p256 : 
                [EdhocSuite.Suite0, EdhocSuite.Suite1, EdhocSuite.Suite4, EdhocSuite.Suite6].includes(edhoc.selectedSuite) ? x25519 : null;
            return {
                privateKey: Buffer.from(this.keys[kid]),
                publicKey: Buffer.from(curveKE!.getPublicKey(this.keys[kid])).subarray(curveKE === p256 ? 1 : 0)
            };
        }
        catch (error) {
            throw new Error(`Wrong key type`);
        }
    }

    keyAgreement(edhoc: EDHOC, keyID: Buffer, publicKey: Buffer, privateKeySize: number) {
        
        const kid = keyID.toString('hex');
        if (kid in this.keys === false) {
            throw new Error(`Key '${kid}' not found`);
        }
                
        // Key Exchange Curve
        const curveKE: KeyUtils | null = 
        [EdhocSuite.Suite2, EdhocSuite.Suite3, EdhocSuite.Suite5].includes(edhoc.selectedSuite) ? p256 : 
        [EdhocSuite.Suite0, EdhocSuite.Suite1, EdhocSuite.Suite4, EdhocSuite.Suite6].includes(edhoc.selectedSuite) ? x25519 : null;
        
        const publicKeyBuffer = (curveKE === p256) ? Buffer.concat([Buffer.from([publicKey.byteLength == 64 ? 0x04 : 0x02]), publicKey]) : publicKey;
        const sharedSecrect = Buffer.from(curveKE!.getSharedSecret!(this.keys[kid], new Uint8Array(publicKeyBuffer)));
        return sharedSecrect.subarray(curveKE === p256 ? 1 : 0);
    }

    sign(edhoc: EDHOC, keyID: Buffer, input: Buffer, signatureSize: number) {
        const kid = keyID.toString('hex');
        if (kid in this.keys === false) {
            throw new Error(`Key '${kid}' not found`);
        }

        // Signature Curve
        const curveSIG: KeyUtils | null = 
            [EdhocSuite.Suite2, EdhocSuite.Suite3, EdhocSuite.Suite5, EdhocSuite.Suite6].includes(edhoc.selectedSuite) ? p256 :
            [EdhocSuite.Suite0, EdhocSuite.Suite1, EdhocSuite.Suite4].includes(edhoc.selectedSuite) ? ed25519 : null;

        if (null === curveSIG) {
            throw new Error('Unsupported suite');
        }

        const signature = curveSIG.sign!(sha256(input), new Uint8Array(this.keys[kid]));
        
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

    verify(edhoc: EDHOC, keyID: Buffer, input: Buffer, signature: Buffer) {
        const kid = keyID.toString('hex');
        if (kid in this.keys === false) {
            throw new Error(`Key '${kid}' not found`);
        }

        // Signature Curve
        const curveSIG: KeyUtils | null = 
            [EdhocSuite.Suite2, EdhocSuite.Suite3, EdhocSuite.Suite5, EdhocSuite.Suite6].includes(edhoc.selectedSuite) ? p256 :
            [EdhocSuite.Suite0, EdhocSuite.Suite1, EdhocSuite.Suite4].includes(edhoc.selectedSuite) ? ed25519 : null;

        if (null === curveSIG) {
            throw new Error('Unsupported suite');
        }
        const publicKey = this.keys[kid];
        const publicKeyBuffer = (curveSIG === p256) ? Buffer.concat([Buffer.from([publicKey.byteLength == 64 ? 0x04 : 0x02]), publicKey]) : publicKey;

        if (!curveSIG.verify!(new Uint8Array(signature), sha256(input), new Uint8Array(publicKeyBuffer))) {
            throw new Error('Signature not verified');
        }
        
        return true;
    }

    extract(edhoc: EDHOC, keyID: Buffer, salt: Buffer, keySize: number) {
        const kid = keyID.toString('hex');
        if (kid in this.keys === false) {
            throw new Error(`Key '${kid}' not found`);
        }
        return Buffer.from(extract(sha256, new Uint8Array(this.keys[kid]), new Uint8Array(salt)));
    }

    expand(edhoc: EDHOC, keyID: Buffer, info: Buffer, keySize: number) {
        const kid = keyID.toString('hex');
        if (kid in this.keys === false) {
            throw new Error(`Key '${kid}' not found`);
        }
        const expanded =  Buffer.from(expand(sha256, new Uint8Array(this.keys[kid]), new Uint8Array(info), keySize));
        return expanded;
    }

    encrypt(edhoc: EDHOC, keyID: Buffer, nonce: Buffer, aad: Buffer, plaintext: Buffer, size: number) {
        const kid = keyID.toString('hex');
        if (kid in this.keys === false) {
            throw new Error(`Key '${kid}' not found`);
        }
        
        const tagLength = [EdhocSuite.Suite0, EdhocSuite.Suite2].includes(edhoc.selectedSuite) ? 8 : 16;
        const algorithm = [EdhocSuite.Suite4, EdhocSuite.Suite5].includes(edhoc.selectedSuite) ? 'chacha20-poly1305' : 
            [EdhocSuite.Suite6].includes(edhoc.selectedSuite) ? 'aes-128-gcm' : 'aes-128-ccm';

        const cipher = createCipheriv(algorithm, this.keys[kid], nonce, { authTagLength: tagLength } as any) as CipherCCM | CipherGCM; 
        cipher.setAAD(aad, { plaintextLength: Buffer.byteLength(plaintext) });

        const encrypted = Buffer.concat([
            cipher.update(plaintext), 
            cipher.final(), 
            cipher.getAuthTag()
        ]);
        return encrypted;
    }

    decrypt(edhoc: EDHOC, keyID: Buffer, nonce: Buffer, aad: Buffer, ciphertext: Buffer, size: number) {
        const kid = keyID.toString('hex');
        if (kid in this.keys === false) {
            throw new Error(`Key '${kid}' not found`);
        }
        
        const tagLength = [EdhocSuite.Suite0, EdhocSuite.Suite2].includes(edhoc.selectedSuite) ? 8 : 16;
        const algorithm = [EdhocSuite.Suite4, EdhocSuite.Suite5].includes(edhoc.selectedSuite) ? 'chacha20-poly1305' : 
            [EdhocSuite.Suite6].includes(edhoc.selectedSuite) ? 'aes-128-gcm' : 'aes-128-ccm';

        const decipher = createDecipheriv(algorithm, this.keys[kid], nonce, { authTagLength: tagLength } as any) as DecipherCCM | DecipherGCM; 
        
        decipher.setAuthTag(ciphertext.subarray(ciphertext.length - tagLength));
        decipher.setAAD(aad, { plaintextLength: ciphertext.length - tagLength });
        
        let decrypted = decipher.update(ciphertext.subarray(0, ciphertext.length - tagLength));
        decipher.final();

        return decrypted;
    }

    async hash(edhoc: EDHOC, data: Buffer, hashSize: number) {
        return Buffer.from(sha256(data));
    }
}
