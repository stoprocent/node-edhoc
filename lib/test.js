const addon = require('../build/Debug/bindings');
const { subtle } = require('crypto').webcrypto;
const { createECDH, createHash } = require('crypto');
const hkdf = require('futoin-hkdf');

const EDHOC_KEY_TYPE = Object.freeze({
    EDHOC_KT_MAKE_KEY_PAIR: 0,
    EDHOC_KT_KEY_AGREEMENT: 1,
    EDHOC_KT_SIGNATURE: 2,
    EDHOC_KT_VERIFY: 3,
    EDHOC_KT_EXTRACT: 4,
    EDHOC_KT_EXPAND: 5,
    EDHOC_KT_ENCRYPT: 6,
    EDHOC_KT_DECRYPT: 7
});

async function run() {
    var currentKey = 100;
    var keysContainer = {};

    const crypto = new addon.EdhocCryptoManager();

    keysContainer['01020304'] = await subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, true, ["sign", "verify"]);

    keysContainer['01020304'] = createECDH('secp256k1');
    keysContainer['01020304'].generateKeys();

    crypto.setGenerateKey((key_type, key) => {
        console.log("setGenerateKey", key_type, key);
        
        currentKey++;
        const keyID = Buffer.alloc(4);
        keyID.writeInt32LE(currentKey);
        const keyIDKey = keyID.toString('hex');
        
        switch (key_type) {
            case EDHOC_KEY_TYPE.EDHOC_KT_MAKE_KEY_PAIR:
                keysContainer[keyIDKey] = createECDH('secp256k1');
                keysContainer[keyIDKey].generateKeys();
                return keyID;
            case EDHOC_KEY_TYPE.EDHOC_KT_KEY_AGREEMENT:
                keysContainer[keyIDKey] = createECDH('secp256k1');
                keysContainer[keyIDKey].setPrivateKey(key, 'hex');
                return keyID;
            case EDHOC_KEY_TYPE.EDHOC_KT_VERIFY:
                keysContainer[keyIDKey] = createECDH('secp256k1');
                keysContainer[keyIDKey].setPrivateKey("816bfd44ba11ac706089399f558a00a7c6ff0fab251bb4de6aa223519a3d4a0c", 'hex');
                console.log("Public Key", keysContainer[keyIDKey].getPublicKey('hex', 'compressed'));
                return keyID;
            case EDHOC_KEY_TYPE.EDHOC_KT_EXTRACT:
            case EDHOC_KEY_TYPE.EDHOC_KT_EXPAND:
                keysContainer[keyIDKey] = key;
                return keyID;
            default:
                return 0;
        }    
    });

    crypto.setDestroyKey((key_id) => {
        const keyID = key_id.toString('hex');
        console.log("setDestroyKey", key_id, keyID);
        if (keyID in keysContainer) {
            delete keysContainer[keyID];
            return true;
        }
        return false;
    });

    crypto.setMakeKeyPair((key_id, priv_key_size, pub_key_size) => {
        const keyID = key_id.toString('hex');
        console.log("setMakeKeyPair", key_id, keyID, priv_key_size, pub_key_size);
        console.log(keysContainer);
        if (keyID in keysContainer) {
            return [
                keysContainer[keyID].getPrivateKey(),
                Buffer.from(keysContainer[keyID].getPublicKey('hex', 'compressed'), 'hex').subarray(1)
            ];
        }
        throw new Error("Key not found");
    });

    crypto.setKeyAgreement((key_id, pub_key, size) => {
        const keyID = key_id.toString('hex');
        console.log("setKeyAgreement", key_id, keyID, pub_key, size);
        if (keyID in keysContainer) {
            const pubKey = Buffer.concat([Buffer.from([0x03]), pub_key]);
            return keysContainer[keyID].computeSecret(pubKey);
        }
        throw new Error("Key not found");
    });

    crypto.setSign(async (key_id, input, size) => {
        const keyID = key_id.toString('hex');
        console.log("setSign", key_id, keyID, input, size);

        if (keyID in keysContainer) {
            let signature = Buffer.from(await subtle.sign({ name: 'ECDSA', hash: { name: "SHA-256" } }, keysContainer[keyID].privateKey, input));
            console.log("Signature", signature);
            return signature;
        }
        throw new Error("Key not found");
    });

    crypto.setExtract((key_id, salt, size) => {
        const keyID = key_id.toString('hex');
        console.log("setExtract", key_id, salt, size);
        if (keyID in keysContainer) {
            return hkdf.extract('sha256', hkdf.hash_length('sha256'), keysContainer[keyID], salt);
        }
        throw new Error("Key not found");
    });

    crypto.setExpand((key_id, info, size) => {
        const keyID = key_id.toString('hex');
        console.log("setExpand", key_id, info, size);
        if (keyID in keysContainer) {
            return hkdf.expand('sha256', hkdf.hash_length('sha256'), keysContainer[keyID], size, info);
        }
        throw new Error("Key not found");
    });

    crypto.setHash(async (data, size) => {
        console.log("setHash", data, size);
        return createHash('sha256').update(data).digest();
    });


    const credentials = {
        fetch: (...args) => {
            console.log("fetch", args);
        },
        verify: (...args) => {
            console.log(args);
        }
    }

    const ead = {
        compose: (message, size) => {
            console.log("ead.compose", message, size);
            if (message === 0) {
                return [
                    [1000, Buffer.from([0x01, 0x02, 0x03, 0x04])],
                    [1001, Buffer.from([0x05, 0x06, 0x07, 0x08, 0x09])],
                ];
            }
        },
        process: (eads) => {
            console.log("ead.process", eads);
        }
    }

    const initiator = new addon.LibEDHOC(122340, 3, credentials, ead, crypto);
    const responder = new addon.LibEDHOC(20, 3, credentials, ead, crypto);
    
    try {
        // Initiator
        let message1 = await initiator.composeMessage1();
        console.log("Message 1", message1.toString('hex'));
        
        // Responder
        let c_i = await responder.processMessage1(message1);
        console.log("Message 1 - C_I", c_i);
        
        let message2 = await responder.composeMessage2();
        console.log("Message 2", message2.toString('hex'));

        // Initiator
        let c_r = await initiator.processMessage2(message2);
        console.log("Message 2 - C_R", c_r);    
    }
    catch (e) {
        console.log(e);
    }
}
run();