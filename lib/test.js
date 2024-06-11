const addon = require('../build/Debug/bindings');
const { subtle } = require('crypto').webcrypto;
const { createHash, createCipheriv } = require('crypto');
const hkdf = require('futoin-hkdf');
var EC = require('elliptic').ec;
const coap = require('coap');

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

const DEREncodedSignature = (signature) => {
    console.log(signature.toString("hex"))
    if (signature.length !== 64) throw new Error('Wrong signature length');

    let r = signature.slice(0, 32);
    let s = signature.slice(32);

    r = r[0] < 0x80 ? r :  Buffer.concat([Buffer.from([0x00]), r]);
    s = s[0] < 0x80 ? s : Buffer.concat([Buffer.from([0x00]), s]);

    let firstPart = Buffer.alloc(4);
    firstPart.writeUInt8(0x30);
    firstPart.writeUInt8(r.length + s.length + 4, 1);
    firstPart.writeUInt8(0x02, 2);
    firstPart.writeUInt8(r.length, 3);

    firstPart = Buffer.concat([firstPart, r]);
    
    let secondPart = Buffer.alloc(2);
    secondPart.writeInt8(0x02);
    secondPart.writeInt8(s.length, 1);
    
    let finalSignature = Buffer.concat([firstPart, secondPart, s]);
    
    return finalSignature;
}

async function run() {
    var currentKey = 100;
    var keysContainer = {};

    var ec = new EC('p256');

    const crypto = new addon.EdhocCryptoManager();

    keysContainer['01020304'] = ec.keyFromPrivate(Buffer.from('FB13ADEB6518CEE5F88417660841142E830A81FE334380A953406A1305E8706B', 'hex'));

    crypto.setGenerateKey((key_type, key) => {
        console.log("setGenerateKey", key_type, key);
        
        currentKey++;
        const keyID = Buffer.alloc(4);
        keyID.writeInt32LE(currentKey);
        const keyIDKey = keyID.toString('hex');
        
        switch (key_type) {
            case EDHOC_KEY_TYPE.EDHOC_KT_MAKE_KEY_PAIR:
                keysContainer[keyIDKey] = ec.genKeyPair();
                return keyID;
            case EDHOC_KEY_TYPE.EDHOC_KT_KEY_AGREEMENT:
                keysContainer[keyIDKey] = ec.keyFromPrivate(key);
                return keyID;
            case EDHOC_KEY_TYPE.EDHOC_KT_VERIFY:
                keysContainer[keyIDKey] = ec.keyFromPublic(Buffer.concat([Buffer.from([0x04]), key]));
                return keyID;
            case EDHOC_KEY_TYPE.EDHOC_KT_ENCRYPT:
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

            console.log([
                keysContainer[keyID].getPrivate().toBuffer(),
                Buffer.from(keysContainer[keyID].getPublic(false, 'array')),
                Buffer.from(keysContainer[keyID].getPublic(true, 'array')).subarray(1)
            ])
            return [
                keysContainer[keyID].getPrivate().toBuffer(),
                Buffer.from(keysContainer[keyID].getPublic(true, 'array')).subarray(1)
            ];
        }
        throw new Error("Key not found");
    });

    crypto.setKeyAgreement((key_id, pub_key, size) => {
        const keyID = key_id.toString('hex');
        console.log("setKeyAgreement", key_id, keyID, pub_key, size);
        console.log("Our Private Key:", keysContainer[keyID].getPrivate().toString('hex'))
        console.log("Our Public Key:", keysContainer[keyID].getPublic(false, 'hex'))
        console.log("Their Public Key:", pub_key.toString('hex'));
        if (keyID in keysContainer) {
            let pubKey;
            let sharedKey;
            try {
                pubKey = ec.keyFromPublic(Buffer.concat([Buffer.from([0x02]), pub_key]));
                sharedKey = keysContainer[keyID].derive(pubKey.getPublic()).toBuffer();
            }
            catch {
                pubKey = ec.keyFromPublic(Buffer.concat([Buffer.from([0x03]), pub_key]));
                sharedKey = keysContainer[keyID].derive(pubKey.getPublic()).toBuffer();
            }

            console.log("Shared Key", sharedKey.toString('hex'));

            return sharedKey
        }
        throw new Error("Key not found");
    });

    crypto.setSign(async (key_id, input, size) => {
        const keyID = key_id.toString('hex');
        console.log("setSign", key_id, keyID, input, size);

        if (keyID in keysContainer) {
            const input_hash = createHash('sha256').update(input).digest();
            let signature = keysContainer[keyID].sign(input_hash);
            let signatureData = Buffer.concat([signature.r.toBuffer(), signature.s.toBuffer()]);

            console.log("Signature", signatureData);
            return signatureData;
        }
        throw new Error("Key not found");
    });

    crypto.setVerify(async (key_id, input, signature) => {
        const keyID = key_id.toString('hex');
        console.log("setVerify", key_id, keyID);
        console.log("Input", input.toString('hex'));
        console.log("Signature", signature.toString('hex'));
        const signatureR = signature.slice(0, signature.length / 2);
        const signatureS = signature.slice(signature.length / 2);
        console.log("Signature", signatureR.toString('hex'), signatureS.toString('hex'));
        console.log("Key",  keysContainer[keyID].getPublic(false, 'hex'));
        if (keyID in keysContainer) {
            const input_hash = createHash('sha256').update(input).digest();
            const verified = keysContainer[keyID].verify(input_hash, { r: signatureR, s: signatureS });
            console.log("Verified", verified);
            return verified;
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

    crypto.setEncrypt(async (key_id, nonce, aad, plaintext, size) => {
        const keyID = key_id.toString('hex');
        console.log("setEncrypt", key_id, nonce.toString("hex"), aad.toString("hex"), plaintext.toString("hex"), size);
        if (keyID in keysContainer) {
            const cipher = createCipheriv('aes-128-ccm', keysContainer[keyID], nonce, {
                authTagLength: 8
            });
            cipher.setAAD(aad, { plaintextLength: Buffer.byteLength(plaintext) });
            const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final(), cipher.getAuthTag()]);
            console.log("Encrypted", encrypted.toString('hex'));
            return encrypted;
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
        compose: async (message, size) => {
            // throw new Error("Not implemented");
            // return [];
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

    const initiator = new addon.LibEDHOC(12, 0, credentials, ead, crypto);
    const responder = new addon.LibEDHOC(20, 0, credentials, ead, crypto);
    
    let requestCoAP = (params, payload, options = {}) => {
        return new Promise(function(resolve, reject) {
            let request = coap.request(params);
            
            if (!!payload) {
              request.write(payload);
            }
            request.on('error', error => reject(error))
            request.on('response', async res => {
                if (!res.code.startsWith('2.')) {
                    reject(res._packet)
                }
                else {
                    resolve(res)
                }
            })
            // Options
            for (const num in options) {
                request.setOption(num, options[num]);
            }
            // Request Call
            request.end();
        })
    }

    try {
        // Message 1 Composing
        let message1 = await initiator.composeMessage1();
        console.log("Message 1", message1.toString('hex'));
        
        const response1 = await requestCoAP({hostname: '127.0.0.1', port: 8888, method: 'POST', pathname: '.well-known/edhoc'}, message1);
        console.log("Response 1", response1.payload.toString('hex'));
        
        // Message 2 Processing
        let c_r = await initiator.processMessage2(response1.payload);
        console.log("Message 2 - C_R", c_r);    

        // Message 3 Composing
        let message3 = await initiator.composeMessage3();
        console.log("Message 3", message3.toString('hex'));

        const response3 = await requestCoAP({hostname: '127.0.0.1', port: 8888, method: 'POST', pathname: '.well-known/edhoc'}, message3);
        console.log("Response 3", response3.payload.toString('hex'));
    }
    catch (e) {
        console.log(e);
    }
}
run();


// // Responder
        // let c_i = await responder.processMessage1(message1);
        // console.log("Message 1 - C_I", c_i);
        
        // let message2 = await responder.composeMessage2();
        // console.log("Message 2", message2.toString('hex'));
