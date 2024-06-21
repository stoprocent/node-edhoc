const addon = require('../build/Debug/bindings');
const { subtle } = require('crypto').webcrypto;
const { createHash, createCipheriv, createDecipheriv, Certificate } = require('crypto');
const hkdf = require('futoin-hkdf');
var EC = require('elliptic').ec;
const coap = require('coap');
const chalk = require('chalk');

let requestCoAP = (params, payload, options = {}) => {
    return new Promise(function (resolve, reject) {
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

    var ec = new EC('p256');

    const crypto = new addon.EdhocCryptoManager();

    keysContainer['01020304'] = ec.keyFromPrivate(Buffer.from('FB13ADEB6518CEE5F88417660841142E830A81FE334380A953406A1305E8706B', 'hex'));
    keysContainer['01020304'] = ec.keyFromPrivate(Buffer.from('FB13ADEB6518CEE5F88417660841142E830A81FE334380A953406A1305E8706B', 'hex'));

    crypto.generateKey = async (edhoc, key_type, key) => {
        console.log(`EDHOC(${edhoc.connectionID}) setGenerateKey`, key_type, key);
        // throw new Error("Not implemented");
        // return []
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
            case EDHOC_KEY_TYPE.EDHOC_KT_DECRYPT:
            case EDHOC_KEY_TYPE.EDHOC_KT_ENCRYPT:
            case EDHOC_KEY_TYPE.EDHOC_KT_EXTRACT:
            case EDHOC_KEY_TYPE.EDHOC_KT_EXPAND:
                keysContainer[keyIDKey] = key;
                return keyID;
            default:
                return 0;
        }
    };

    crypto.destroyKey = async (edhoc, key_id) => {
        const keyID = key_id.toString('hex');
        console.log(`EDHOC(${edhoc.connectionID}) setDestroyKey`, key_id, keyID);
        if (keyID in keysContainer) {
            delete keysContainer[keyID];
            return true;
        }
        return false;
    };

    crypto.makeKeyPair = async (edhoc, key_id, priv_key_size, pub_key_size) => {
        const keyID = key_id.toString('hex');
        console.log(`EDHOC(${edhoc.connectionID}) setMakeKeyPair`, key_id, keyID, priv_key_size, pub_key_size);
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
    };

    crypto.keyAgreement = async (edhoc, key_id, pub_key, size) => {
        const keyID = key_id.toString('hex');
        console.log(`EDHOC(${edhoc.connectionID}) setKeyAgreement`, key_id, keyID, pub_key, size);
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
    };

    crypto.sign = async (edhoc, key_id, input, size) => {
        const keyID = key_id.toString('hex');
        console.log(`EDHOC(${edhoc.connectionID}) setSign`, key_id, keyID, input, size);

        if (keyID in keysContainer) {
            const input_hash = createHash('sha256').update(input).digest();
            let signature = keysContainer[keyID].sign(input_hash);
            let signatureData = Buffer.concat([signature.r.toBuffer(), signature.s.toBuffer()]);

            console.log("Signature", signatureData);
            return signatureData;
        }
        throw new Error("Key not found");
    };

    crypto.verify = async (edhoc, key_id, input, signature) => {
        const keyID = key_id.toString('hex');
        console.log(`EDHOC(${edhoc.connectionID}) setVerify`, key_id, keyID);
        console.log("Input", input.toString('hex'));
        console.log("Signature", signature.toString('hex'));
        const signatureR = signature.slice(0, signature.length / 2);
        const signatureS = signature.slice(signature.length / 2);
        console.log("Signature", signatureR.toString('hex'), signatureS.toString('hex'));
        console.log("Key", keysContainer[keyID].getPublic(false, 'hex'));
        if (keyID in keysContainer) {
            const input_hash = createHash('sha256').update(input).digest();
            const verified = keysContainer[keyID].verify(input_hash, { r: signatureR, s: signatureS });
            console.log("Verified", verified);
            return verified;
        }
        throw new Error("Key not found");
    };

    crypto.extract = async (edhoc, key_id, salt, size) => {
        const keyID = key_id.toString('hex');
        console.log(`EDHOC(${edhoc.connectionID}) setExtract`, key_id, salt, size);
        if (keyID in keysContainer) {
            return hkdf.extract('sha256', hkdf.hash_length('sha256'), keysContainer[keyID], salt);
        }
        throw new Error("Key not found");
    };

    crypto.expand = (edhoc, key_id, info, size) => {
        const keyID = key_id.toString('hex');
        console.log(`EDHOC(${edhoc.connectionID}) setExpand`, key_id, info, size);
        if (keyID in keysContainer) {
            return hkdf.expand('sha256', hkdf.hash_length('sha256'), keysContainer[keyID], size, info);
        }
        throw new Error("Key not found");
    };

    crypto.encrypt = async (edhoc, key_id, nonce, aad, plaintext, size) => {
        const keyID = key_id.toString('hex');
        console.log(`EDHOC(${edhoc.connectionID}) setEncrypt`, key_id, nonce.toString("hex"), aad.toString("hex"), plaintext.toString("hex"), size);
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
    };

    crypto.decrypt = async (edhoc, key_id, nonce, aad, ciphertext, size) => {
        const keyID = key_id.toString('hex');
        console.log(`EDHOC(${edhoc.connectionID}) setDecrypt`, ciphertext.subarray(ciphertext.length - 8), key_id, nonce.toString("hex"), aad.toString("hex"), ciphertext.toString("hex"), size);
        if (keyID in keysContainer) {

            const decipher = createDecipheriv('aes-128-ccm', keysContainer[keyID], nonce, {
                authTagLength: 8
            });

            decipher.setAuthTag(ciphertext.subarray(ciphertext.length - 8));
            decipher.setAAD(aad, { plaintextLength: ciphertext.length - 8 });

            let decrypted = decipher.update(ciphertext.subarray(0, ciphertext.length - 8));
            decipher.final();
            console.log("Decrypted", decrypted.toString('hex'));

            return decrypted;
        }
        throw new Error("Key not found");
    };

    crypto.hash = async (edhoc, data, size) => {
        console.log(`EDHOC(${edhoc.connectionID}) setHash`, data, size);
        return createHash('sha256').update(data).digest();
    };

    const credentials = new addon.EdhocCredentialManager();

    credentials.fetch = async (edhoc, ...args) => {
        console.log(`EDHOC(${edhoc.connectionID}) credentials.fetch`, args);
        return {
            label: 33,
            privateKeyId: Buffer.from([0x01, 0x02, 0x03, 0x04]),
            x5chain: {
                certificate: Buffer.from([0x01, 0x02, 0x03, 0x04, 0x02, 0x03, 0x04, 0x02, 0x03, 0x04, 0x02, 0x03, 0x04, 0x02, 0x03, 0x04, 0x02, 0x03, 0x04, 0x02, 0x03, 0x04, 0x02, 0x03, 0x04, 0x02, 0x03, 0x04, 0x02, 0x03, 0x04, 0x02, 0x03, 0x04]),
                // hash: Buffer.from([0x01, 0x02, 0x03, 0x04]),
                // hashAlgorithm: 100
            }
        }
    }

    credentials.verify = async (edhoc, credentials) => {
        console.log(`EDHOC(${edhoc.connectionID}) credentials.verify`, credentials);

        credentials.publicKey = Buffer.from(keysContainer['01020304'].getPublic(false, 'array')).subarray(1)
        console.log("Public Key", credentials.publicKey.toString('hex'));
        // credentials.x5t.certificate = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x02, 0x03, 0x04, 0x02, 0x03, 0x04, 0x02, 0x03, 0x04, 0x02, 0x03, 0x04, 0x02, 0x03, 0x04, 0x02, 0x03, 0x04, 0x02, 0x03, 0x04, 0x02, 0x03, 0x04, 0x02, 0x03, 0x04, 0x02, 0x03, 0x04])

        console.log(`EDHOC(${edhoc.connectionID}) credentials.verify`, credentials);
        return credentials;
    }

    try {

        const initiator = new addon.LibEDHOC(Buffer.from([0x99, 0x88, 0x77, 0x66]), 0, [2], credentials, crypto);
        const responder = new addon.LibEDHOC(20, 0, [2], credentials, crypto);

        console.log("Cred", credentials.edhoc === responder);
        console.log("Crypto", crypto.edhoc === initiator);

        console.log("Initiator", initiator.cipherSuites, initiator.connectionID);
        console.log("Responder", responder.cipherSuites, responder.connectionID);

        initiator.logger = (name, data) => {
            // console.log("Parameter name ================================= [", name, "]");
            // console.log(data.toString('hex'));
            // console.log("=================================");
        }

        // Message 1 Composing
        let message1 = await initiator.composeMessage1([{ label: 9999, value: Buffer.from([0x01, 0x02, 0x03, 0x04]) }, { label: 1999, value: Buffer.from([0x01, 0x02, 0x03, 0x04]) }]);
        console.log("Message 1", message1.toString('hex'));

        // await new Promise((resolve, reject) => { setTimeout(resolve, 3000)});

        // Responder - Message 1 Processing
        let ead = await responder.processMessage1(message1);
        console.log(chalk.red("Message 1 - EAD"), ead);

        // Responder - Message 2 Composing
        let message2 = await responder.composeMessage2([{ label: 123, value: Buffer.from([0x01, 0x02, 0x03, 0x04]) }]);
        console.log("Message 2", message2.toString('hex'));
        console.log(chalk.red("Responder - C_I"), responder.peerConnectionID);
        console.log(chalk.red("Responder - C_R"), responder.connectionID);

        // Message 2 Processing
        let ead_2 = await initiator.processMessage2(message2);
        console.log(chalk.red("Message 2 - EAD"), ead_2);
        console.log(chalk.red("Initiator - C_I"), initiator.connectionID);
        console.log(chalk.red("Initiator - C_R"), initiator.peerConnectionID);

        // Message 3 Composing
        let message3 = await initiator.composeMessage3([]);
        console.log("Message 3", message3.toString('hex'));
        console.log("Initiator OSCORE Context", await initiator.exportOSCORE());

        // Message 3 Processing
        let ead_3 = await responder.processMessage3(message3);
        console.log(chalk.red("Message 3 - EAD"), ead_3);
        console.log("Responder OSCORE Context", await responder.exportOSCORE());
    }
    catch (e) {
        console.log(e);
    }
}
run();

