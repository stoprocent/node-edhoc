import cbor from 'cbor';
import { getCipherSuiteParams } from '../lib/cipher-suites';
import { DefaultEdhocCryptoManager } from '../lib/crypto';
import {
    EDHOC,
    EdhocCredentialManager,
    EdhocCredentials,
    EdhocCredentialsKID,
    EdhocMethod,
    EdhocSuite,
} from '../lib/edhoc';
import { connectionIdToBytes, decodeCborSequence, decodeIdCred } from '../lib/cbor-utils';

class NoopCredentialManager implements EdhocCredentialManager {
    async fetch(_edhoc: EDHOC): Promise<EdhocCredentials> {
        throw new Error('Not used in this test');
    }
    async verify(_edhoc: EDHOC, _credentials: EdhocCredentials): Promise<EdhocCredentials> {
        throw new Error('Not used in this test');
    }
}

function makeSession(suite: EdhocSuite, connectionID: number | Buffer = 10): EDHOC {
    const credMgr = new NoopCredentialManager();
    const crypto = new DefaultEdhocCryptoManager();
    return new EDHOC(connectionID, [EdhocMethod.Method0], [suite], credMgr, crypto);
}

describe('RFC 9528 suite parameters', () => {
    test('suite 6 parameters', () => {
        const s = getCipherSuiteParams(EdhocSuite.Suite6);
        expect(s.aeadAlgorithm).toBe('AES-GCM-128');
        expect(s.aeadKeyLength).toBe(16);
        expect(s.aeadTagLength).toBe(16);
        expect(s.aeadIvLength).toBe(12);
        expect(s.hashAlgorithm).toBe('SHA-256');
        expect(s.hashLength).toBe(32);
        expect(s.macLength).toBe(16);
        expect(s.eccKeyLength).toBe(32);
        expect(s.eccSignLength).toBe(64);
    });

    test('suite 24 parameters', () => {
        const s = getCipherSuiteParams(EdhocSuite.Suite24);
        expect(s.aeadAlgorithm).toBe('AES-GCM-256');
        expect(s.aeadKeyLength).toBe(32);
        expect(s.aeadTagLength).toBe(16);
        expect(s.aeadIvLength).toBe(12);
        expect(s.hashAlgorithm).toBe('SHA-384');
        expect(s.hashLength).toBe(48);
        expect(s.macLength).toBe(16);
        expect(s.eccKeyLength).toBe(48);
        expect(s.eccSignLength).toBe(96);
    });

    test('suite 25 parameters', () => {
        const s = getCipherSuiteParams(EdhocSuite.Suite25);
        expect(s.aeadAlgorithm).toBe('ChaCha20/Poly1305');
        expect(s.aeadKeyLength).toBe(32);
        expect(s.aeadTagLength).toBe(16);
        expect(s.aeadIvLength).toBe(12);
        expect(s.hashAlgorithm).toBe('SHAKE256');
        expect(s.hashLength).toBe(64);
        expect(s.macLength).toBe(16);
        expect(s.eccKeyLength).toBe(56);
        expect(s.eccSignLength).toBe(114);
    });
});

describe('RFC 9528 suite-dependent crypto behavior', () => {
    test('suite 24 hash output is 48 bytes', async () => {
        const crypto = new DefaultEdhocCryptoManager();
        const edhoc = makeSession(EdhocSuite.Suite24);
        const h = await crypto.hash(edhoc, Buffer.from('abc'));
        expect(h.length).toBe(48);
    });

    test('suite 25 hash output is 64 bytes', async () => {
        const crypto = new DefaultEdhocCryptoManager();
        const edhoc = makeSession(EdhocSuite.Suite25);
        const h = await crypto.hash(edhoc, Buffer.from('abc'));
        expect(h.length).toBe(64);
    });

    test('suite 24 key agreement keypair size', () => {
        const crypto = new DefaultEdhocCryptoManager();
        const edhoc = makeSession(EdhocSuite.Suite24);
        const kp = crypto.generateKeyPair(edhoc);
        expect(kp.publicKey.length).toBe(48);
        expect(kp.privateKey.length).toBe(48);
    });

    test('suite 25 key agreement keypair size', () => {
        const crypto = new DefaultEdhocCryptoManager();
        const edhoc = makeSession(EdhocSuite.Suite25);
        const kp = crypto.generateKeyPair(edhoc);
        expect(kp.publicKey.length).toBe(56);
        expect(kp.privateKey.length).toBe(56);
    });
});

describe('RFC 9528 identifier and CBOR minimal encoding', () => {
    test('single-byte bstr C_I is canonicalized to integer in message_1', async () => {
        const edhoc = makeSession(EdhocSuite.Suite0, Buffer.from([0x0a]));
        const msg1 = await edhoc.composeMessage1();
        const items = decodeCborSequence(msg1);
        expect(items[3]).toBe(10);
    });

    test('integer C_X outside [-24,23] is encoded as bstr(cbor(int))', async () => {
        const edhoc = makeSession(EdhocSuite.Suite0, 24);
        const msg1 = await edhoc.composeMessage1();
        const items = decodeCborSequence(msg1);
        expect(items[3]).toEqual(Buffer.from([0x18, 0x18]));
    });

    test('connectionIdToBytes encodes out-of-range integer as full CBOR integer bytes', () => {
        expect(connectionIdToBytes(24)).toEqual(Buffer.from([0x18, 0x18]));
        expect(connectionIdToBytes(-25)).toEqual(Buffer.from([0x38, 0x18]));
    });

    test('ID_CRED map kid bstr(cbor(kid)) is decoded back to kid value', () => {
        const idCredMap = new Map<number, unknown>();
        idCredMap.set(4, cbor.encode(-12));
        const decoded = decodeIdCred(idCredMap) as EdhocCredentialsKID;
        expect(decoded.kid.kid).toBe(-12);
    });
});
