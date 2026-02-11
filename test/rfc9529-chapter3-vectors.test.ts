/**
 * RFC 9529 Chapter 3 test vectors — Method 3 (StaticDH/StaticDH), Suite 2,
 * CCS/kid credentials.
 *
 * Verifies the TypeScript EDHOC library against the reference vectors from
 * the C libedhoc library's test_vector_ccs_static_dh_keys_suite_2.h header,
 * which implements the RFC 9529 Chapter 3 scenario with CCS (CBOR Certificate
 * Structures) and kid-based credential identification.
 *
 * Key differences from X.509 test vectors:
 *   - ID_CRED_x on the wire uses compact form: bare CBOR integer (e.g., 0x32)
 *   - ID_CRED_x in MAC context / Sig_structure uses full map: {4: bstr(cbor(kid))}
 *   - CRED_x is a raw CBOR map (CCS), NOT bstr-wrapped
 */

import {
    EDHOC,
    DefaultEdhocCryptoManager,
    EdhocMethod,
    EdhocSuite,
    CCSCredentialManager,
    PublicPrivateTuple,
} from '../dist/index';
import { p256 } from '@noble/curves/p256';

// ---------------------------------------------------------------------------
// Test vector data from C libedhoc: test_vector_ccs_static_dh_keys_suite_2.h
// ---------------------------------------------------------------------------

// Ephemeral DH private keys (P-256)
const X_hex = '368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525';
const Y_hex = 'e2f4126777205e853b437d6eaca1e1f753cdcc3e2c69fa884b0a1a640977e418';

// Static authentication private keys (P-256)
const SK_I_hex = 'fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b';
const SK_R_hex = '72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac';

// P-256 public keys (x-coordinate only, 32 bytes)
const PK_I_hex = 'ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6';
const PK_R_hex = 'bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0';

// Connection identifiers
const C_I = -24;
const C_R = -8;

// kid values
const KID_I = -12;  // CBOR encoding: 0x2b
const KID_R = -19;  // CBOR encoding: 0x32

// CRED_R: CCS CBOR map (verbatim from C header CRED_R_cborised[])
const CRED_R = Buffer.from([
    0xa2, 0x02, 0x6b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x65,
    0x64, 0x75, 0x08, 0xa1, 0x01, 0xa5, 0x01, 0x02, 0x02, 0x41, 0x32, 0x20,
    0x01, 0x21, 0x58, 0x20, 0xbb, 0xc3, 0x49, 0x60, 0x52, 0x6e, 0xa4, 0xd3,
    0x2e, 0x94, 0x0c, 0xad, 0x2a, 0x23, 0x41, 0x48, 0xdd, 0xc2, 0x17, 0x91,
    0xa1, 0x2a, 0xfb, 0xcb, 0xac, 0x93, 0x62, 0x20, 0x46, 0xdd, 0x44, 0xf0,
    0x22, 0x58, 0x20, 0x45, 0x19, 0xe2, 0x57, 0x23, 0x6b, 0x2a, 0x0c, 0xe2,
    0x02, 0x3f, 0x09, 0x31, 0xf1, 0xf3, 0x86, 0xca, 0x7a, 0xfd, 0xa6, 0x4f,
    0xcd, 0xe0, 0x10, 0x8c, 0x22, 0x4c, 0x51, 0xea, 0xbf, 0x60, 0x72,
]);

// CRED_I: CCS CBOR map (verbatim from C header CRED_I_cborised[])
const CRED_I = Buffer.from([
    0xa2, 0x02, 0x77, 0x34, 0x32, 0x2d, 0x35, 0x30, 0x2d, 0x33, 0x31, 0x2d,
    0x46, 0x46, 0x2d, 0x45, 0x46, 0x2d, 0x33, 0x37, 0x2d, 0x33, 0x32, 0x2d,
    0x33, 0x39, 0x08, 0xa1, 0x01, 0xa5, 0x01, 0x02, 0x02, 0x41, 0x2b, 0x20,
    0x01, 0x21, 0x58, 0x20, 0xac, 0x75, 0xe9, 0xec, 0xe3, 0xe5, 0x0b, 0xfc,
    0x8e, 0xd6, 0x03, 0x99, 0x88, 0x95, 0x22, 0x40, 0x5c, 0x47, 0xbf, 0x16,
    0xdf, 0x96, 0x66, 0x0a, 0x41, 0x29, 0x8c, 0xb4, 0x30, 0x7f, 0x7e, 0xb6,
    0x22, 0x58, 0x20, 0x6e, 0x5d, 0xe6, 0x11, 0x38, 0x8a, 0x4b, 0x8a, 0x82,
    0x11, 0x33, 0x4a, 0xc7, 0xd3, 0x7e, 0xcb, 0x52, 0xa3, 0x87, 0xd2, 0x57,
    0xe6, 0xdb, 0x3c, 0x2a, 0x93, 0xdf, 0x21, 0xff, 0x3a, 0xff, 0xc8,
]);

// Expected intermediate values from C library vectors
const expected = {
    H_message_1: 'ca02cabda5a8902749b42f711050bb4dbd52153e87527594b39f50cdf019888c',
    TH_2: '356efd53771425e008f3fe3a86c83ff4c6b16e57028ff39d5236c182b202084b',
    PRK_2e: '5aa0d69f3e3d1e0c479f0b8a486690c9802630c3466b1dc92371c982563170b5',
    PRK_3e2m: '0ca3d3398296b3c03900987620c11f6fce70781c1d1219720f9ec08c122d8434',
    MAC_2: '0943305c899f5c54',
    TH_3: 'adaf67a78a4bcc91e018f8882762a722000b2507039df0bc1bbf0c161bb3155c',
    PRK_4e3m: '81cc8a298e357044e3c466bb5c0a1e507e01d49238aeba138df94635407c0ff7',
    MAC_3: '623c91df41e34c2f',
    TH_4: 'c902b1e3a4326c93c5551f5f3aa6c5ecc0246806765612e52b5d99e6059d6b6e',
    OSCORE_masterSecret: 'f9868f6a3aca78a05d1485b35030b162',
    OSCORE_masterSalt: 'ada24c7dbfc85eeb',
    // OSCORE IDs: CBOR encoding of connection IDs
    // C_I = -24 -> CBOR byte = 0x37, C_R = -8 -> CBOR byte = 0x27
    OSCORE_C_I: '37',
    OSCORE_C_R: '27',
};

// ---------------------------------------------------------------------------
// Crypto manager with fixed ephemeral keys
// ---------------------------------------------------------------------------

class CCSVectorsCryptoManager extends DefaultEdhocCryptoManager {
    private ephemeralKey: Buffer;

    constructor(ephemeralKey: Buffer) {
        super();
        this.ephemeralKey = ephemeralKey;
    }

    generateKeyPair(edhoc: EDHOC): PublicPrivateTuple {
        const privateKey = this.ephemeralKey;
        // Suite 2 uses P-256
        const publicKey = Buffer.from(p256.getPublicKey(privateKey)).subarray(1);
        return { publicKey, privateKey };
    }
}

// ---------------------------------------------------------------------------
// Helper: create an EDHOC session for CCS/kid vectors
// ---------------------------------------------------------------------------

function makeCCSSession(
    role: 'initiator' | 'responder',
    log: [string, string][],
): EDHOC {
    const isInitiator = role === 'initiator';

    const ownKid = isInitiator ? KID_I : KID_R;
    const ownCred = isInitiator ? CRED_I : CRED_R;
    const ownPK = Buffer.from(isInitiator ? PK_I_hex : PK_R_hex, 'hex');
    const peerKid = isInitiator ? KID_R : KID_I;
    const peerCred = isInitiator ? CRED_R : CRED_I;
    const peerPK = Buffer.from(isInitiator ? PK_R_hex : PK_I_hex, 'hex');
    const skHex = isInitiator ? SK_I_hex : SK_R_hex;
    const ephHex = isInitiator ? X_hex : Y_hex;
    const connID = isInitiator ? C_I : C_R;

    const credMgr = new CCSCredentialManager();
    credMgr.addOwnCredential(ownKid, ownCred, ownPK, Buffer.from(skHex, 'hex'));
    credMgr.addPeerCredential(peerKid, peerCred, peerPK);

    const crypto = new CCSVectorsCryptoManager(Buffer.from(ephHex, 'hex'));

    // C vector: SUITES_I = [6, 2] (selected = 2). Initiator lists both; responder only needs the selected suite.
    const suites = isInitiator
        ? [EdhocSuite.Suite6, EdhocSuite.Suite2]
        : [EdhocSuite.Suite2];
    const session = new EDHOC(connID, [EdhocMethod.Method3], suites, credMgr, crypto);
    session.logger = (name: string, data: Buffer) => log.push([name, data.toString('hex')]);
    return session;
}

function getVal(log: [string, string][], key: string): string | undefined {
    return log.find(l => l[0] === key)?.[1];
}

// ===========================================================================
// Tests
// ===========================================================================

describe('RFC 9529 Chapter 3: Method 3 (StaticDH/StaticDH), Suite 2, CCS/kid', () => {
    let iLog: [string, string][];
    let rLog: [string, string][];
    let initiator: EDHOC;
    let responder: EDHOC;

    beforeAll(async () => {
        iLog = [];
        rLog = [];
        initiator = makeCCSSession('initiator', iLog);
        responder = makeCCSSession('responder', rLog);

        const msg1 = await initiator.composeMessage1();
        await responder.processMessage1(msg1);
        const msg2 = await responder.composeMessage2();
        await initiator.processMessage2(msg2);
        const msg3 = await initiator.composeMessage3();
        await responder.processMessage3(msg3);
    });

    test('H(message_1) matches expected vector', () => {
        expect(getVal(iLog, 'TH_1')).toBe(expected.H_message_1);
    });

    test('TH_2 matches expected vector', () => {
        expect(getVal(rLog, 'TH_2')).toBe(expected.TH_2);
    });

    test('PRK_2e matches expected vector', () => {
        expect(getVal(rLog, 'PRK_2e')).toBe(expected.PRK_2e);
    });

    test('PRK_3e2m matches expected vector', () => {
        expect(getVal(rLog, 'PRK_3e2m')).toBe(expected.PRK_3e2m);
    });

    test('MAC_2 matches expected vector', () => {
        expect(getVal(rLog, 'MAC_2')).toBe(expected.MAC_2);
    });

    test('TH_3 matches expected vector', () => {
        // TH_3 is computed by both sides; check both
        const rTH3 = getVal(rLog, 'TH_3');
        const iTH3 = getVal(iLog, 'TH_3');
        expect(rTH3).toBe(expected.TH_3);
        expect(iTH3).toBe(expected.TH_3);
    });

    test('PRK_4e3m matches expected vector', () => {
        expect(getVal(iLog, 'PRK_4e3m')).toBe(expected.PRK_4e3m);
    });

    test('MAC_3 matches expected vector', () => {
        expect(getVal(iLog, 'MAC_3')).toBe(expected.MAC_3);
    });

    test('TH_4 matches expected vector', () => {
        expect(getVal(iLog, 'TH_4')).toBe(expected.TH_4);
    });

    test('OSCORE master secret matches expected vector', async () => {
        const iOSCORE = await initiator.exportOSCORE();
        expect(iOSCORE.masterSecret.toString('hex')).toBe(expected.OSCORE_masterSecret);
    });

    test('OSCORE master salt matches expected vector', async () => {
        const iOSCORE = await initiator.exportOSCORE();
        expect(iOSCORE.masterSalt.toString('hex')).toBe(expected.OSCORE_masterSalt);
    });

    test('OSCORE sender/recipient IDs use correct CBOR encoding', async () => {
        const iOSCORE = await initiator.exportOSCORE();
        // Initiator Sender ID = connectionIdToBytes(C_R) = CBOR(-8) = 0x27
        expect(iOSCORE.senderId.toString('hex')).toBe(expected.OSCORE_C_R);
        // Initiator Recipient ID = connectionIdToBytes(C_I) = CBOR(-24) = 0x37
        expect(iOSCORE.recipientId.toString('hex')).toBe(expected.OSCORE_C_I);
    });

    test('OSCORE contexts match between initiator and responder', async () => {
        const iOSCORE = await initiator.exportOSCORE();
        const rOSCORE = await responder.exportOSCORE();

        expect(iOSCORE.masterSecret).toEqual(rOSCORE.masterSecret);
        expect(iOSCORE.masterSalt).toEqual(rOSCORE.masterSalt);
        expect(iOSCORE.senderId).toEqual(rOSCORE.recipientId);
        expect(iOSCORE.recipientId).toEqual(rOSCORE.senderId);
    });
});
