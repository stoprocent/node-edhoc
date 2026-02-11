/**
 * Tests against vectors from the C libedhoc library.
 *
 * Uses keys and certificates from:
 *   - test_vector_x5chain_sign_keys_suite_2.h       (Method 0 - Sig/Sig)
 *   - test_vector_x5chain_static_dh_keys_suite_2.h  (Method 3 - StaticDH/StaticDH)
 *
 * Also verifies the P-256 ECDH shared secret from RFC 9529 Chapter 3.
 */

import { X509Certificate } from 'crypto';
import {
    EDHOC,
    X509CertificateCredentialManager,
    DefaultEdhocCryptoManager,
    EdhocMethod,
    EdhocSuite,
    EdhocCredentialManager,
    EdhocCredentials,
    EdhocCredentialsFormat,
    EdhocCredentialsCertificateChain,
    PublicPrivateTuple,
} from '../dist/index';
import { p256 } from '@noble/curves/p256';

// ---------------------------------------------------------------------------
// C libedhoc test vector data (P-256 / Suite 2)
// Byte arrays taken verbatim from the C header files.
// ---------------------------------------------------------------------------

// Ephemeral keys (same in both sign and static_dh headers)
const X_hex = '368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525';
const Y_hex = 'e2f4126777205e853b437d6eaca1e1f753cdcc3e2c69fa884b0a1a640977e418';

// Static private keys
const SK_I_hex = 'fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b';
const SK_R_hex = '72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac';

// Responder X.509 DER certificate (exact bytes from C header)
const CRED_R = Buffer.from([
    0x30, 0x82, 0x01, 0x1e, 0x30, 0x81, 0xc5, 0xa0, 0x03, 0x02, 0x01, 0x02,
    0x02, 0x04, 0x61, 0xe9, 0x98, 0x1e, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x15, 0x31, 0x13, 0x30, 0x11,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, 0x45, 0x44, 0x48, 0x4f, 0x43,
    0x20, 0x52, 0x6f, 0x6f, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x32, 0x30,
    0x31, 0x32, 0x30, 0x31, 0x37, 0x31, 0x33, 0x30, 0x32, 0x5a, 0x17, 0x0d,
    0x32, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x30, 0x30, 0x30, 0x30,
    0x5a, 0x30, 0x1a, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x0f, 0x45, 0x44, 0x48, 0x4f, 0x43, 0x20, 0x52, 0x65, 0x73, 0x70,
    0x6f, 0x6e, 0x64, 0x65, 0x72, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xbb, 0xc3, 0x49, 0x60,
    0x52, 0x6e, 0xa4, 0xd3, 0x2e, 0x94, 0x0c, 0xad, 0x2a, 0x23, 0x41, 0x48,
    0xdd, 0xc2, 0x17, 0x91, 0xa1, 0x2a, 0xfb, 0xcb, 0xac, 0x93, 0x62, 0x20,
    0x46, 0xdd, 0x44, 0xf0, 0x45, 0x19, 0xe2, 0x57, 0x23, 0x6b, 0x2a, 0x0c,
    0xe2, 0x02, 0x3f, 0x09, 0x31, 0xf1, 0xf3, 0x86, 0xca, 0x7a, 0xfd, 0xa6,
    0x4f, 0xcd, 0xe0, 0x10, 0x8c, 0x22, 0x4c, 0x51, 0xea, 0xbf, 0x60, 0x72,
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x30, 0x19, 0x4e, 0xf5, 0xfc,
    0x65, 0xc8, 0xb7, 0x95, 0xcd, 0xcd, 0x0b, 0xb4, 0x31, 0xbf, 0x83, 0xee,
    0x67, 0x41, 0xc1, 0x37, 0x0c, 0x22, 0xc8, 0xeb, 0x8e, 0xe9, 0xed, 0xd2,
    0xa7, 0x05, 0x19, 0x02, 0x21, 0x00, 0xb5, 0x83, 0x0e, 0x9c, 0x89, 0xa6,
    0x2a, 0xc7, 0x3c, 0xe1, 0xeb, 0xce, 0x00, 0x61, 0x70, 0x7d, 0xb8, 0xa8,
    0x8e, 0x23, 0x70, 0x9b, 0x4a, 0xcc, 0x58, 0xa1, 0x31, 0x3b, 0x13, 0x3d,
    0x05, 0x58,
]);

// Initiator X.509 DER certificate (exact bytes from C header)
const CRED_I = Buffer.from([
    0x30, 0x82, 0x01, 0x1e, 0x30, 0x81, 0xc5, 0xa0, 0x03, 0x02, 0x01, 0x02,
    0x02, 0x04, 0x62, 0x32, 0xef, 0x6f, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x15, 0x31, 0x13, 0x30, 0x11,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, 0x45, 0x44, 0x48, 0x4f, 0x43,
    0x20, 0x52, 0x6f, 0x6f, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x32, 0x30,
    0x33, 0x31, 0x37, 0x30, 0x38, 0x32, 0x31, 0x30, 0x33, 0x5a, 0x17, 0x0d,
    0x32, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x30, 0x30, 0x30, 0x30,
    0x5a, 0x30, 0x1a, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x0f, 0x45, 0x44, 0x48, 0x4f, 0x43, 0x20, 0x49, 0x6e, 0x69, 0x74,
    0x69, 0x61, 0x74, 0x6f, 0x72, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xac, 0x75, 0xe9, 0xec,
    0xe3, 0xe5, 0x0b, 0xfc, 0x8e, 0xd6, 0x03, 0x99, 0x88, 0x95, 0x22, 0x40,
    0x5c, 0x47, 0xbf, 0x16, 0xdf, 0x96, 0x66, 0x0a, 0x41, 0x29, 0x8c, 0xb4,
    0x30, 0x7f, 0x7e, 0xb6, 0x6e, 0x5d, 0xe6, 0x11, 0x38, 0x8a, 0x4b, 0x8a,
    0x82, 0x11, 0x33, 0x4a, 0xc7, 0xd3, 0x7e, 0xcb, 0x52, 0xa3, 0x87, 0xd2,
    0x57, 0xe6, 0xdb, 0x3c, 0x2a, 0x93, 0xdf, 0x21, 0xff, 0x3a, 0xff, 0xc8,
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0x8c, 0x32, 0x3a, 0x1f,
    0x33, 0x21, 0x38, 0xaa, 0xb9, 0xd0, 0xbe, 0xaf, 0xb8, 0x5f, 0x8d, 0x5a,
    0x44, 0x07, 0x3c, 0x58, 0x0f, 0x59, 0x5b, 0xc5, 0x21, 0xef, 0x91, 0x3f,
    0x6e, 0xf4, 0x8d, 0x11, 0x02, 0x20, 0x6c, 0x0a, 0xf1, 0xa1, 0x85, 0xa4,
    0xe4, 0xde, 0x06, 0x35, 0x36, 0x99, 0x23, 0x1c, 0x73, 0x3a, 0x6e, 0x8d,
    0xd2, 0xdf, 0x65, 0x13, 0x96, 0x6c, 0x91, 0x30, 0x15, 0x2a, 0x07, 0xa2,
    0xbe, 0xde,
]);

// Expected ECDH shared secret (RFC 9529 Chapter 3)
const G_XY_hex = '2f0cb7e860ba538fbf5c8bded009f6259b4b628fe1eb7dbe9378e5ecf7a824ba';

// ---------------------------------------------------------------------------
// Custom credential manager for C library vectors.
// ---------------------------------------------------------------------------

class CLibCredentialManager implements EdhocCredentialManager {
    private ownCertDer: Buffer;
    private peerCertDer: Buffer;
    private privateKey: Buffer;

    constructor(ownCertDer: Buffer, peerCertDer: Buffer, privateKey: Buffer) {
        this.ownCertDer = ownCertDer;
        this.peerCertDer = peerCertDer;
        this.privateKey = privateKey;
    }

    async fetch(_edhoc: EDHOC): Promise<EdhocCredentials> {
        return {
            format: EdhocCredentialsFormat.x5chain,
            privateKey: this.privateKey,
            x5chain: {
                certificates: [this.ownCertDer],
            },
        } as EdhocCredentialsCertificateChain;
    }

    async verify(_edhoc: EDHOC, credentials: EdhocCredentials): Promise<EdhocCredentials> {
        if (credentials.format !== EdhocCredentialsFormat.x5chain) {
            throw new Error('Expected x5chain credentials format');
        }

        const x5chain = (credentials as EdhocCredentialsCertificateChain).x5chain;
        if (!x5chain || x5chain.certificates.length < 1) {
            throw new Error('No certificates in chain');
        }

        const receivedCertDer = x5chain.certificates[0];

        // Verify the received certificate matches the expected peer cert
        if (!Buffer.from(receivedCertDer).equals(this.peerCertDer)) {
            throw new Error('Received certificate does not match expected peer certificate');
        }

        // Extract the P-256 public key from the X.509 certificate
        const x509 = new X509Certificate(receivedCertDer);
        const jwk = x509.publicKey.export({ format: 'jwk' });
        if (jwk.crv !== 'P-256') {
            throw new Error(`Unsupported curve: ${jwk.crv}`);
        }
        const pubKey = Buffer.concat([
            Buffer.from(jwk.x!, 'base64'),
            Buffer.from(jwk.y!, 'base64'),
        ]);

        credentials.publicKey = pubKey;
        return credentials;
    }
}

// ---------------------------------------------------------------------------
// Crypto manager that injects fixed ephemeral keys
// ---------------------------------------------------------------------------

class CLibVectorsCryptoManager extends DefaultEdhocCryptoManager {
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
// Helper: create an EDHOC session for the C library vectors
// ---------------------------------------------------------------------------

function makeClibSession(
    method: EdhocMethod,
    role: 'initiator' | 'responder',
): EDHOC {
    const isInitiator = role === 'initiator';

    const ownCert = isInitiator ? CRED_I : CRED_R;
    const peerCert = isInitiator ? CRED_R : CRED_I;
    const skHex = isInitiator ? SK_I_hex : SK_R_hex;
    const ephHex = isInitiator ? X_hex : Y_hex;
    const connID = isInitiator ? 0 : 1;

    const credMgr = new CLibCredentialManager(ownCert, peerCert, Buffer.from(skHex, 'hex'));

    const crypto = new CLibVectorsCryptoManager(Buffer.from(ephHex, 'hex'));

    return new EDHOC(connID, [method], [EdhocSuite.Suite2], credMgr, crypto);
}

// ===========================================================================
// 1. P-256 ECDH shared secret verification (RFC 9529 Chapter 3)
// ===========================================================================

describe('P-256 ECDH shared secret (RFC 9529 Chapter 3)', () => {
    test('keyAgreement(X, G_Y) produces expected G_XY', async () => {
        const crypto = new DefaultEdhocCryptoManager();
        const credMgr = new X509CertificateCredentialManager([CRED_I], Buffer.alloc(0));
        const edhoc = new EDHOC(
            0,
            [EdhocMethod.Method0],
            [EdhocSuite.Suite2],
            credMgr,
            crypto,
        );

        // Derive G_Y from private key Y
        const privateKeyY = Buffer.from(Y_hex, 'hex');
        const G_Y = Buffer.from(p256.getPublicKey(privateKeyY)).subarray(1);

        // Compute shared secret G_XY = ECDH(X, G_Y)
        const privateKeyX = Buffer.from(X_hex, 'hex');
        const sharedSecret = crypto.keyAgreement(edhoc, privateKeyX, G_Y);

        // Verify against expected value
        expect(sharedSecret.toString('hex')).toBe(G_XY_hex);
    });
});

// ===========================================================================
// 2. Method 0 (Sig/Sig) handshake with C library P-256 certificates
// ===========================================================================

describe('C library vectors: Method 0 (Sig/Sig) / Suite 2', () => {
    let initiator: EDHOC;
    let responder: EDHOC;

    beforeEach(() => {
        initiator = makeClibSession(EdhocMethod.Method0, 'initiator');
        responder = makeClibSession(EdhocMethod.Method0, 'responder');
    });

    test('should complete a full handshake with OSCORE consistency', async () => {
        // Three-message handshake
        const message1 = await initiator.composeMessage1();
        const ead1 = await responder.processMessage1(message1);
        expect(ead1).toEqual([]);

        const message2 = await responder.composeMessage2();
        const ead2 = await initiator.processMessage2(message2);
        expect(ead2).toEqual([]);

        const message3 = await initiator.composeMessage3();
        const ead3 = await responder.processMessage3(message3);
        expect(ead3).toEqual([]);

        // Verify OSCORE security context consistency
        const iOSCORE = await initiator.exportOSCORE();
        const rOSCORE = await responder.exportOSCORE();

        expect(iOSCORE.masterSecret).toEqual(rOSCORE.masterSecret);
        expect(iOSCORE.masterSalt).toEqual(rOSCORE.masterSalt);
        expect(iOSCORE.senderId).toEqual(rOSCORE.recipientId);
        expect(iOSCORE.recipientId).toEqual(rOSCORE.senderId);
    });
});

// ===========================================================================
// 3. Method 3 (StaticDH/StaticDH) handshake with C library P-256 certificates
// ===========================================================================

describe('C library vectors: Method 3 (StaticDH/StaticDH) / Suite 2', () => {
    let initiator: EDHOC;
    let responder: EDHOC;

    beforeEach(() => {
        initiator = makeClibSession(EdhocMethod.Method3, 'initiator');
        responder = makeClibSession(EdhocMethod.Method3, 'responder');
    });

    test('should complete a full handshake with OSCORE consistency', async () => {
        // Three-message handshake
        const message1 = await initiator.composeMessage1();
        const ead1 = await responder.processMessage1(message1);
        expect(ead1).toEqual([]);

        const message2 = await responder.composeMessage2();
        const ead2 = await initiator.processMessage2(message2);
        expect(ead2).toEqual([]);

        const message3 = await initiator.composeMessage3();
        const ead3 = await responder.processMessage3(message3);
        expect(ead3).toEqual([]);

        // Verify OSCORE security context consistency
        const iOSCORE = await initiator.exportOSCORE();
        const rOSCORE = await responder.exportOSCORE();

        expect(iOSCORE.masterSecret).toEqual(rOSCORE.masterSecret);
        expect(iOSCORE.masterSalt).toEqual(rOSCORE.masterSalt);
        expect(iOSCORE.senderId).toEqual(rOSCORE.recipientId);
        expect(iOSCORE.recipientId).toEqual(rOSCORE.senderId);
    });
});
