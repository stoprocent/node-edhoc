/**
 * Cross-validation tests between TypeScript (node-edhoc) and Swift (SwiftEDHOC).
 *
 * Method 3 (StaticDH/StaticDH) has NO signatures, so all values are fully
 * deterministic in both implementations — byte-exact cross-validation.
 *
 * Method 2 (StaticDH/Sig) has the responder sign. TS noble produces deterministic
 * P-256 ECDSA signatures, while Swift CryptoKit produces hedged (randomized) ones.
 * Values up to and including MAC_2 are deterministic; after that they diverge.
 */

import { EDHOC, X509CertificateCredentialManager, DefaultEdhocCryptoManager, EdhocMethod, EdhocSuite, PublicPrivateTuple } from '../dist/index';
import { p256 } from '@noble/curves/p256';

// Shared test data (same certificates/keys as BasicHandshakeTests and SwiftEDHOC CrossValidationTests)
const trustedCA = Buffer.from('308201323081DAA003020102021478408C6EC18A1D452DAE70C726CB0192A6116DBB300A06082A8648CE3D040302301A3118301606035504030C0F5468697320697320434120526F6F74301E170D3234313031393138333635335A170D3235313031393138333635335A301A3118301606035504030C0F5468697320697320434120526F6F743059301306072A8648CE3D020106082A8648CE3D03010703420004B9348A8A267EF52CFDC30109A29008A2D99F6B8F78BA9EAF5D51578C06134E78CB90A073EDC2488A14174B4E2997C840C5DE7F8E35EB54A0DB6977E894D1B2CB300A06082A8648CE3D040302034700304402203B92BFEC770B0FA4E17F8F02A13CD945D914ED8123AC85C37C8C7BAA2BE3E0F102202CB2DC2EC295B5F4B7BB631ED751179C145D6B6E081559AEA38CE215369E9C31', 'hex');

const initiatorCert = Buffer.from('3082012E3081D4A003020102021453423D5145C767CDC29895C3DB590192A611EA50300A06082A8648CE3D040302301A3118301606035504030C0F5468697320697320434120526F6F74301E170D3234313031393138333732345A170D3235313031393138333732345A30143112301006035504030C09696E69746961746F723059301306072A8648CE3D020106082A8648CE3D03010703420004EB0EF585F3992A1653CF310BF0F0F8035267CDAB6989C8B02E7228FBD759EF6B56263259AADF087F9849E7B7651F74C3B4F144CCCF86BB6FE2FF0EF3AA5FB5DC300A06082A8648CE3D0403020349003046022100D8C3AA7C98A730B3D4862EDAB4C1474FCD9A17A9CA3FB078914A10978FE95CC40221009F5877DD4E2C635A04ED1F6F1854C87B58521BDDFF533B1076F53D456739764C', 'hex');
const initiatorKey = Buffer.from('DC1FBB05B6B08360CE5B9EEA08EBFBFC6766A21340641863D4C8A3F68F096337', 'hex');

const responderCert = Buffer.from('3082012E3081D4A00302010202146648869E2608FC2E16D945C10E1F0192A6125CC0300A06082A8648CE3D040302301A3118301606035504030C0F5468697320697320434120526F6F74301E170D3234313031393138333735345A170D3235313031393138333735345A30143112301006035504030C09726573706F6E6465723059301306072A8648CE3D020106082A8648CE3D03010703420004161F76A7A106C9B79B7F651156B5B095E63A6101A39020F4E86DDACE61FB395E8AEF6CD9C444EE9A43DBD62DAD44FF50FE4146247D3AFD28F60DBC01FBFC573C300A06082A8648CE3D0403020349003046022100E8AD0926518CDB61E84D171700C7158FD0E72D03A117D40133ECD10F8B9F42CE022100E7E69B4C79100B3F0792F010AE11EE5DD2859C29EFC4DBCEFD41FA5CD4D3C3C9', 'hex');
const responderKey = Buffer.from('EE6287116FE27CDC539629DC87E12BF8EAA2229E7773AA67BC4C0FBA96E7FBB2', 'hex');

// Fixed ephemeral DH keys (P-256 private keys, 32 bytes)
const initiatorEphemeral = Buffer.from('3717F87F867BC4C8AB4A564093F1CC4A5414C24DB2ED0690CFAC651A02A04010', 'hex');
const responderEphemeral = Buffer.from('A7FFB1B45F2B570893B0E31C8AAF9C1C0E88C133E15CF2C0B89E5E3074B2D2A0', 'hex');

const keyUpdateContext = Buffer.from('a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6', 'hex');

class VectorsCryptoManager extends DefaultEdhocCryptoManager {
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

// Cross-validation vectors for Method 3 (StaticDH/StaticDH, Suite 2) — fully deterministic
// RFC 9528: P-256 public keys use x-coordinate only (32 bytes) on the wire
const swiftM3 = {
    TH_1: '3d54fea658b0305dd50cb93f326f9b8ba8a5a68ce5ac3ee36571d740eae68e01',
    TH_2: 'f3bacc9d43ea95fefa1a3547844158199655ff3e037440dbd83a9799d6f224dc',
    PRK_2e: '843986712609a510a1feaa57486ffa6225d75a0a2bfd3dde5430a740e4779432',
    PRK_3e2m: 'adadb2eb0e9d6626a6b417dd2892d9913da85b8dc3bc04ee0bc3675203c6dd05',
    MAC_2: 'cad6bf389a35f360',
    TH_3: 'b51d18370cd62188e45c02f60d7bf11e28c7ce6440505d548a0ffc421903ecc9',
    PRK_4e3m: '980ea0be4c04fb6af82018404de816ac40d96c6d3cfc293fec387f429c6be552',
    MAC_3: 'ab344668b80d4125',
    TH_4: '526e9be77beef021cdd7845fba7f6730ec34cb0b198a58b9e2722762a3f040b3',
    masterSecret: '8b5c8b7aa5b8a92e84dbdebc984fce09',
    masterSalt: 'e530cbfc7783c8ca',
    masterSecretAfterUpdate: '24feba33ff32da1a70cf9fd7ac94f03c',
    masterSaltAfterUpdate: '0ca64d81411671b2',
};

// Cross-validation vectors for Method 2 (StaticDH/Sig, Suite 2) — deterministic up to MAC_2
const swiftM2 = {
    TH_1: '8656bb353c0f62546a8ea3c0fd13a59d7af2ef94deaeda10079c7a02d7159ff4',
    TH_2: 'a5168d16f33ad812d6b5ba55f8a8400cf6bb624d01a45155fbe612e078b8bc3d',
    PRK_2e: 'fbe3873abe6d8d24fb2324387fdd04eeccd1ea64fd49abdc98804bd23efcbf18',
    PRK_3e2m: 'fbe3873abe6d8d24fb2324387fdd04eeccd1ea64fd49abdc98804bd23efcbf18',
    MAC_2: '7b815c4fe241ac2492d95d548150e11fc874006398e2c901a91d62c6dd726ec8',
};

function makeSession(method: EdhocMethod, role: 'initiator' | 'responder', log: [string, string][]) {
    const isInitiator = role === 'initiator';
    const cert = isInitiator ? initiatorCert : responderCert;
    const key = isInitiator ? initiatorKey : responderKey;
    const ephemeral = isInitiator ? initiatorEphemeral : responderEphemeral;
    const connID = isInitiator ? 10 : 20;

    const credMgr = new X509CertificateCredentialManager([cert], key);
    credMgr.addTrustedCA(trustedCA);

    const crypto = new VectorsCryptoManager(ephemeral);

    const session = new EDHOC(connID, [method], [EdhocSuite.Suite2], credMgr, crypto);
    session.logger = (name: string, data: Buffer) => log.push([name, data.toString('hex')]);
    return session;
}

function getVal(log: [string, string][], key: string): string | undefined {
    return log.find(l => l[0] === key)?.[1];
}

describe('Cross-Validation: Swift <-> TypeScript', () => {

    describe('Method 3 (StaticDH/StaticDH) / Suite 2 — fully deterministic', () => {
        let iLog: [string, string][];
        let rLog: [string, string][];
        let initiator: EDHOC;
        let responder: EDHOC;

        beforeAll(async () => {
            iLog = [];
            rLog = [];
            initiator = makeSession(EdhocMethod.Method3, 'initiator', iLog);
            responder = makeSession(EdhocMethod.Method3, 'responder', rLog);

            const msg1 = await initiator.composeMessage1();
            await responder.processMessage1(msg1);
            const msg2 = await responder.composeMessage2();
            await initiator.processMessage2(msg2);
            const msg3 = await initiator.composeMessage3();
            await responder.processMessage3(msg3);
        });

        test('TH_1 matches Swift vector', () => {
            expect(getVal(iLog, 'TH_1')).toBe(swiftM3.TH_1);
        });

        test('TH_2 matches Swift vector', () => {
            expect(getVal(iLog, 'TH_2')).toBe(swiftM3.TH_2);
        });

        test('PRK_2e matches Swift vector', () => {
            expect(getVal(iLog, 'PRK_2e')).toBe(swiftM3.PRK_2e);
        });

        test('PRK_3e2m matches Swift vector', () => {
            expect(getVal(iLog, 'PRK_3e2m') || getVal(rLog, 'PRK_3e2m')).toBe(swiftM3.PRK_3e2m);
        });

        test('MAC_2 matches Swift vector', () => {
            expect(getVal(rLog, 'MAC_2')).toBe(swiftM3.MAC_2);
        });

        test('TH_3 matches Swift vector', () => {
            expect(getVal(iLog, 'TH_3') || getVal(rLog, 'TH_3')).toBe(swiftM3.TH_3);
        });

        test('PRK_4e3m matches Swift vector', () => {
            expect(getVal(iLog, 'PRK_4e3m')).toBe(swiftM3.PRK_4e3m);
        });

        test('MAC_3 matches Swift vector', () => {
            expect(getVal(iLog, 'MAC_3')).toBe(swiftM3.MAC_3);
        });

        test('TH_4 matches Swift vector', () => {
            expect(getVal(iLog, 'TH_4')).toBe(swiftM3.TH_4);
        });

        test('OSCORE master secret matches Swift vector', async () => {
            const iOSCORE = await initiator.exportOSCORE();
            expect(iOSCORE.masterSecret.toString('hex')).toBe(swiftM3.masterSecret);
        });

        test('OSCORE master salt matches Swift vector', async () => {
            const iOSCORE = await initiator.exportOSCORE();
            expect(iOSCORE.masterSalt.toString('hex')).toBe(swiftM3.masterSalt);
        });

        test('OSCORE contexts match between initiator and responder', async () => {
            const iOSCORE = await initiator.exportOSCORE();
            const rOSCORE = await responder.exportOSCORE();

            expect(iOSCORE.masterSecret).toEqual(rOSCORE.masterSecret);
            expect(iOSCORE.masterSalt).toEqual(rOSCORE.masterSalt);
            expect(iOSCORE.senderId).toEqual(rOSCORE.recipientId);
            expect(iOSCORE.recipientId).toEqual(rOSCORE.senderId);
        });

        test('OSCORE after keyUpdate matches Swift vector', async () => {
            await initiator.keyUpdate(keyUpdateContext);
            await responder.keyUpdate(keyUpdateContext);

            const iUpdated = await initiator.exportOSCORE();
            const rUpdated = await responder.exportOSCORE();

            expect(iUpdated.masterSecret.toString('hex')).toBe(swiftM3.masterSecretAfterUpdate);
            expect(iUpdated.masterSalt.toString('hex')).toBe(swiftM3.masterSaltAfterUpdate);

            expect(iUpdated.masterSecret).toEqual(rUpdated.masterSecret);
            expect(iUpdated.masterSalt).toEqual(rUpdated.masterSalt);
        });
    });

    describe('Method 2 (StaticDH/Sig) / Suite 2 — deterministic up to MAC_2', () => {
        let iLog: [string, string][];
        let rLog: [string, string][];
        let initiator: EDHOC;
        let responder: EDHOC;

        beforeAll(async () => {
            iLog = [];
            rLog = [];
            initiator = makeSession(EdhocMethod.Method2, 'initiator', iLog);
            responder = makeSession(EdhocMethod.Method2, 'responder', rLog);

            const msg1 = await initiator.composeMessage1();
            await responder.processMessage1(msg1);
            const msg2 = await responder.composeMessage2();
            await initiator.processMessage2(msg2);
            const msg3 = await initiator.composeMessage3();
            await responder.processMessage3(msg3);
        });

        test('TH_1 matches Swift vector', () => {
            expect(getVal(iLog, 'TH_1')).toBe(swiftM2.TH_1);
        });

        test('TH_2 matches Swift vector', () => {
            expect(getVal(iLog, 'TH_2')).toBe(swiftM2.TH_2);
        });

        test('PRK_2e matches Swift vector', () => {
            expect(getVal(iLog, 'PRK_2e')).toBe(swiftM2.PRK_2e);
        });

        test('PRK_3e2m matches Swift vector', () => {
            expect(getVal(iLog, 'PRK_3e2m') || getVal(rLog, 'PRK_3e2m')).toBe(swiftM2.PRK_3e2m);
        });

        test('MAC_2 matches Swift vector', () => {
            expect(getVal(rLog, 'MAC_2')).toBe(swiftM2.MAC_2);
        });

        test('OSCORE contexts match between initiator and responder', async () => {
            const iOSCORE = await initiator.exportOSCORE();
            const rOSCORE = await responder.exportOSCORE();

            expect(iOSCORE.masterSecret).toEqual(rOSCORE.masterSecret);
            expect(iOSCORE.masterSalt).toEqual(rOSCORE.masterSalt);
            expect(iOSCORE.senderId).toEqual(rOSCORE.recipientId);
            expect(iOSCORE.recipientId).toEqual(rOSCORE.senderId);
        });

        test('keyUpdate produces consistent OSCORE contexts', async () => {
            await initiator.keyUpdate(keyUpdateContext);
            await responder.keyUpdate(keyUpdateContext);

            const iUpdated = await initiator.exportOSCORE();
            const rUpdated = await responder.exportOSCORE();

            expect(iUpdated.masterSecret).toEqual(rUpdated.masterSecret);
            expect(iUpdated.masterSalt).toEqual(rUpdated.masterSalt);
        });
    });
});
