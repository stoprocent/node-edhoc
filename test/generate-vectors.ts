/**
 * Generate cross-validation test vectors for Methods 2 and 3 with Suite 2 (P-256).
 *
 * Method 3 (StaticDH/StaticDH) has NO signatures, so all values are fully
 * deterministic in both TypeScript (noble) and Swift (CryptoKit).
 *
 * Method 2 (StaticDH/Sig) has the responder sign, so TS produces deterministic
 * signatures while Swift (CryptoKit) produces hedged ones. All values before
 * Signature_or_MAC_2 are deterministic in both.
 */

import { EDHOC, X509CertificateCredentialManager, DefaultEdhocCryptoManager, EdhocMethod, EdhocSuite, PublicPrivateTuple } from '../dist/index';
import { p256 } from '@noble/curves/p256';

// Shared test data (same certificates/keys as BasicHandshakeTests)
const trustedCA = Buffer.from('308201323081DAA003020102021478408C6EC18A1D452DAE70C726CB0192A6116DBB300A06082A8648CE3D040302301A3118301606035504030C0F5468697320697320434120526F6F74301E170D3234313031393138333635335A170D3235313031393138333635335A301A3118301606035504030C0F5468697320697320434120526F6F743059301306072A8648CE3D020106082A8648CE3D03010703420004B9348A8A267EF52CFDC30109A29008A2D99F6B8F78BA9EAF5D51578C06134E78CB90A073EDC2488A14174B4E2997C840C5DE7F8E35EB54A0DB6977E894D1B2CB300A06082A8648CE3D040302034700304402203B92BFEC770B0FA4E17F8F02A13CD945D914ED8123AC85C37C8C7BAA2BE3E0F102202CB2DC2EC295B5F4B7BB631ED751179C145D6B6E081559AEA38CE215369E9C31', 'hex');

const initiatorCert = Buffer.from('3082012E3081D4A003020102021453423D5145C767CDC29895C3DB590192A611EA50300A06082A8648CE3D040302301A3118301606035504030C0F5468697320697320434120526F6F74301E170D3234313031393138333732345A170D3235313031393138333732345A30143112301006035504030C09696E69746961746F723059301306072A8648CE3D020106082A8648CE3D03010703420004EB0EF585F3992A1653CF310BF0F0F8035267CDAB6989C8B02E7228FBD759EF6B56263259AADF087F9849E7B7651F74C3B4F144CCCF86BB6FE2FF0EF3AA5FB5DC300A06082A8648CE3D0403020349003046022100D8C3AA7C98A730B3D4862EDAB4C1474FCD9A17A9CA3FB078914A10978FE95CC40221009F5877DD4E2C635A04ED1F6F1854C87B58521BDDFF533B1076F53D456739764C', 'hex');
const initiatorKey = Buffer.from('DC1FBB05B6B08360CE5B9EEA08EBFBFC6766A21340641863D4C8A3F68F096337', 'hex');

const responderCert = Buffer.from('3082012E3081D4A00302010202146648869E2608FC2E16D945C10E1F0192A6125CC0300A06082A8648CE3D040302301A3118301606035504030C0F5468697320697320434120526F6F74301E170D3234313031393138333735345A170D3235313031393138333735345A30143112301006035504030C09726573706F6E6465723059301306072A8648CE3D020106082A8648CE3D03010703420004161F76A7A106C9B79B7F651156B5B095E63A6101A39020F4E86DDACE61FB395E8AEF6CD9C444EE9A43DBD62DAD44FF50FE4146247D3AFD28F60DBC01FBFC573C300A06082A8648CE3D0403020349003046022100E8AD0926518CDB61E84D171700C7158FD0E72D03A117D40133ECD10F8B9F42CE022100E7E69B4C79100B3F0792F010AE11EE5DD2859C29EFC4DBCEFD41FA5CD4D3C3C9', 'hex');
const responderKey = Buffer.from('EE6287116FE27CDC539629DC87E12BF8EAA2229E7773AA67BC4C0FBA96E7FBB2', 'hex');

// Fixed ephemeral DH keys (P-256 private keys, 32 bytes)
const initiatorEphemeral = Buffer.from('3717F87F867BC4C8AB4A564093F1CC4A5414C24DB2ED0690CFAC651A02A04010', 'hex');
const responderEphemeral = Buffer.from('A7FFB1B45F2B570893B0E31C8AAF9C1C0E88C133E15CF2C0B89E5E3074B2D2A0', 'hex');

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

async function generateVectors(method: EdhocMethod, methodName: string) {
    const iLog: [string, string][] = [];
    const rLog: [string, string][] = [];

    const iCredMgr = new X509CertificateCredentialManager([initiatorCert], initiatorKey);
    iCredMgr.addTrustedCA(trustedCA);

    const iCrypto = new VectorsCryptoManager(initiatorEphemeral);

    const rCredMgr = new X509CertificateCredentialManager([responderCert], responderKey);
    rCredMgr.addTrustedCA(trustedCA);

    const rCrypto = new VectorsCryptoManager(responderEphemeral);

    const initiator = new EDHOC(10, [method], [EdhocSuite.Suite2], iCredMgr, iCrypto);
    const responder = new EDHOC(20, [method], [EdhocSuite.Suite2], rCredMgr, rCrypto);

    initiator.logger = (name: string, data: Buffer) => iLog.push([name, data.toString('hex')]);
    responder.logger = (name: string, data: Buffer) => rLog.push([name, data.toString('hex')]);

    // Three-message handshake
    const msg1 = await initiator.composeMessage1();
    await responder.processMessage1(msg1);

    const msg2 = await responder.composeMessage2();
    await initiator.processMessage2(msg2);

    const msg3 = await initiator.composeMessage3();
    await responder.processMessage3(msg3);

    // Export OSCORE
    const iOSCORE = await initiator.exportOSCORE();
    const rOSCORE = await responder.exportOSCORE();

    // Key update
    const keyUpdateContext = Buffer.from('a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6', 'hex');
    await initiator.keyUpdate(keyUpdateContext);
    await responder.keyUpdate(keyUpdateContext);
    const iOSCOREUpdated = await initiator.exportOSCORE();

    console.log(`\n=== ${methodName} / Suite 2 (P-256) ===\n`);

    // Print all logged values
    for (const key of ['message_1', 'TH_1', 'G_Y', 'G_XY', 'TH_2', 'PRK_2e', 'PRK_3e2m',
                        'MAC_2', 'Signature_or_MAC_2', 'PLAINTEXT_2', 'CIPHERTEXT_2', 'TH_3',
                        'PRK_4e3m', 'MAC_3', 'Signature_or_MAC_3', 'PLAINTEXT_3', 'CIPHERTEXT_3', 'TH_4',
                        'message_2', 'message_3']) {
        const iVal = iLog.find(l => l[0] === key)?.[1];
        const rVal = rLog.find(l => l[0] === key)?.[1];
        const val = iVal || rVal;
        if (val) {
            const tag = iVal && rVal && iVal !== rVal ? ' (I/R DIFFER)' : '';
            console.log(`${key}: ${val}${tag}`);
        }
    }

    console.log(`\nOSCORE:`);
    console.log(`  masterSecret: ${iOSCORE.masterSecret.toString('hex')}`);
    console.log(`  masterSalt:   ${iOSCORE.masterSalt.toString('hex')}`);
    console.log(`  i.senderId:   ${iOSCORE.senderId.toString('hex')}`);
    console.log(`  i.recipientId:${iOSCORE.recipientId.toString('hex')}`);
    console.log(`  match: secret=${iOSCORE.masterSecret.equals(rOSCORE.masterSecret)} salt=${iOSCORE.masterSalt.equals(rOSCORE.masterSalt)}`);

    console.log(`\nOSCORE after keyUpdate(a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6):`);
    console.log(`  masterSecret: ${iOSCOREUpdated.masterSecret.toString('hex')}`);
    console.log(`  masterSalt:   ${iOSCOREUpdated.masterSalt.toString('hex')}`);
}

(async () => {
    await generateVectors(EdhocMethod.Method3, 'Method 3 (StaticDH/StaticDH)');
    await generateVectors(EdhocMethod.Method2, 'Method 2 (StaticDH/Sig)');
})();
