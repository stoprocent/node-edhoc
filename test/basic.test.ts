import { randomBytes } from 'crypto';
import { EDHOC, X509CertificateCredentialManager, DefaultEdhocCryptoManager, EdhocMethod, EdhocSuite, EdhocKeyType, EdhocCryptoManager } from '../dist/index'

describe('EDHOC Handshake', () => {
    // Test setup variables
    const trustedCA = Buffer.from('308201323081DAA003020102021478408C6EC18A1D452DAE70C726CB0192A6116DBB300A06082A8648CE3D040302301A3118301606035504030C0F5468697320697320434120526F6F74301E170D3234313031393138333635335A170D3235313031393138333635335A301A3118301606035504030C0F5468697320697320434120526F6F743059301306072A8648CE3D020106082A8648CE3D03010703420004B9348A8A267EF52CFDC30109A29008A2D99F6B8F78BA9EAF5D51578C06134E78CB90A073EDC2488A14174B4E2997C840C5DE7F8E35EB54A0DB6977E894D1B2CB300A06082A8648CE3D040302034700304402203B92BFEC770B0FA4E17F8F02A13CD945D914ED8123AC85C37C8C7BAA2BE3E0F102202CB2DC2EC295B5F4B7BB631ED751179C145D6B6E081559AEA38CE215369E9C31', 'hex');
    let initiator: EDHOC;
    let responder: EDHOC;
    
    let staticDhKeyInitiator: Buffer;
    let staticDhKeyResponder: Buffer;
    
    let initiatorCredentialManager: X509CertificateCredentialManager;
    let responderCredentialManager: X509CertificateCredentialManager;

    let initiatorCryptoManager: EdhocCryptoManager;
    let responderCryptoManager: EdhocCryptoManager;

    class StaticCryptoManager extends DefaultEdhocCryptoManager {

        async importKey(edhoc: EDHOC, keyType: EdhocKeyType, key: Buffer) {
            if (keyType === EdhocKeyType.MakeKeyPair && key && edhoc.connectionID === 10) {
                key = staticDhKeyInitiator
            }
            if (keyType === EdhocKeyType.MakeKeyPair && key && edhoc.connectionID === 20) {
                key = staticDhKeyResponder
            }
            return super.importKey(edhoc, keyType, key);
        }
    }

    beforeAll(() => {
        staticDhKeyInitiator = randomBytes(32);
        staticDhKeyResponder = randomBytes(32);
    })

    beforeEach(() => {
        // Initialize credentials and crypto managers for both parties
        const initiatorKeyID = Buffer.from('00000001', 'hex');
        initiatorCredentialManager = new X509CertificateCredentialManager(
            [Buffer.from('3082012E3081D4A003020102021453423D5145C767CDC29895C3DB590192A611EA50300A06082A8648CE3D040302301A3118301606035504030C0F5468697320697320434120526F6F74301E170D3234313031393138333732345A170D3235313031393138333732345A30143112301006035504030C09696E69746961746F723059301306072A8648CE3D020106082A8648CE3D03010703420004EB0EF585F3992A1653CF310BF0F0F8035267CDAB6989C8B02E7228FBD759EF6B56263259AADF087F9849E7B7651F74C3B4F144CCCF86BB6FE2FF0EF3AA5FB5DC300A06082A8648CE3D0403020349003046022100D8C3AA7C98A730B3D4862EDAB4C1474FCD9A17A9CA3FB078914A10978FE95CC40221009F5877DD4E2C635A04ED1F6F1854C87B58521BDDFF533B1076F53D456739764C', 'hex')],
            initiatorKeyID
        );
        initiatorCredentialManager.addTrustedCA(trustedCA);

        initiatorCryptoManager = new DefaultEdhocCryptoManager();
        initiatorCryptoManager.addKey(initiatorKeyID, Buffer.from('DC1FBB05B6B08360CE5B9EEA08EBFBFC6766A21340641863D4C8A3F68F096337', 'hex'));

        const responderKeyID = Buffer.from('00000002', 'hex');
        responderCredentialManager = new X509CertificateCredentialManager(
            [Buffer.from('3082012E3081D4A00302010202146648869E2608FC2E16D945C10E1F0192A6125CC0300A06082A8648CE3D040302301A3118301606035504030C0F5468697320697320434120526F6F74301E170D3234313031393138333735345A170D3235313031393138333735345A30143112301006035504030C09726573706F6E6465723059301306072A8648CE3D020106082A8648CE3D03010703420004161F76A7A106C9B79B7F651156B5B095E63A6101A39020F4E86DDACE61FB395E8AEF6CD9C444EE9A43DBD62DAD44FF50FE4146247D3AFD28F60DBC01FBFC573C300A06082A8648CE3D0403020349003046022100E8AD0926518CDB61E84D171700C7158FD0E72D03A117D40133ECD10F8B9F42CE022100E7E69B4C79100B3F0792F010AE11EE5DD2859C29EFC4DBCEFD41FA5CD4D3C3C9', 'hex')],
            responderKeyID
        );
        responderCredentialManager.addTrustedCA(trustedCA);

        responderCryptoManager = new DefaultEdhocCryptoManager();
        responderCryptoManager.addKey(responderKeyID, Buffer.from('EE6287116FE27CDC539629DC87E12BF8EAA2229E7773AA67BC4C0FBA96E7FBB2', 'hex'));

        // Initialize EDHOC instances
        initiator = new EDHOC(10, [EdhocMethod.Method1], [EdhocSuite.Suite2], initiatorCredentialManager, initiatorCryptoManager);
        responder = new EDHOC(20, [EdhocMethod.Method2, EdhocMethod.Method0, EdhocMethod.Method1], [EdhocSuite.Suite2], responderCredentialManager, responderCryptoManager);
    });

    test('should complete successful EDHOC handshake', async () => {
        // Perform the three-message handshake
        const message1 = await initiator.composeMessage1([{ label: 1, value: Buffer.from('Hello') }]);
        const ead1 = await responder.processMessage1(message1);
        expect(ead1[0].value.toString()).toBe('Hello');

        const message2 = await responder.composeMessage2();
        const ead2 = await initiator.processMessage2(message2);
        expect(ead2).toEqual([]);

        const message3 = await initiator.composeMessage3();
        const ead3 = await responder.processMessage3(message3);
        expect(ead3).toEqual([]);

        // Verify that both parties derived the same OSCORE security context
        const initiatorOSCORE = await initiator.exportOSCORE();
        const responderOSCORE = await responder.exportOSCORE();
        
        expect(initiatorOSCORE.masterSalt).toEqual(responderOSCORE.masterSalt);
        expect(initiatorOSCORE.masterSecret).toEqual(responderOSCORE.masterSecret);
        expect(initiatorOSCORE.senderId).toEqual(responderOSCORE.recipientId);
        expect(initiatorOSCORE.recipientId).toEqual(responderOSCORE.senderId);

        // Verify that both parties can derive the same application keys
        const initiatorKey = await initiator.exportKey(40001, 32);
        const responderKey = await responder.exportKey(40001, 32);
        expect(initiatorKey).toEqual(responderKey);
    });

    test('should fail to generate message 1 twice', async () => {
        await initiator.composeMessage1();
        await expect(initiator.composeMessage1()).rejects.toThrow();
    });

    describe('should NOT fail to generate message 1 twice', () => {

        it('messages should be different', async () => {
            const message_a = await responder.composeMessage1();
            await responder.reset();
            const message_b = await responder.composeMessage1();
            expect(message_a).not.toEqual(message_b);
        });

        it('messages should be the same', async () => {
            initiatorCryptoManager = new StaticCryptoManager();
            responderCryptoManager = new StaticCryptoManager();
            
            initiator = new EDHOC(10, [EdhocMethod.Method1], [EdhocSuite.Suite2], initiatorCredentialManager, initiatorCryptoManager);
            responder = new EDHOC(20, [EdhocMethod.Method2, EdhocMethod.Method0, EdhocMethod.Method1], [EdhocSuite.Suite2], responderCredentialManager, responderCryptoManager);

            const message_a = await responder.composeMessage1();
            await responder.reset();
            const message_b = await responder.composeMessage1();

            expect(message_a).toEqual(message_b);
        });
    });
});
