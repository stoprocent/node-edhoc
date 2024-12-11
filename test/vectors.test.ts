import { EDHOC, X509CertificateCredentialManager, DefaultEdhocCryptoManager, EdhocMethod, EdhocSuite, EdhocCredentialsFormat, EdhocKeyType } from '../dist/index'

class VectorsEdhocCryptoManager extends DefaultEdhocCryptoManager {

    async importKey(edhoc: EDHOC, keyType: EdhocKeyType, key: Buffer) {
        // Method 0, Suite 0, Connection ID -14 - Initiator
        if (keyType === EdhocKeyType.MakeKeyPair && key && edhoc.connectionID === -14) {
            key = Buffer.from('892EC28E5CB6669108470539500B705E60D008D347C5817EE9F3327C8A87BB03', 'hex');
        }
        // Method 0, Suite 0, Connection ID 0x18 - Responder
        if (keyType === EdhocKeyType.MakeKeyPair && key && Buffer.isBuffer(edhoc.connectionID) && Buffer.compare(edhoc.connectionID, Buffer.from([0x18])) === 0) {
            key = Buffer.from('E69C23FBF81BC435942446837FE827BF206C8FA10A39DB47449E5A813421E1E8', 'hex');
        }
        return super.importKey(edhoc, keyType, key);
    }
}

describe('EDHOC RFC9529 Test Vectors', () => {
    // Test setup variables
    const trustedCA = Buffer.from('3082010E3081C1A003020102020462319E74300506032B6570301D311B301906035504030C124544484F4320526F6F742045643235353139301E170D3232303331363038323331365A170D3239313233313233303030305A301D311B301906035504030C124544484F4320526F6F742045643235353139302A300506032B65700321002B7B3E8057C8642944D06AFE7A71D1C9BF961B6292BAC4B04F91669BBB713BE4A3233021300E0603551D0F0101FF040403020204300F0603551D130101FF040530030101FF300506032B65700341004BB52BBF1539B71A4AAF429778F29EDA7E814680698F16C48F2A6FA4DBE82541C58207BA1BC9CDB0C2FA947FFBF0F0EC0EE91A7FF37A94D9251FA5CDF1E67A0F', 'hex');
    const keyUpdate = Buffer.from('d6be169602b8bceaa01158fdb820890c', 'hex');

    const masterSecret = Buffer.from('1e1c6beac3a8a1cac435de7e2f9ae7ff', 'hex');
    const masterSalt = Buffer.from('ce7ab844c0106d73', 'hex');

    const masterSecret_Update = Buffer.from('ee0ff542c47eb0e09c69307649bdbbe5', 'hex');
    const masterSalt_Update = Buffer.from('80cede2a1e5aab48', 'hex');

    // Initiator Identity
    const initiatorCert = Buffer.from('3081EE3081A1A003020102020462319EA0300506032B6570301D311B301906035504030C124544484F4320526F6F742045643235353139301E170D3232303331363038323430305A170D3239313233313233303030305A30223120301E06035504030C174544484F4320496E69746961746F722045643235353139302A300506032B6570032100ED06A8AE61A829BA5FA54525C9D07F48DD44A302F43E0F23D8CC20B73085141E300506032B6570034100521241D8B3A770996BCFC9B9EAD4E7E0A1C0DB353A3BDF2910B39275AE48B756015981850D27DB6734E37F67212267DD05EEFF27B9E7A813FA574B72A00B430B', 'hex');
    const initiatorKey = Buffer.from('4C5B25878F507C6B9DAE68FBD4FD3FF997533DB0AF00B25D324EA28E6C213BC8', 'hex');
    const initiatorKeyID = Buffer.from('00000001', 'hex');
    
    // Responder Identity
    const responderCert = Buffer.from('3081EE3081A1A003020102020462319EC4300506032B6570301D311B301906035504030C124544484F4320526F6F742045643235353139301E170D3232303331363038323433365A170D3239313233313233303030305A30223120301E06035504030C174544484F4320526573706F6E6465722045643235353139302A300506032B6570032100A1DB47B95184854AD12A0C1A354E418AACE33AA0F2C662C00B3AC55DE92F9359300506032B6570034100B723BC01EAB0928E8B2B6C98DE19CC3823D46E7D6987B032478FECFAF14537A1AF14CC8BE829C6B73044101837EB4ABC949565D86DCE51CFAE52AB82C152CB02', 'hex');
    const responderKey = Buffer.from('EF140FF900B0AB03F0C08D879CBBD4B31EA71E6E7EE7FFCB7E7955777A332799', 'hex');
    const responderKeyID = Buffer.from('00000002', 'hex');
    
    let initiator: EDHOC;
    let responder: EDHOC;

    beforeEach(() => {
        // Initiator Setup
        const initiatorCredentialManager = new X509CertificateCredentialManager([initiatorCert], initiatorKeyID);
        initiatorCredentialManager.addTrustedCA(trustedCA);
        initiatorCredentialManager.addPeerCertificate(responderCert);
        initiatorCredentialManager.fetchFormat = EdhocCredentialsFormat.x5t;

        // Initiator Crypto Manager
        const initiatorCryptoManager = new VectorsEdhocCryptoManager();
        initiatorCryptoManager.addKey(initiatorKeyID, initiatorKey);

        // Responder Setup
        const responderCredentialManager = new X509CertificateCredentialManager([responderCert], responderKeyID);
        responderCredentialManager.addTrustedCA(trustedCA);
        responderCredentialManager.addPeerCertificate(initiatorCert);
        responderCredentialManager.fetchFormat = EdhocCredentialsFormat.x5t;

        // Responder Crypto Manager
        const responderCryptoManager = new VectorsEdhocCryptoManager();
        responderCryptoManager.addKey(responderKeyID, responderKey);

        // Initialize EDHOC instances
        initiator = new EDHOC(-14, [EdhocMethod.Method0], [EdhocSuite.Suite0], initiatorCredentialManager, initiatorCryptoManager);
        responder = new EDHOC(Buffer.from([0x18]), [EdhocMethod.Method0], [EdhocSuite.Suite0], responderCredentialManager, responderCryptoManager);
    });

    test('should complete successful EDHOC handshake', async () => {
        // Perform the three-message handshake
        const message1 = await initiator.composeMessage1();
        const ead1 = await responder.processMessage1(message1);
        expect(ead1).toEqual([]);

        const message2 = await responder.composeMessage2();
        const ead2 = await initiator.processMessage2(message2);
        expect(ead2).toEqual([]);

        const message3 = await initiator.composeMessage3();
        const ead3 = await responder.processMessage3(message3);
        expect(ead3).toEqual([]);

        const message4 = await initiator.composeMessage4();
        const ead4 = await responder.processMessage4(message4);
        expect(ead4).toEqual([]);

        const initiatorOSCORE = await initiator.exportOSCORE();
        const responderOSCORE = await responder.exportOSCORE();

        expect(initiatorOSCORE.masterSalt).toEqual(responderOSCORE.masterSalt);
        expect(initiatorOSCORE.masterSecret).toEqual(responderOSCORE.masterSecret);
        expect(initiatorOSCORE.senderId).toEqual(responderOSCORE.recipientId);
        expect(initiatorOSCORE.recipientId).toEqual(responderOSCORE.senderId);

        expect(initiatorOSCORE.masterSalt).toEqual(masterSalt);
        expect(initiatorOSCORE.masterSecret).toEqual(masterSecret);

        await initiator.keyUpdate(keyUpdate);
        await responder.keyUpdate(keyUpdate);

        const initiatorOSCORE_Update = await initiator.exportOSCORE();
        const responderOSCORE_Update = await responder.exportOSCORE();

        expect(initiatorOSCORE_Update.masterSalt).toEqual(responderOSCORE_Update.masterSalt);
        expect(initiatorOSCORE_Update.masterSecret).toEqual(responderOSCORE_Update.masterSecret);
        expect(initiatorOSCORE_Update.senderId).toEqual(responderOSCORE_Update.recipientId);
        expect(initiatorOSCORE_Update.recipientId).toEqual(responderOSCORE_Update.senderId);

        expect(initiatorOSCORE_Update.masterSecret).toEqual(masterSecret_Update);
        expect(initiatorOSCORE_Update.masterSalt).toEqual(masterSalt_Update);
    });
});
