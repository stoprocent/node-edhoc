import { EDHOC, X509CertificateCredentialManager, DefaultEdhocCryptoManager, EdhocMethod, EdhocSuite } from '../dist/index'

const trustedCA = Buffer.from('308201323081DAA003020102021478408C6EC18A1D452DAE70C726CB0192A6116DBB300A06082A8648CE3D040302301A3118301606035504030C0F5468697320697320434120526F6F74301E170D3234313031393138333635335A170D3235313031393138333635335A301A3118301606035504030C0F5468697320697320434120526F6F743059301306072A8648CE3D020106082A8648CE3D03010703420004B9348A8A267EF52CFDC30109A29008A2D99F6B8F78BA9EAF5D51578C06134E78CB90A073EDC2488A14174B4E2997C840C5DE7F8E35EB54A0DB6977E894D1B2CB300A06082A8648CE3D040302034700304402203B92BFEC770B0FA4E17F8F02A13CD945D914ED8123AC85C37C8C7BAA2BE3E0F102202CB2DC2EC295B5F4B7BB631ED751179C145D6B6E081559AEA38CE215369E9C31', 'hex');

const initiatorKeyID = Buffer.from('00000001', 'hex');
const initiatorCredentialManager = new X509CertificateCredentialManager(
    [Buffer.from('3082012E3081D4A003020102021453423D5145C767CDC29895C3DB590192A611EA50300A06082A8648CE3D040302301A3118301606035504030C0F5468697320697320434120526F6F74301E170D3234313031393138333732345A170D3235313031393138333732345A30143112301006035504030C09696E69746961746F723059301306072A8648CE3D020106082A8648CE3D03010703420004EB0EF585F3992A1653CF310BF0F0F8035267CDAB6989C8B02E7228FBD759EF6B56263259AADF087F9849E7B7651F74C3B4F144CCCF86BB6FE2FF0EF3AA5FB5DC300A06082A8648CE3D0403020349003046022100D8C3AA7C98A730B3D4862EDAB4C1474FCD9A17A9CA3FB078914A10978FE95CC40221009F5877DD4E2C635A04ED1F6F1854C87B58521BDDFF533B1076F53D456739764C', 'hex')],
    initiatorKeyID
);
initiatorCredentialManager.addTrustCA(trustedCA);

const initiatorCryptoManager = new DefaultEdhocCryptoManager();
initiatorCryptoManager.addKey(initiatorKeyID, Buffer.from('DC1FBB05B6B08360CE5B9EEA08EBFBFC6766A21340641863D4C8A3F68F096337', 'hex'));


const responderKeyID = Buffer.from('00000002', 'hex');
const responderCredentialManager = new X509CertificateCredentialManager(
    [Buffer.from('3082012E3081D4A00302010202146648869E2608FC2E16D945C10E1F0192A6125CC0300A06082A8648CE3D040302301A3118301606035504030C0F5468697320697320434120526F6F74301E170D3234313031393138333735345A170D3235313031393138333735345A30143112301006035504030C09726573706F6E6465723059301306072A8648CE3D020106082A8648CE3D03010703420004161F76A7A106C9B79B7F651156B5B095E63A6101A39020F4E86DDACE61FB395E8AEF6CD9C444EE9A43DBD62DAD44FF50FE4146247D3AFD28F60DBC01FBFC573C300A06082A8648CE3D0403020349003046022100E8AD0926518CDB61E84D171700C7158FD0E72D03A117D40133ECD10F8B9F42CE022100E7E69B4C79100B3F0792F010AE11EE5DD2859C29EFC4DBCEFD41FA5CD4D3C3C9', 'hex')],
    responderKeyID
);
responderCredentialManager.addTrustCA(trustedCA);

const responderCryptoManager = new DefaultEdhocCryptoManager();
responderCryptoManager.addKey(responderKeyID, Buffer.from('EE6287116FE27CDC539629DC87E12BF8EAA2229E7773AA67BC4C0FBA96E7FBB2', 'hex'));

const method = [EdhocMethod.Method1];
const method_r = [EdhocMethod.Method2, EdhocMethod.Method0, EdhocMethod.Method1];

const initiator = new EDHOC(10, method, [ EdhocSuite.Suite2 ], initiatorCredentialManager, initiatorCryptoManager);
const responder = new EDHOC(20, method_r, [ EdhocSuite.Suite2 ], responderCredentialManager, responderCryptoManager);

// initiator.logger = (name, value) => console.log("INITIATOR", name, value.toString('hex'));
// responder.logger = (name, value) => console.log(colors.red("RESPONDER"), colors.green(name), colors.yellow(value.toString('hex')), "\n");

async function run() {
    try {
        let message_1 = await initiator.composeMessage1([{ label: 1, value: Buffer.from('Hello') }])
        console.log("message_1", message_1.toString('hex'));

        let ead_1 = await responder.processMessage1(message_1);
        console.log("ead_1", ead_1);

        let message_2 = await responder.composeMessage2();
        console.log("message_2", message_2.toString('hex'));

        let ead_2 = await initiator.processMessage2(message_2);
        console.log("ead_2", ead_2);

        let message_3 = await initiator.composeMessage3();
        console.log("message_3", message_3.toString('hex'));

        let ead_3 = await responder.processMessage3(message_3);
        console.log("ead_3", ead_3);

        console.log("initiator", await initiator.exportOSCORE());
        console.log("responder", await responder.exportOSCORE());

        console.log("initiator key :", await initiator.exportKey(40001, 32));
        console.log("responder key :", await responder.exportKey(40001, 32));
    }
    catch (error) {
        console.log("ERROR");
        console.log(error);
    }
}
run();
