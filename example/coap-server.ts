import { createServer } from 'coap'
import { EDHOC, DefaultEdhocCredentialManager, DefaultEdhocCryptoManager, EdhocMethod, EdhocSuite, X509Credentials } from '../dist/index'
import { randomBytes } from 'crypto'
import { decodeAll } from 'cbor'

const server = createServer({ type: 'udp4' });
const sessions = new Map<string, EDHOC>();

const credentialManager = new DefaultEdhocCredentialManager();
const cryptoManager = new DefaultEdhocCryptoManager();

const certificateR_p256 = new X509Credentials(
    Buffer.from('3082011e3081c5a003020102020461e9981e300a06082a8648ce3d04030230153113301106035504030c0a4544484f4320526f6f74301e170d3232303132303137313330325a170d3239313233313233303030305a301a3118301606035504030c0f4544484f4320526573706f6e6465723059301306072a8648ce3d020106082a8648ce3d03010703420004bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f04519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072300a06082a8648ce3d0403020348003045022030194ef5fc65c8b795cdcd0bb431bf83ee6741c1370c22c8eb8ee9edd2a70519022100b5830e9c89a62ac73ce1ebce0061707db8a88e23709b4acc58a1313b133d0558', 'hex'), 
    Buffer.from('72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac', 'hex')
);

const rootCertificate = Buffer.from('308201183081c0a003020102020461e997c5300a06082a8648ce3d04030230153113301106035504030c0a4544484f4320526f6f74301e170d3232303132303137313133335a170d3239313233313233303030305a30153113301106035504030c0a4544484f4320526f6f743059301306072a8648ce3d020106082a8648ce3d0301070342000427ecf4b466d3cd61144c944021838d57bf6701973378a15b3f5d27575d34c4a97b79e0f24b446bca67e13d75d09573124b49b838b10973f0fb67e126051c9595300a06082a8648ce3d0403020347003044022013734326f2ca35d1aedb6d5e1c8eb7b965da67ead3314e502909b9d757cba168022049ba0ba4f06efe8c0d9c3d3115eb9c96ca46d128499b68957d0a85af136bf306', 'hex');

credentialManager.setCredentials(cryptoManager, certificateR_p256);
credentialManager.addTrustRoot(rootCertificate);

server.on('request', async (req, res) => {
    if (req.method === 'POST' && req.url === '/.well-known/edhoc') {
        // Handle Initialization
        let isTrue = false;
        let method = EdhocMethod.Method0;

        try {
            const payload = await decodeAll(req.payload);
            isTrue = (typeof payload[0] == "boolean") && payload[0] === true;
            method = payload[1] as EdhocMethod;
        }
        catch {
            // Do nothing
        }

        if (isTrue) {
            // Responder creates a new session
            const connectionID = randomBytes(4);
            const responder = new EDHOC(connectionID, method, [ EdhocSuite.Suite2 ], credentialManager, cryptoManager);
            
            responder.logger = (name, value) => console.log(name, value.toString('hex'), `\n`);

            // Process message 1
            const message1 = req.payload.subarray(1);
            console.log("message1", message1.toString('hex'));
            const ead_1 = await responder.processMessage1(message1);
            console.log("ead_1", ead_1);
            
            // Generate message 2
            const message2 = await responder.composeMessage2([{ label: 1245, value: Buffer.from('00112233445566', 'hex') }]);
            console.log("message2", message2.toString('hex'));
            
            // Store Sesssion
            sessions.set(connectionID.toString('hex'), responder);

            // Respond with message 2
            res.end(message2);
        }
        else {
            try {
                // Decode CBOR
                const payload = await decodeAll(req.payload);
                const responder = sessions.get(payload[0].toString('hex'));
                
                // Check Session
                if (responder === undefined) {
                    throw new Error('Session does not exist')
                }

                // Message 3
                const message3 = req.payload.slice(payload[0].length + 1);               
                const ead_3 = await responder.processMessage3(message3);
                console.log("ead_3", ead_3);
                console.log("OSCORE Context", await responder.exportOSCORE());

                // Respond
                res.end();
            }
            catch (error) {
                res.code = '5.00';
                res.end(error);
            }
        }

    } 
});

server.listen(5683, () => {

});