import { EDHOC, DefaultEdhocCredentialManager, DefaultEdhocCryptoManager, EdhocMethod, EdhocSuite } from '../dist/index'

const credentialManager = new DefaultEdhocCredentialManager();
const cryptoManager = new DefaultEdhocCryptoManager();

const edhoc = new EDHOC(10, EdhocMethod.Method0, [ EdhocSuite.Suite2 ], credentialManager, cryptoManager);

async function run() {
    try {
        let message = await edhoc.composeMessage1()
        console.log(message.toString('hex'));
    }
    catch (error) {
        console.log(error);
    }
}
run();
