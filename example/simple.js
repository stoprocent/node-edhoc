"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const index_1 = require("../dist/index");
const credentialManager = new index_1.DefaultEdhocCredentialManager();
const cryptoManager = new index_1.DefaultEdhocCryptoManager();
const edhoc = new index_1.EDHOC(10, index_1.EdhocMethod.Method0, [index_1.EdhocSuite.Suite2], credentialManager, cryptoManager);
async function run() {
    let message = await edhoc.composeMessage1();
    console.log(message.toString('hex'));
}
run();
