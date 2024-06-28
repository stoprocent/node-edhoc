"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DefaultEdhocCredentialManager = void 0;
const edhoc_1 = require("./edhoc");
class DefaultEdhocCredentialManager {
    fetch(edhoc) {
        return Promise.resolve({ format: edhoc_1.EdhocCredentialsFormat.kid, privateKeyID: Buffer.alloc(0) });
    }
    verify(edhoc, credentials) {
        return Promise.resolve(credentials);
    }
}
exports.DefaultEdhocCredentialManager = DefaultEdhocCredentialManager;
