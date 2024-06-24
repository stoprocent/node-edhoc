"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DefaultEdhocCredentialManager = void 0;
const edhoc_1 = require("./edhoc");
class DefaultEdhocCredentialManager extends edhoc_1.EdhocCredentialManager {
    fetch = async (edhoc) => {
        return Promise.resolve({ format: 0, privateKeyID: Buffer.alloc(0) });
    };
    verify = async (edhoc, credentials) => {
        return Promise.resolve(credentials);
    };
}
exports.DefaultEdhocCredentialManager = DefaultEdhocCredentialManager;
