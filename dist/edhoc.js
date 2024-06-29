"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.EdhocSuite = exports.EdhocMethod = exports.EdhocKeyType = exports.EdhocCredentialsCertificateHashAlgorithm = exports.EdhocCredentialsFormat = void 0;
/**
 * Enumerates the types of credential formats that can be used with EDHOC.
 */
var EdhocCredentialsFormat;
(function (EdhocCredentialsFormat) {
    EdhocCredentialsFormat[EdhocCredentialsFormat["kid"] = 4] = "kid";
    EdhocCredentialsFormat[EdhocCredentialsFormat["x5chain"] = 33] = "x5chain";
    EdhocCredentialsFormat[EdhocCredentialsFormat["x5t"] = 34] = "x5t"; // Represents a hashed X.509 certificate.
})(EdhocCredentialsFormat || (exports.EdhocCredentialsFormat = EdhocCredentialsFormat = {}));
/**
 * Enumerates the types of hash algorithms that can be used with hashed X.509 certificates.
 */
var EdhocCredentialsCertificateHashAlgorithm;
(function (EdhocCredentialsCertificateHashAlgorithm) {
    EdhocCredentialsCertificateHashAlgorithm[EdhocCredentialsCertificateHashAlgorithm["Sha256"] = -16] = "Sha256";
    EdhocCredentialsCertificateHashAlgorithm[EdhocCredentialsCertificateHashAlgorithm["Sha256_64"] = -15] = "Sha256_64"; // SHA-256 truncated to 64 bits.
})(EdhocCredentialsCertificateHashAlgorithm || (exports.EdhocCredentialsCertificateHashAlgorithm = EdhocCredentialsCertificateHashAlgorithm = {}));
/**
 * Enumerates the types of cryptographic operations that can be performed with EDHOC.
 */
var EdhocKeyType;
(function (EdhocKeyType) {
    EdhocKeyType[EdhocKeyType["MakeKeyPair"] = 0] = "MakeKeyPair";
    EdhocKeyType[EdhocKeyType["KeyAgreement"] = 1] = "KeyAgreement";
    EdhocKeyType[EdhocKeyType["Signature"] = 2] = "Signature";
    EdhocKeyType[EdhocKeyType["Verify"] = 3] = "Verify";
    EdhocKeyType[EdhocKeyType["Extract"] = 4] = "Extract";
    EdhocKeyType[EdhocKeyType["Expand"] = 5] = "Expand";
    EdhocKeyType[EdhocKeyType["Encrypt"] = 6] = "Encrypt";
    EdhocKeyType[EdhocKeyType["Decrypt"] = 7] = "Decrypt";
})(EdhocKeyType || (exports.EdhocKeyType = EdhocKeyType = {}));
/**
 * Enumerates the methods available for EDHOC protocol exchanges.
 * Each method corresponds to different authentication mechanisms.
 */
var EdhocMethod;
(function (EdhocMethod) {
    EdhocMethod[EdhocMethod["Method0"] = 0] = "Method0";
    EdhocMethod[EdhocMethod["Method1"] = 1] = "Method1";
    EdhocMethod[EdhocMethod["Method2"] = 2] = "Method2";
    EdhocMethod[EdhocMethod["Method3"] = 3] = "Method3";
})(EdhocMethod || (exports.EdhocMethod = EdhocMethod = {}));
/**
 * Enumerates the cipher suites available for EDHOC protocol operations.
 * Each suite represents a set of cryptographic algorithms.
 */
var EdhocSuite;
(function (EdhocSuite) {
    EdhocSuite[EdhocSuite["Suite0"] = 0] = "Suite0";
    EdhocSuite[EdhocSuite["Suite1"] = 1] = "Suite1";
    EdhocSuite[EdhocSuite["Suite2"] = 2] = "Suite2";
    EdhocSuite[EdhocSuite["Suite3"] = 3] = "Suite3";
    EdhocSuite[EdhocSuite["Suite4"] = 4] = "Suite4";
    EdhocSuite[EdhocSuite["Suite5"] = 5] = "Suite5";
    EdhocSuite[EdhocSuite["Suite6"] = 6] = "Suite6";
    EdhocSuite[EdhocSuite["Suite24"] = 24] = "Suite24";
    EdhocSuite[EdhocSuite["Suite25"] = 25] = "Suite25";
})(EdhocSuite || (exports.EdhocSuite = EdhocSuite = {}));
__exportStar(require("./bindings"), exports);
