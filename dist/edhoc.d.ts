/// <reference types="node" />
/**
 * Enumerates the types of credential formats that can be used with EDHOC.
 */
export declare enum EdhocCredentialsFormat {
    kid = 4,// Represents a key identifier.
    x5chain = 33,// Represents an X.509 certificate chain.
    x5t = 34
}
/**
 * Base interface for EDHOC credentials.
 */
export interface EdhocCredentials {
    format: EdhocCredentialsFormat;
    privateKeyID?: Buffer;
    publicKey?: Buffer;
}
/**
 * Extends EdhocCredentials for credentials using a key identifier (KID).
 */
export interface EdhocCredentialsKID extends EdhocCredentials {
    format: EdhocCredentialsFormat.kid;
    kid: {
        kid: number;
        credentials?: Buffer;
        isCBOR?: boolean;
    };
}
/**
 * Extends EdhocCredentials for credentials using an X.509 certificate chain.
 */
export interface EdhocCredentialsCertificateChain extends EdhocCredentials {
    format: EdhocCredentialsFormat.x5chain;
    x5chain: {
        certificates: Buffer[];
    };
}
/**
 * Extends EdhocCredentials for credentials using a hashed X.509 certificate.
 */
export interface EdhocCredentialsCertificateHash extends EdhocCredentials {
    format: EdhocCredentialsFormat.x5t;
    x5t: {
        certificate?: Buffer;
        hash: Buffer;
        hashAlgorithm: EdhocCredentialsCertificateHashAlgorithm;
    };
}
/**
 * Enumerates the types of hash algorithms that can be used with hashed X.509 certificates.
 */
export declare enum EdhocCredentialsCertificateHashAlgorithm {
    Sha256 = -16,// SHA-256 hash algorithm.
    Sha256_64 = -15
}
/**
 * Provides methods for managing EDHOC credentials.
 */
export interface EdhocCredentialManager {
    /**
     * Fetches EDHOC credentials based on the provided EDHOC context.
     * @param edhoc The EDHOC context for which to fetch credentials.
     * @return A promise that resolves to the fetched EdhocCredentials or throws an error if not successful.
     */
    fetch(edhoc: EDHOC): Promise<EdhocCredentials> | EdhocCredentials | never;
    /**
     * Verifies EDHOC credentials based on the provided EDHOC context and credentials.
     * @param edhoc The EDHOC context against which to verify credentials.
     * @param credentials The credentials to verify.
     * @return A promise that resolves to the verified EdhocCredentials or throws an error if not successful.
     */
    verify(edhoc: EDHOC, credentials: EdhocCredentials): Promise<EdhocCredentials> | EdhocCredentials | never;
}
/**
 * Enumerates the types of cryptographic operations that can be performed with EDHOC.
 */
export declare enum EdhocKeyType {
    MakeKeyPair = 0,// Used to generate a key pair.
    KeyAgreement = 1,// Used for key agreement operations.
    Signature = 2,// Used for creating digital signatures.
    Verify = 3,// Used for verifying digital signatures.
    Extract = 4,// Used for extracting key material.
    Expand = 5,// Used for expanding key material.
    Encrypt = 6,// Used for encrypting data.
    Decrypt = 7
}
/**
 * Type representing a public key in buffer format.
 */
export type EdhocPublicKey = Buffer;
/**
 * Type representing a private key in buffer format.
 */
export type EdhocPrivateKey = Buffer;
/**
 * Represents a tuple of public and private keys.
 */
export interface PublicPrivateTuple {
    publicKey: EdhocPublicKey;
    privateKey: EdhocPrivateKey;
}
/**
 * Manages cryptographic functions necessary for the operation of EDHOC protocols.
 */
export interface EdhocCryptoManager {
    /**
     * Generates a cryptographic key of the specified type.
     * @param edhoc The EDHOC session context.
     * @param keyType The type of key to generate, as defined in EdhocKeyType.
     * @param key Optional buffer containing seed or related data if necessary.
     * @return A promise resolving to a Buffer containing the generated key.
     */
    generateKey(edhoc: EDHOC, keyType: EdhocKeyType, key: Buffer): Promise<Buffer> | Buffer | never;
    /**
     * Destroys a cryptographic key identified by the keyID.
     * @param edhoc The EDHOC session context.
     * @param keyID Buffer identifying the key to destroy.
     * @return A promise resolving to true if the key was successfully destroyed.
     */
    destroyKey(edhoc: EDHOC, keyID: Buffer): Promise<boolean> | boolean | never;
    /**
     * Generates a public-private key pair.
     * @param edhoc The EDHOC session context.
     * @param keyID Buffer to identify the key pair for future operations.
     * @param privateKeySize Size in bytes for the private key.
     * @param publicKeySize Size in bytes for the public key.
     * @return A promise resolving to a PublicPrivateTuple containing both keys.
    //  */
    makeKeyPair(edhoc: EDHOC, keyID: Buffer, privateKeySize: number, publicKeySize: number): Promise<PublicPrivateTuple> | PublicPrivateTuple | never;
    /**
     * Performs a key agreement operation using a public and a private key.
     * @param edhoc The EDHOC session context.
     * @param keyID Buffer identifying the key agreement process.
     * @param publicKey The public key of the other party.
     * @param privateKeySize Size of the private key used in the key agreement.
     * @return A promise resolving to the resultant private key.
     */
    keyAgreement(edhoc: EDHOC, keyID: Buffer, publicKey: EdhocPublicKey, privateKeySize: number): Promise<Buffer> | Buffer | never;
    /**
     * Signs data using a specified key.
     * @param edhoc The EDHOC session context.
     * @param keyID Buffer identifying the key to use for signing.
     * @param input Buffer containing the data to sign.
     * @param signatureSize The desired size of the signature.
     * @return A promise resolving to the signature.
     */
    sign(edhoc: EDHOC, keyID: Buffer, input: Buffer, signatureSize: number): Promise<Buffer> | Buffer | never;
    /**
     * Verifies a signature against the provided data.
     * @param edhoc The EDHOC session context.
     * @param keyID Buffer identifying the key to use for verification.
     * @param input Buffer containing the original data that was signed.
     * @param signature Buffer containing the signature to verify.
     * @return A promise resolving to true if the signature is valid.
     */
    verify(edhoc: EDHOC, keyID: Buffer, input: Buffer, signature: Buffer): Promise<boolean> | boolean | never;
    /**
     * Extracts a key using a salt.
     * @param edhoc The EDHOC session context.
     * @param keyID Buffer identifying the extraction process.
     * @param salt Buffer containing the salt used in the extraction.
     * @param keySize The desired size of the key to extract.
     * @return A promise resolving to the extracted key.
     */
    extract(edhoc: EDHOC, keyID: Buffer, salt: Buffer, keySize: number): Promise<Buffer> | Buffer | never;
    /**
     * Expands a key using provided information.
     * @param edhoc The EDHOC session context.
     * @param keyID Buffer identifying the expansion process.
     * @param info Buffer containing information used for key expansion.
     * @param keySize The desired size of the key after expansion.
     * @return A promise resolving to the expanded key.
     */
    expand(edhoc: EDHOC, keyID: Buffer, info: Buffer, keySize: number): Promise<Buffer> | Buffer | never;
    /**
     * Encrypts plaintext using a specified key and nonce.
     * @param edhoc The EDHOC session context.
     * @param keyID Buffer identifying the key to use for encryption.
     * @param nonce Buffer containing the nonce to use in the encryption process.
     * @param aad Buffer containing additional authenticated data.
     * @param plaintext Buffer containing the data to encrypt.
     * @param size The size of the output buffer.
     * @return A promise resolving to the ciphertext.
     */
    encrypt(edhoc: EDHOC, keyID: Buffer, nonce: Buffer, aad: Buffer, plaintext: Buffer, size: number): Promise<Buffer> | Buffer | never;
    /**
     * Decrypts ciphertext using a specified key and nonce.
     * @param edhoc The EDHOC session context.
     * @param keyID Buffer identifying the key to use for decryption.
     * @param nonce Buffer containing the nonce to use in the decryption process.
     * @param aad Buffer containing additional authenticated data.
     * @param ciphertext Buffer containing the data to decrypt.
     * @param size The size of the output buffer.
     * @return A promise resolving to the plaintext.
     */
    decrypt(edhoc: EDHOC, keyID: Buffer, nonce: Buffer, aad: Buffer, ciphertext: Buffer, size: number): Promise<Buffer> | Buffer | never;
    /**
     * Computes a hash of the given data.
     * @param edhoc The EDHOC session context.
     * @param data Buffer containing the data to hash.
     * @param hashSize The size of the hash to compute.
     * @return A promise resolving to the hash.
     */
    hash(edhoc: EDHOC, data: Buffer, hashSize: number): Promise<Buffer> | Buffer | never;
}
/**
 * Represents an EDHOC connection identifier which can be either a number or a Buffer.
 */
export type EdhocConnectionID = number | Buffer;
/**
 * Enumerates the methods available for EDHOC protocol exchanges.
 * Each method corresponds to different authentication mechanisms.
 */
export declare enum EdhocMethod {
    Method0 = 0,
    Method1 = 1,
    Method2 = 2,
    Method3 = 3
}
/**
 * Enumerates the cipher suites available for EDHOC protocol operations.
 * Each suite represents a set of cryptographic algorithms.
 */
export declare enum EdhocSuite {
    Suite0 = 0,
    Suite1 = 1,
    Suite2 = 2,
    Suite3 = 3,
    Suite4 = 4,
    Suite5 = 5,
    Suite6 = 6,
    Suite24 = 24,
    Suite25 = 25
}
/**
 * Represents an External Authorization Data (EAD) object used in EDHOC protocol exchanges.
 * EAD objects carry additional authorization information relevant to the session.
 */
export interface EdhocEAD {
    label: number;
    value: Buffer;
}
/**
 * Describes the context for OSCORE (Object Security for Constrained RESTful Environments) derived from EDHOC.
 * OSCORE contexts are used to securely communicate over constrained networks.
 */
export interface EdhocOscoreContext {
    masterSecret: Buffer;
    masterSalt: Buffer;
    senderId: Buffer;
    recipientId: Buffer;
}
/**
 * The EDHOC class encapsulates the EDHOC protocol logic, managing the lifecycle of an EDHOC session.
 */
export declare class EDHOC {
    /**
     * The connection ID used by the local entity for this EDHOC session.
     */
    connectionID: EdhocConnectionID;
    /**
     * The connection ID used by the peer entity, which is read-only and set during the EDHOC message exchange.
     */
    readonly peerConnectionID: EdhocConnectionID;
    /**
     * The method of authentication to be used in this EDHOC session, as defined in EdhocMethod.
     */
    method: EdhocMethod;
    /**
     * A list of cipher suites supported by this session, providing flexibility in cryptographic negotiations.
     */
    cipherSuites: EdhocSuite[];
    /**
     * Represents the selected EDHOC cipher suite.
     */
    selectedSuite: EdhocSuite;
    /**
     * A logging function to log operational data during the EDHOC protocol execution.
     * @param name The name or description of the log entry.
     * @param data The data to be logged, typically related to protocol messages or internal state.
     */
    logger: (name: string, data: Buffer) => void;
    /**
     * Constructs an EDHOC protocol handler.
     * @param connectionID The identifier for this connection.
     * @param method The EDHOC method to be used for the session.
     * @param suite An array of supported cipher suites.
     * @param credentials A manager for handling credentials related to EDHOC.
     * @param crypto A crypto manager to handle cryptographic functions.
     */
    constructor(connectionID: EdhocConnectionID, method: EdhocMethod, suite: EdhocSuite[], credentials: EdhocCredentialManager, crypto: EdhocCryptoManager);
    /**
     * Composes the first EDHOC message.
     * @param ead Optional array of EAD objects to include in the message.
     * @return A promise that resolves to the composed message buffer.
     */
    composeMessage1(ead?: EdhocEAD[]): Promise<Buffer> | never;
    /**
     * Processes the received first EDHOC message.
     * @param message The received message buffer.
     * @return A promise that resolves to an array of EAD objects extracted from the message.
     */
    processMessage1(message: Buffer): Promise<EdhocEAD[]> | never;
    /**
     * Composes the second EDHOC message.
     * @param ead Optional array of EAD objects to include in the message.
     * @return A promise that resolves to the composed message buffer.
     */
    composeMessage2(ead?: EdhocEAD[]): Promise<Buffer> | never;
    /**
     * Processes the received second EDHOC message.
     * @param message The received message buffer.
     * @return A promise that resolves to an array of EAD objects extracted from the message.
     */
    processMessage2(message: Buffer): Promise<EdhocEAD[]> | never;
    /**
     * Composes the third EDHOC message.
     * @param ead Optional array of EAD objects to include in the message.
     * @return A promise that resolves to the composed message buffer.
     */
    composeMessage3(ead?: EdhocEAD[]): Promise<Buffer> | never;
    /**
     * Processes the received third EDHOC message.
     * @param message The received message buffer.
     * @return A promise that resolves to an array of EAD objects extracted from the message.
     */
    processMessage3(message: Buffer): Promise<EdhocEAD[]> | never;
    /**
     * Composes the fourth and final EDHOC message.
     * @param ead Optional array of EAD objects to include in the message.
     * @return A promise that resolves to the composed message buffer.
     */
    composeMessage4(ead?: EdhocEAD[]): Promise<Buffer> | never;
    /**
     * Processes the received fourth EDHOC message.
     * @param message The received message buffer.
     * @return A promise that resolves to an array of EAD objects extracted from the message.
     */
    processMessage4(message: Buffer): Promise<EdhocEAD[]> | never;
    /**
     * Exports the OSCORE context derived from the EDHOC session.
     * @return A promise that resolves to the OSCORE context used for secured communication in constrained environments.
     */
    exportOSCORE(): Promise<EdhocOscoreContext> | never;
}
export * from './bindings';
//# sourceMappingURL=edhoc.d.ts.map