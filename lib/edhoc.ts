import cbor from 'cbor';
import { getCipherSuiteParams, CipherSuiteParams } from './cipher-suites';
import {
    encodeCborSequence,
    decodeCborSequence,
    encodeSuites,
    connectionIdToBytes,
    connectionIdFromCbor,
    encodeIdCred,
    encodeIdCredMap,
    encodeCredItem,
    decodeIdCred,
    getCredBytes,
    encodePlaintext,
    parsePlaintext,
    encodeEadItems,
    parseEadItems,
} from './cbor-utils';

// ── Error Types ─────────────────────────────────────────────────────────

export class EdhocError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'EdhocError';
    }
}

export class EdhocCipherSuiteError extends EdhocError {
    public readonly peerCipherSuites: number[];

    constructor(message: string, peerCipherSuites: number[]) {
        super(message);
        this.name = 'EdhocCipherSuiteError';
        this.peerCipherSuites = peerCipherSuites;
    }
}

// ── Public Types & Interfaces ──────────────────────────────────────────

export enum EdhocCredentialsFormat {
    kid = 4,
    x5chain = 33,
    x5t = 34,
}

export interface EdhocCredentials {
    format: EdhocCredentialsFormat;
    privateKey?: Buffer;
    publicKey?: Buffer;
}

export interface EdhocCredentialsKID extends EdhocCredentials {
    format: EdhocCredentialsFormat.kid;
    kid: {
        kid: number | Buffer;
        credentials?: Buffer;
        isCBOR?: boolean;
    };
}

export interface EdhocCredentialsCertificateChain extends EdhocCredentials {
    format: EdhocCredentialsFormat.x5chain;
    x5chain: { certificates: Buffer[] };
}

export interface EdhocCredentialsCertificateHash extends EdhocCredentials {
    format: EdhocCredentialsFormat.x5t;
    x5t: {
        certificate?: Buffer;
        hash: Buffer;
        hashAlgorithm: EdhocCredentialsCertificateHashAlgorithm;
    };
}

export enum EdhocCredentialsCertificateHashAlgorithm {
    Sha256 = -16,
    Sha256_64 = -15,
}

export interface EdhocCredentialManager {
    fetch(edhoc: EDHOC): Promise<EdhocCredentials> | EdhocCredentials | never;
    verify(edhoc: EDHOC, credentials: EdhocCredentials): Promise<EdhocCredentials> | EdhocCredentials | never;
}

export type EdhocPublicKey = Buffer;
export type EdhocPrivateKey = Buffer;

export interface PublicPrivateTuple {
    publicKey: EdhocPublicKey;
    privateKey: EdhocPrivateKey;
}

export interface EdhocCryptoManager {
    generateKeyPair(edhoc: EDHOC): Promise<PublicPrivateTuple> | PublicPrivateTuple | never;
    keyAgreement(edhoc: EDHOC, privateKey: Buffer, peerPublicKey: Buffer): Promise<Buffer> | Buffer | never;
    sign(edhoc: EDHOC, privateKey: Buffer, input: Buffer): Promise<Buffer> | Buffer | never;
    verify(edhoc: EDHOC, publicKey: Buffer, input: Buffer, signature: Buffer): Promise<boolean> | boolean | never;
    hkdfExtract(edhoc: EDHOC, ikm: Buffer, salt: Buffer): Promise<Buffer> | Buffer | never;
    hkdfExpand(edhoc: EDHOC, prk: Buffer, info: Buffer, length: number): Promise<Buffer> | Buffer | never;
    encrypt(edhoc: EDHOC, key: Buffer, nonce: Buffer, aad: Buffer, plaintext: Buffer): Promise<Buffer> | Buffer | never;
    decrypt(edhoc: EDHOC, key: Buffer, nonce: Buffer, aad: Buffer, ciphertext: Buffer): Promise<Buffer> | Buffer | never;
    hash(edhoc: EDHOC, input: Buffer): Promise<Buffer> | Buffer | never;
}

export type EdhocConnectionID = number | Buffer;

export enum EdhocMethod {
    Method0 = 0,
    Method1,
    Method2,
    Method3,
}

export enum EdhocSuite {
    Suite0 = 0,
    Suite1,
    Suite2,
    Suite3,
    Suite4,
    Suite5,
    Suite6,
    Suite24 = 24,
    Suite25,
}

export interface EdhocEAD {
    label: number;
    value: Buffer;
}

export interface EdhocOscoreContext {
    masterSecret: Buffer;
    masterSalt: Buffer;
    senderId: Buffer;
    recipientId: Buffer;
}

// ── Internal state enum (not exported) ─────────────────────────────────

const enum State {
    START,
    WAIT_M2,
    VERIFIED_M1,
    WAIT_M3,
    VERIFIED_M2,
    WAIT_M4_OR_DONE,
    DONE,
}

// ── EDHOC Class ────────────────────────────────────────────────────────

export class EDHOC {

    // ── public properties (matching original API) ──────────────────────

    public connectionID: EdhocConnectionID;
    public get peerConnectionID(): EdhocConnectionID { return this._peerCid!; }
    public methods: EdhocMethod[];
    public get selectedMethod(): EdhocMethod { return this._method; }
    public set selectedMethod(v: EdhocMethod) { this._method = v; }
    public cipherSuites: EdhocSuite[];
    public get selectedSuite(): EdhocSuite { return this._suite; }
    public set selectedSuite(v: EdhocSuite) { this._suite = v; }
    public logger!: (name: string, data: Buffer) => void;

    // ── private dependencies ───────────────────────────────────────────

    private readonly credMgr: EdhocCredentialManager;
    private readonly crypto: EdhocCryptoManager;

    // ── private protocol state ─────────────────────────────────────────

    private _state = State.START;
    private _role: 'initiator' | 'responder' | null = null;
    private _method: EdhocMethod;
    private _suite: EdhocSuite;
    private _suiteParams: CipherSuiteParams;

    private _peerCid: EdhocConnectionID | null = null;
    private _ephPrivateKey: Buffer | null = null;
    private _ephPub: Buffer | null = null;
    private _peerEphPub: Buffer | null = null;

    private _th: Buffer | null = null;
    private _prk2e: Buffer | null = null;
    private _prk3e2m: Buffer | null = null;
    private _prk4e3m: Buffer | null = null;
    private _prkOut: Buffer | null = null;
    private _prkExporter: Buffer | null = null;
    private _peerCredentials: EdhocCredentials | null = null;

    // ── constructor / reset ────────────────────────────────────────────

    constructor(
        connectionID: EdhocConnectionID,
        methods: EdhocMethod[],
        suites: EdhocSuite[],
        credentials: EdhocCredentialManager,
        crypto: EdhocCryptoManager,
    ) {
        this.connectionID = connectionID;
        this.methods = methods;
        this.cipherSuites = suites;
        this.credMgr = credentials;
        this.crypto = crypto;
        this._method = methods[0];
        this._suite = suites[suites.length - 1];
        this._suiteParams = getCipherSuiteParams(this._suite);
    }

    public reset(): void {
        this._state = State.START;
        this._role = null;
        this._method = this.methods[0];
        this._suite = this.cipherSuites[this.cipherSuites.length - 1];
        this._suiteParams = getCipherSuiteParams(this._suite);
        this._peerCid = null;
        this._ephPrivateKey = null;
        this._ephPub = null;
        this._peerEphPub = null;
        this._th = null;
        this._prk2e = null;
        this._prk3e2m = null;
        this._prk4e3m = null;
        this._prkOut = null;
        this._prkExporter = null;
        this._peerCredentials = null;
    }

    // ── public message API ─────────────────────────────────────────────

    public async composeMessage1(ead?: EdhocEAD[]): Promise<Buffer> {
        this.assertState(State.START, 'composeMessage1');
        this._role = 'initiator';
        this._method = this.methods[0];
        this._suite = this.cipherSuites[this.cipherSuites.length - 1];
        this._suiteParams = getCipherSuiteParams(this._suite);

        // Generate ephemeral DH keypair
        await this.generateEphemeralKey();

        // Build message_1 CBOR sequence: METHOD, SUITES_I, G_X, C_I, ?EAD_1
        const parts: unknown[] = [
            this._method,
            encodeSuites(this.cipherSuites, this._suite),
            this._ephPub!,
            this.connectionID,
        ];
        if (ead?.length) for (const t of ead) {
            parts.push(t.label);
            if (t.value?.length) parts.push(t.value);
        }
        const msg1 = encodeCborSequence(...parts);
        this.log('message_1', msg1);

        // TH_1 = H(message_1) — hash of the raw CBOR-sequence bytes
        this._th = await this.hash(msg1);
        this.log('TH_1', this._th);

        this._state = State.WAIT_M2;
        return msg1;
    }

    public async processMessage1(message: Buffer): Promise<EdhocEAD[]> {
        this.assertState(State.START, 'processMessage1');
        this._role = 'responder';

        const items = decodeCborSequence(message);
        if (items.length < 4) throw new EdhocError('Invalid message_1');

        // Parse METHOD
        const method = items[0] as number;
        if (!this.methods.includes(method)) throw new EdhocError(`Unsupported method: ${method}`);
        this._method = method as EdhocMethod;

        // Parse SUITES_I
        const rawSuites = items[1];
        const selected = typeof rawSuites === 'number'
            ? rawSuites as EdhocSuite
            : (rawSuites as number[])[(rawSuites as number[]).length - 1] as EdhocSuite;
        if (!this.cipherSuites.includes(selected)) {
            throw new EdhocCipherSuiteError(
                `Unsupported cipher suite: ${selected}`,
                typeof rawSuites === 'number' ? [rawSuites] : rawSuites as number[]
            );
        }
        this._suite = selected;
        this._suiteParams = getCipherSuiteParams(selected);

        // Parse G_X, C_I
        const gx = items[2];
        this._peerEphPub = Buffer.isBuffer(gx) ? gx : Buffer.from(gx as Uint8Array);
        this._peerCid = connectionIdFromCbor(items[3]);

        // Parse ?EAD_1
        const eadTokens = items.length > 4 ? parseEadItems(items.slice(4)) : [];

        this.log('message_1', message);

        // TH_1 = H(message_1)
        this._th = await this.hash(message);
        this.log('TH_1', this._th);

        this._state = State.VERIFIED_M1;
        return eadTokens;
    }

    public async composeMessage2(ead?: EdhocEAD[]): Promise<Buffer> {
        this.assertState(State.VERIFIED_M1, 'composeMessage2');

        // Generate ephemeral DH keypair (G_Y)
        await this.generateEphemeralKey();
        const gY = this._ephPub!;
        this.log('G_Y', gY);

        // ECDH → G_XY
        const gXY = Buffer.from(await this.crypto.keyAgreement(
            this, this._ephPrivateKey!, this._peerEphPub!));
        this.log('G_XY', gXY);

        // TH_2 = H( G_Y, H(message_1) )  — RFC 9528 §5.3.2
        this._th = await this.hash(encodeCborSequence(gY, this._th!));
        this.log('TH_2', this._th);

        // PRK_2e = HKDF-Extract(TH_2, G_XY)
        this._prk2e = await this.hkdfExtract(gXY, this._th);
        this.log('PRK_2e', this._prk2e);

        // Fetch own credentials
        const cred = await this.credMgr.fetch(this);
        const credR = getCredBytes(cred);
        const idCredR = encodeIdCred(cred);
        const idCredRMap = encodeIdCredMap(cred);
        const credRCbor = encodeCredItem(cred, credR);

        // Static DH for methods 1, 3 (responder authenticates with static DH)
        let gRX: Buffer | undefined;
        if (this._method === EdhocMethod.Method1 || this._method === EdhocMethod.Method3) {
            gRX = Buffer.from(await this.crypto.keyAgreement(
                this, cred.privateKey!, this._peerEphPub!));
        }

        // PRK_3e2m
        this._prk3e2m = await this.derivePrk3e2m(gRX);
        this.log('PRK_3e2m', this._prk3e2m);

        // MAC_2 with context_2 = << C_R, ID_CRED_R, TH_2, CRED_R, ?EAD_2 >>
        const context2 = this.buildContext(cbor.encode(this.connectionID), idCredRMap, this._th, credRCbor, ead);
        const mac2Len = this.macLength('responder');
        const mac2 = await this.kdf(this._prk3e2m, 2, context2, mac2Len);
        this.log('MAC_2', mac2);

        // Signature_or_MAC_2
        const sigOrMac2 = await this.signOrMac('responder', cred, idCredRMap, this._th, credRCbor, ead, mac2);
        this.log('Signature_or_MAC_2', sigOrMac2);

        // PLAINTEXT_2 = ( C_R, ID_CRED_R, Signature_or_MAC_2, ?EAD_2 )
        // Uses compact idCredR (bare kid) for the wire format
        const pt2 = Buffer.concat([
            cbor.encode(this.connectionID),
            encodePlaintext(idCredR, sigOrMac2, ead),
        ]);
        this.log('PLAINTEXT_2', pt2);

        // KEYSTREAM_2 = EDHOC-KDF(PRK_2e, 0, TH_2, |PLAINTEXT_2|)
        const ks2 = await this.kdf(this._prk2e, 0, this._th, pt2.length);
        const ct2 = this.xor(pt2, ks2);
        this.log('CIPHERTEXT_2', ct2);

        // TH_3 = H( TH_2, PLAINTEXT_2, CRED_R )
        this._th = await this.hash(Buffer.concat([cbor.encode(this._th), pt2, credRCbor]));
        this.log('TH_3', this._th);

        // message_2 = bstr( G_Y || CIPHERTEXT_2 )  — RFC 9528 §5.3.1
        const msg2 = cbor.encode(Buffer.concat([gY, ct2]));
        this.log('message_2', msg2);

        this._state = State.WAIT_M3;
        return msg2;
    }

    public async processMessage2(message: Buffer): Promise<EdhocEAD[]> {
        this.assertState(State.WAIT_M2, 'processMessage2');

        // Decode outer bstr → G_Y || CIPHERTEXT_2
        const inner = Buffer.from(cbor.decodeFirstSync(message) as Uint8Array);
        const gY = inner.subarray(0, this._suiteParams.eccKeyLength);
        const ct2 = inner.subarray(this._suiteParams.eccKeyLength);
        this._peerEphPub = Buffer.from(gY);
        this.log('G_Y', gY);

        // ECDH → G_XY
        const gXY = Buffer.from(await this.crypto.keyAgreement(
            this, this._ephPrivateKey!, gY));
        this.log('G_XY', gXY);

        // TH_2 = H( G_Y, H(message_1) )
        this._th = await this.hash(encodeCborSequence(gY, this._th!));
        this.log('TH_2', this._th);

        // PRK_2e
        this._prk2e = await this.hkdfExtract(gXY, this._th);
        this.log('PRK_2e', this._prk2e);

        // Decrypt PLAINTEXT_2
        const ks2 = await this.kdf(this._prk2e, 0, this._th, ct2.length);
        const pt2 = this.xor(ct2, ks2);
        this.log('PLAINTEXT_2', pt2);

        // Parse PLAINTEXT_2: C_R, ID_CRED_R, Signature_or_MAC_2, ?EAD_2
        const pt2Items = decodeCborSequence(pt2);
        if (pt2Items.length < 3) throw new EdhocError('Invalid PLAINTEXT_2');
        this._peerCid = connectionIdFromCbor(pt2Items[0]);

        const parsed = parsePlaintext(Buffer.concat(
            pt2Items.slice(1).map((item: unknown) => cbor.encode(item))
        ));

        // Verify peer credentials
        const peerCredPartial = decodeIdCred(parsed.idCredRaw);
        const peerCred = await this.credMgr.verify(this, peerCredPartial);
        this._peerCredentials = peerCred;
        const credR = getCredBytes(peerCred);
        const idCredR = encodeIdCred(peerCred);
        const idCredRMap = encodeIdCredMap(peerCred);
        const credRCbor = encodeCredItem(peerCred, credR);

        // Static DH for methods 1, 3
        let gRX: Buffer | undefined;
        if (this._method === EdhocMethod.Method1 || this._method === EdhocMethod.Method3) {
            gRX = Buffer.from(await this.crypto.keyAgreement(
                this, this._ephPrivateKey!, peerCred.publicKey!));
        }

        // PRK_3e2m
        this._prk3e2m = await this.derivePrk3e2m(gRX);
        this.log('PRK_3e2m', this._prk3e2m);

        // Verify MAC_2 / Signature_or_MAC_2
        const context2 = this.buildContext(cbor.encode(this._peerCid), idCredRMap, this._th, credRCbor,
            parsed.ead.length > 0 ? parsed.ead : undefined);
        const mac2Len = this.macLength('responder');
        const mac2 = await this.kdf(this._prk3e2m, 2, context2, mac2Len);
        this.log('MAC_2', mac2);

        await this.verifySignatureOrMac('responder', peerCred, idCredRMap, this._th, credRCbor,
            parsed.ead.length > 0 ? parsed.ead : undefined, mac2, parsed.signatureOrMac);

        // TH_3 = H( TH_2, PLAINTEXT_2, CRED_R )
        this._th = await this.hash(Buffer.concat([cbor.encode(this._th), pt2, credRCbor]));
        this.log('TH_3', this._th);

        this._state = State.VERIFIED_M2;
        return parsed.ead;
    }

    public async composeMessage3(ead?: EdhocEAD[]): Promise<Buffer> {
        this.assertState(State.VERIFIED_M2, 'composeMessage3');
        const th3 = this._th!;

        // Fetch own credentials
        const cred = await this.credMgr.fetch(this);
        const credI = getCredBytes(cred);
        const idCredI = encodeIdCred(cred);
        const idCredIMap = encodeIdCredMap(cred);
        const credICbor = encodeCredItem(cred, credI);

        // Static DH for methods 2, 3 (initiator authenticates with static DH)
        let gIX: Buffer | undefined;
        if (this._method === EdhocMethod.Method2 || this._method === EdhocMethod.Method3) {
            gIX = Buffer.from(await this.crypto.keyAgreement(
                this, cred.privateKey!, this._peerEphPub!));
        }

        // PRK_4e3m
        this._prk4e3m = await this.derivePrk4e3m(th3, gIX);
        this.log('PRK_4e3m', this._prk4e3m);

        // MAC_3 with context_3 = << ID_CRED_I, TH_3, CRED_I, ?EAD_3 >>
        const context3 = this.buildContext(null, idCredIMap, th3, credICbor, ead);
        const mac3Len = this.macLength('initiator');
        const mac3 = await this.kdf(this._prk4e3m, 6, context3, mac3Len);
        this.log('MAC_3', mac3);

        // Signature_or_MAC_3
        const sigOrMac3 = await this.signOrMac('initiator', cred, idCredIMap, th3, credICbor, ead, mac3);
        this.log('Signature_or_MAC_3', sigOrMac3);

        // PLAINTEXT_3 = ( ID_CRED_I, Signature_or_MAC_3, ?EAD_3 )
        // Uses compact idCredI (bare kid) for the wire format
        const pt3 = encodePlaintext(idCredI, sigOrMac3, ead);
        this.log('PLAINTEXT_3', pt3);

        // AEAD encrypt: K_3, IV_3
        const k3 = await this.kdf(this._prk3e2m!, 3, th3, this._suiteParams.aeadKeyLength);
        const iv3 = await this.kdf(this._prk3e2m!, 4, th3, this._suiteParams.aeadIvLength);
        // external_aad_3 = << TH_3, CRED_I, ?EAD_3 >>
        const aad3 = this.buildEncAad(th3, credI, ead);
        const ct3 = await this.aeadEncrypt(k3, iv3, aad3, pt3);
        this.log('CIPHERTEXT_3', ct3);

        // TH_4 = H( TH_3, PLAINTEXT_3, CRED_I )
        this._th = await this.hash(Buffer.concat([cbor.encode(th3), pt3, credICbor]));
        this.log('TH_4', this._th);

        // PRK_out, PRK_exporter
        this._prkOut = await this.kdf(this._prk4e3m, 7, this._th, this._suiteParams.hashLength);
        this._prkExporter = await this.kdf(this._prkOut, 10, Buffer.alloc(0), this._suiteParams.hashLength);

        // Destroy ephemeral key
        await this.destroyEphemeralKey();

        // message_3 = CBOR bstr of CIPHERTEXT_3
        const msg3 = cbor.encode(ct3);
        this.log('message_3', msg3);

        this._state = State.WAIT_M4_OR_DONE;
        return msg3;
    }

    public async processMessage3(message: Buffer): Promise<EdhocEAD[]> {
        this.assertState(State.WAIT_M3, 'processMessage3');
        const th3 = this._th!;

        const ct3 = Buffer.from(cbor.decodeFirstSync(message) as Uint8Array);

        // AEAD decrypt
        const k3 = await this.kdf(this._prk3e2m!, 3, th3, this._suiteParams.aeadKeyLength);
        const iv3 = await this.kdf(this._prk3e2m!, 4, th3, this._suiteParams.aeadIvLength);

        // Fetch own credentials first to build AAD (we need CRED_I for verifying, but AAD needs CRED_I too)
        // Actually, for the responder processing message 3, the AAD uses the initiator's credentials.
        // But we don't know CRED_I yet. The AAD for decrypt uses TH_3 only? No.
        // RFC 9528: external_aad_3 = << TH_3, CRED_I, ?EAD_3 >>
        // But CRED_I isn't known until after decryption...
        // Actually, for AEAD decryption, we need the AAD. Since CRED_I is inside the encrypted
        // PLAINTEXT_3, the responder can't know it before decryption.
        // Looking at RFC 9528 more carefully: the Enc_structure external_aad is just TH_3
        // The << TH_3, CRED_I, ?EAD_3 >> is for the Sig_structure, not the Enc_structure.
        // The AEAD AAD = Enc_structure = ["Encrypt0", h'', TH_3]
        const aad3 = cbor.encode(['Encrypt0', Buffer.alloc(0), th3]);
        const pt3 = await this.aeadDecrypt(k3, iv3, aad3, ct3);
        this.log('PLAINTEXT_3', pt3);

        // Parse PLAINTEXT_3: ID_CRED_I, Signature_or_MAC_3, ?EAD_3
        const parsed = parsePlaintext(pt3);

        // Verify peer credentials
        const peerCredPartial = decodeIdCred(parsed.idCredRaw);
        const peerCred = await this.credMgr.verify(this, peerCredPartial);
        this._peerCredentials = peerCred;
        const credI = getCredBytes(peerCred);
        const idCredI = encodeIdCred(peerCred);
        const idCredIMap = encodeIdCredMap(peerCred);
        const credICbor = encodeCredItem(peerCred, credI);

        // Static DH for methods 2, 3
        let gIX: Buffer | undefined;
        if (this._method === EdhocMethod.Method2 || this._method === EdhocMethod.Method3) {
            if (this._ephPrivateKey) {
                gIX = Buffer.from(await this.crypto.keyAgreement(
                    this, this._ephPrivateKey, peerCred.publicKey!));
            }
        }

        // PRK_4e3m
        this._prk4e3m = await this.derivePrk4e3m(th3, gIX);

        // Verify MAC_3
        const context3 = this.buildContext(null, idCredIMap, th3, credICbor,
            parsed.ead.length > 0 ? parsed.ead : undefined);
        const mac3Len = this.macLength('initiator');
        const mac3 = await this.kdf(this._prk4e3m, 6, context3, mac3Len);

        await this.verifySignatureOrMac('initiator', peerCred, idCredIMap, th3, credICbor,
            parsed.ead.length > 0 ? parsed.ead : undefined, mac3, parsed.signatureOrMac);

        // TH_4
        this._th = await this.hash(Buffer.concat([cbor.encode(th3), pt3, credICbor]));

        // PRK_out, PRK_exporter
        this._prkOut = await this.kdf(this._prk4e3m, 7, this._th, this._suiteParams.hashLength);
        this._prkExporter = await this.kdf(this._prkOut, 10, Buffer.alloc(0), this._suiteParams.hashLength);

        await this.destroyEphemeralKey();

        this._state = State.DONE;
        return parsed.ead;
    }

    public async composeMessage4(ead?: EdhocEAD[]): Promise<Buffer> {
        this.assertState(State.WAIT_M4_OR_DONE, 'composeMessage4');
        const th4 = this._th!;

        const k4 = await this.kdf(this._prk4e3m!, 8, th4, this._suiteParams.aeadKeyLength);
        const iv4 = await this.kdf(this._prk4e3m!, 9, th4, this._suiteParams.aeadIvLength);
        const pt4 = ead?.length ? encodeEadItems(ead) : Buffer.alloc(0);
        const aad4 = cbor.encode(['Encrypt0', Buffer.alloc(0), th4]);
        const ct4 = await this.aeadEncrypt(k4, iv4, aad4, pt4);

        const msg4 = cbor.encode(ct4);
        this._state = State.DONE;
        return msg4;
    }

    public async processMessage4(message: Buffer): Promise<EdhocEAD[]> {
        this.assertState(State.DONE, 'processMessage4');
        const th4 = this._th!;

        const ct4 = Buffer.from(cbor.decodeFirstSync(message) as Uint8Array);
        const k4 = await this.kdf(this._prk4e3m!, 8, th4, this._suiteParams.aeadKeyLength);
        const iv4 = await this.kdf(this._prk4e3m!, 9, th4, this._suiteParams.aeadIvLength);
        const aad4 = cbor.encode(['Encrypt0', Buffer.alloc(0), th4]);
        const pt4 = await this.aeadDecrypt(k4, iv4, aad4, ct4);

        return pt4.length > 0 ? parseEadItems(decodeCborSequence(pt4)) : [];
    }

    // ── export API ─────────────────────────────────────────────────────

    public async exportOSCORE(): Promise<EdhocOscoreContext> {
        if (!this._prkExporter) throw new EdhocError('Handshake not completed');

        const masterSecret = await this.kdf(this._prkExporter, 0, Buffer.alloc(0), 16);
        const masterSalt = await this.kdf(this._prkExporter, 1, Buffer.alloc(0), 8);

        // RFC 9528 §7.2.1: Initiator Sender ID = C_R, Responder Sender ID = C_I
        const senderId = connectionIdToBytes(this._peerCid!);
        const recipientId = connectionIdToBytes(this.connectionID);

        return { masterSecret, masterSalt, senderId, recipientId };
    }

    public async exportKey(exporterLabel: number, length: number): Promise<Buffer> {
        if (!this._prkExporter) throw new EdhocError('Handshake not completed');
        return this.kdf(this._prkExporter, exporterLabel, Buffer.alloc(0), length);
    }

    public exportUsedPeerCredentials(): EdhocCredentials | null {
        return this._peerCredentials;
    }

    public async keyUpdate(context: Buffer): Promise<void> {
        if (!this._prkOut) throw new EdhocError('Handshake not completed');
        this._prkOut = await this.kdf(this._prkOut, 11, context, this._suiteParams.hashLength);
        this._prkExporter = await this.kdf(this._prkOut, 10, Buffer.alloc(0), this._suiteParams.hashLength);
    }

    // ── private helpers: key schedule ──────────────────────────────────

    /** EDHOC-KDF(PRK, label, context, length) = HKDF-Expand(PRK, info, length)
     *  info is a CBOR sequence: label, context, length (NOT array-wrapped) */
    private async kdf(prk: Buffer, label: number, context: Buffer, length: number): Promise<Buffer> {
        const info = encodeCborSequence(label, context, length);
        return Buffer.from(await this.crypto.hkdfExpand(this, prk, info, length));
    }

    /** HKDF-Extract(IKM, salt) */
    private async hkdfExtract(ikm: Buffer, salt: Buffer): Promise<Buffer> {
        return Buffer.from(await this.crypto.hkdfExtract(this, ikm, salt));
    }

    /** Hash */
    private async hash(data: Buffer): Promise<Buffer> {
        return Buffer.from(await this.crypto.hash(this, data));
    }

    // ── private helpers: PRK derivation ────────────────────────────────

    /** PRK_3e2m: Methods 0,2 → PRK_2e; Methods 1,3 → Extract(SALT_3e2m, G_RX) */
    private async derivePrk3e2m(gRX?: Buffer): Promise<Buffer> {
        if ((this._method === EdhocMethod.Method1 || this._method === EdhocMethod.Method3) && gRX) {
            const salt = await this.kdf(this._prk2e!, 1, this._th!, this._suiteParams.hashLength);
            return this.hkdfExtract(gRX, salt);
        }
        return this._prk2e!;
    }

    /** PRK_4e3m: Methods 0,1 → PRK_3e2m; Methods 2,3 → Extract(SALT_4e3m, G_IX) */
    private async derivePrk4e3m(th3: Buffer, gIX?: Buffer): Promise<Buffer> {
        if ((this._method === EdhocMethod.Method2 || this._method === EdhocMethod.Method3) && gIX) {
            const salt = await this.kdf(this._prk3e2m!, 5, th3, this._suiteParams.hashLength);
            return this.hkdfExtract(gIX, salt);
        }
        return this._prk3e2m!;
    }

    // ── private helpers: ephemeral keys ────────────────────────────────

    private async generateEphemeralKey(): Promise<void> {
        const kp = await this.crypto.generateKeyPair(this);
        this._ephPrivateKey = Buffer.from(kp.privateKey);
        this._ephPub = Buffer.from(kp.publicKey);
    }

    private async destroyEphemeralKey(): Promise<void> {
        this._ephPrivateKey = null;
    }

    // ── private helpers: MAC / Signature ───────────────────────────────

    /** Determine MAC length based on role and method.
     *  Responder signature methods (0, 2): tag length; otherwise hash length.
     *  Initiator signature methods (0, 1): tag length; otherwise hash length. */
    private macLength(role: 'initiator' | 'responder'): number {
        // RFC 9528: when authenticating with signature → mac_length = hash_length
        //           when authenticating with static DH → mac_length = EDHOC MAC length
        const usesSig = role === 'responder'
            ? (this._method === EdhocMethod.Method0 || this._method === EdhocMethod.Method2)
            : (this._method === EdhocMethod.Method0 || this._method === EdhocMethod.Method1);
        return usesSig ? this._suiteParams.hashLength : this._suiteParams.macLength;
    }

    /** Build context bytes: << [C_R,] ID_CRED_x, TH, CRED_x, ?EAD >> */
    private buildContext(
        cRCbor: Buffer | null, idCredCbor: Buffer, th: Buffer, credXCbor: Buffer, ead?: EdhocEAD[],
    ): Buffer {
        const parts: Buffer[] = [];
        if (cRCbor) parts.push(cRCbor);
        parts.push(idCredCbor, cbor.encode(th), credXCbor);
        if (ead?.length) parts.push(encodeEadItems(ead));
        return Buffer.concat(parts);
    }

    /** Build Enc_structure external_aad for CIPHERTEXT_3/4: ["Encrypt0", h'', TH] */
    private buildEncAad(th: Buffer, _credX?: Buffer, _ead?: EdhocEAD[]): Buffer {
        // RFC 9528: AAD for AEAD = Enc_structure = ["Encrypt0", h'', TH_x]
        return cbor.encode(['Encrypt0', Buffer.alloc(0), th]);
    }

    /** Compute Signature_or_MAC for the local party */
    private async signOrMac(
        role: 'initiator' | 'responder',
        cred: EdhocCredentials,
        idCredCbor: Buffer,
        th: Buffer,
        credXCbor: Buffer,
        ead: EdhocEAD[] | undefined,
        mac: Buffer,
    ): Promise<Buffer> {
        const usesSig = role === 'responder'
            ? (this._method === EdhocMethod.Method0 || this._method === EdhocMethod.Method2)
            : (this._method === EdhocMethod.Method0 || this._method === EdhocMethod.Method1);

        if (!usesSig) return mac;

        // Sig_structure = ["Signature1", << ID_CRED_x >>, << TH, CRED_x, ?EAD >>, MAC]
        const externalAad = this.buildSigExternalAad(th, credXCbor, ead);
        const sigStructure = cbor.encode(['Signature1', idCredCbor, externalAad, mac]);
        return Buffer.from(await this.crypto.sign(
            this, cred.privateKey!, sigStructure));
    }

    /** Verify Signature_or_MAC from the peer */
    private async verifySignatureOrMac(
        peerRole: 'initiator' | 'responder',
        peerCred: EdhocCredentials,
        idCredCbor: Buffer,
        th: Buffer,
        credXCbor: Buffer,
        ead: EdhocEAD[] | undefined,
        mac: Buffer,
        received: Buffer,
    ): Promise<void> {
        const usesSig = peerRole === 'responder'
            ? (this._method === EdhocMethod.Method0 || this._method === EdhocMethod.Method2)
            : (this._method === EdhocMethod.Method0 || this._method === EdhocMethod.Method1);

        if (!usesSig) {
            if (!mac.equals(received)) throw new EdhocError('MAC verification failed');
            return;
        }

        const externalAad = this.buildSigExternalAad(th, credXCbor, ead);
        const sigStructure = cbor.encode(['Signature1', idCredCbor, externalAad, mac]);

        await this.crypto.verify(this, peerCred.publicKey!, sigStructure, received);
    }

    /** Build the external_aad bstr for Sig_structure: concatenation of CBOR items */
    private buildSigExternalAad(th: Buffer, credXCbor: Buffer, ead?: EdhocEAD[]): Buffer {
        const parts = [cbor.encode(th), credXCbor];
        if (ead?.length) parts.push(encodeEadItems(ead));
        return Buffer.concat(parts);
    }

    // ── private helpers: AEAD ──────────────────────────────────────────

    private async aeadEncrypt(key: Buffer, iv: Buffer, aad: Buffer, pt: Buffer): Promise<Buffer> {
        return Buffer.from(await this.crypto.encrypt(this, key, iv, aad, pt));
    }

    private async aeadDecrypt(key: Buffer, iv: Buffer, aad: Buffer, ct: Buffer): Promise<Buffer> {
        return Buffer.from(await this.crypto.decrypt(this, key, iv, aad, ct));
    }

    // ── private helpers: misc ──────────────────────────────────────────

    private xor(a: Buffer, b: Buffer): Buffer {
        const out = Buffer.alloc(a.length);
        for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
        return out;
    }

    private log(name: string, data: Buffer): void {
        if (this.logger) this.logger(name, data);
    }

    private assertState(expected: State, method: string): void {
        if (this._state !== expected) {
            throw new EdhocError(`Invalid state for ${method}`);
        }
    }
}
