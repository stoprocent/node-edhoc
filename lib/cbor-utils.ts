import cbor from 'cbor';
import {
    EdhocCredentials,
    EdhocCredentialsFormat,
    EdhocCredentialsCertificateChain,
    EdhocCredentialsCertificateHash,
    EdhocCredentialsKID,
    EdhocConnectionID,
    EdhocEAD,
    EdhocSuite,
} from './edhoc';

/** Encode a CBOR sequence (concatenated CBOR items) */
export function encodeCborSequence(...items: unknown[]): Buffer {
    return Buffer.concat(items.map(item => cbor.encode(item)));
}

/** Decode N items from a CBOR sequence buffer */
export function decodeCborSequence(buf: Buffer, count?: number): unknown[] {
    const results: unknown[] = [];
    let offset = 0;
    while (offset < buf.length && (count === undefined || results.length < count)) {
        const result = cbor.decodeFirstSync(buf.subarray(offset), { extendedResults: true });
        results.push(result.value);
        offset += result.length;
    }
    return results;
}

/** Encode SUITES_I: single int if one suite, array if multiple (selected last) */
export function encodeSuites(suites: EdhocSuite[], selected: EdhocSuite): number | number[] {
    if (suites.length === 1) return suites[0];
    const rest = suites.filter(s => s !== selected);
    rest.push(selected);
    return rest;
}

/** Convert a connection ID to its raw byte representation (for OSCORE IDs).
 *  RFC 9528 §3.3.2: the OSCORE identifier is a 1-byte bstr whose byte value
 *  is the CBOR encoding of the integer n ∈ [-24, 23]. */
export function connectionIdToBytes(cid: EdhocConnectionID): Buffer {
    if (Buffer.isBuffer(cid)) return cid;
    // CBOR encoding of integer n:
    //   n >= 0  → major type 0, additional info = n  → byte = n
    //   n <  0  → major type 1, additional info = -(n+1) → byte = 0x20 | (-(n+1))
    if (cid >= 0) return Buffer.from([cid]);
    return Buffer.from([0x20 | (-(cid + 1))]);
}

/** Decode a CBOR-decoded value back to an EdhocConnectionID */
export function connectionIdFromCbor(value: unknown): EdhocConnectionID {
    if (typeof value === 'number') return value;
    if (Buffer.isBuffer(value)) return value;
    if (value instanceof Uint8Array) return Buffer.from(value);
    throw new Error(`Invalid connection ID: ${typeof value}`);
}

/** Encode ID_CRED_x for PLAINTEXT / context embedding (already CBOR) */
export function encodeIdCred(credentials: EdhocCredentials): Buffer {
    switch (credentials.format) {
        case EdhocCredentialsFormat.kid: {
            const kid = (credentials as EdhocCredentialsKID).kid.kid;
            return cbor.encode(kid);
        }
        case EdhocCredentialsFormat.x5chain: {
            const certs = (credentials as EdhocCredentialsCertificateChain).x5chain.certificates;
            const map = new Map<number, unknown>();
            map.set(EdhocCredentialsFormat.x5chain, certs.length === 1 ? certs[0] : certs);
            return cbor.encode(map);
        }
        case EdhocCredentialsFormat.x5t: {
            const x5t = (credentials as EdhocCredentialsCertificateHash).x5t;
            const map = new Map<number, unknown>();
            map.set(EdhocCredentialsFormat.x5t, [x5t.hashAlgorithm, x5t.hash]);
            return cbor.encode(map);
        }
        default:
            throw new Error(`Unsupported credential format`);
    }
}

/** Encode ID_CRED_x as a CBOR map (full form for MAC context / Sig_structure).
 *  For kid: {4: bstr(cbor(kid))}; for x5chain/x5t: same as encodeIdCred. */
export function encodeIdCredMap(credentials: EdhocCredentials): Buffer {
    switch (credentials.format) {
        case EdhocCredentialsFormat.kid: {
            const kid = (credentials as EdhocCredentialsKID).kid.kid;
            const kidCborBytes = cbor.encode(kid);
            const map = new Map<number, unknown>();
            map.set(EdhocCredentialsFormat.kid, kidCborBytes);
            return cbor.encode(map);
        }
        default:
            return encodeIdCred(credentials);
    }
}

/** Encode CRED_x as a CBOR item for use in context / TH input.
 *  For CCS (kid + isCBOR): credBytes is already CBOR, return as-is.
 *  For DER certs: wrap as CBOR bstr. */
export function encodeCredItem(credentials: EdhocCredentials, credBytes: Buffer): Buffer {
    if (credentials.format === EdhocCredentialsFormat.kid &&
        (credentials as EdhocCredentialsKID).kid.isCBOR) {
        return credBytes;
    }
    return cbor.encode(credBytes);
}

/** Decode an ID_CRED_x value (already CBOR-decoded) into partial credentials */
export function decodeIdCred(value: unknown): EdhocCredentials {
    if (typeof value === 'number' || Buffer.isBuffer(value) || value instanceof Uint8Array) {
        const kid = Buffer.isBuffer(value) || value instanceof Uint8Array
            ? Buffer.from(value as Uint8Array) : value;
        return { format: EdhocCredentialsFormat.kid, kid: { kid } } as EdhocCredentialsKID;
    }
    if (value instanceof Map) {
        if (value.has(EdhocCredentialsFormat.x5chain)) {
            const d = value.get(EdhocCredentialsFormat.x5chain);
            const certificates = Array.isArray(d)
                ? d.map((c: unknown) => Buffer.from(c as Uint8Array))
                : [Buffer.from(d as Uint8Array)];
            return { format: EdhocCredentialsFormat.x5chain, x5chain: { certificates } } as EdhocCredentialsCertificateChain;
        }
        if (value.has(EdhocCredentialsFormat.x5t)) {
            const arr = value.get(EdhocCredentialsFormat.x5t) as unknown[];
            return {
                format: EdhocCredentialsFormat.x5t,
                x5t: { hashAlgorithm: arr[0] as number, hash: Buffer.from(arr[1] as Uint8Array) },
            } as EdhocCredentialsCertificateHash;
        }
        if (value.has(EdhocCredentialsFormat.kid)) {
            return {
                format: EdhocCredentialsFormat.kid,
                kid: { kid: value.get(EdhocCredentialsFormat.kid) as number | Buffer },
            } as EdhocCredentialsKID;
        }
    }
    throw new Error(`Cannot decode ID_CRED_x`);
}

/** Get the raw credential bytes (CRED_x) from credentials */
export function getCredBytes(credentials: EdhocCredentials): Buffer {
    switch (credentials.format) {
        case EdhocCredentialsFormat.kid: {
            const c = (credentials as EdhocCredentialsKID).kid.credentials;
            if (!c) throw new Error('KID credentials require credential data');
            return c;
        }
        case EdhocCredentialsFormat.x5chain:
            return (credentials as EdhocCredentialsCertificateChain).x5chain.certificates[0];
        case EdhocCredentialsFormat.x5t: {
            const cert = (credentials as EdhocCredentialsCertificateHash).x5t.certificate;
            if (!cert) throw new Error('x5t credentials require the certificate');
            return cert;
        }
        default:
            throw new Error(`Unsupported credential format for CRED_x`);
    }
}

/** Encode PLAINTEXT_2/3: ID_CRED_x, Signature_or_MAC_x, ?EAD */
export function encodePlaintext(idCredCbor: Buffer, signatureOrMac: Buffer, ead?: EdhocEAD[]): Buffer {
    const parts = [idCredCbor, cbor.encode(signatureOrMac)];
    if (ead && ead.length > 0) parts.push(encodeEadItems(ead));
    return Buffer.concat(parts);
}

/** Parse PLAINTEXT_2/3 into { idCredRaw, signatureOrMac, ead } */
export function parsePlaintext(data: Buffer): { idCredRaw: unknown; signatureOrMac: Buffer; ead: EdhocEAD[] } {
    const items = decodeCborSequence(data);
    if (items.length < 2) throw new Error('PLAINTEXT must contain at least 2 items');
    const sigRaw = items[1];
    return {
        idCredRaw: items[0],
        signatureOrMac: Buffer.isBuffer(sigRaw) ? sigRaw : Buffer.from(sigRaw as Uint8Array),
        ead: items.length > 2 ? parseEadItems(items.slice(2)) : [],
    };
}

/** Encode EAD tokens as a CBOR sequence of (label, ?value) pairs */
export function encodeEadItems(tokens: EdhocEAD[]): Buffer {
    const parts: Buffer[] = [];
    for (const t of tokens) {
        parts.push(cbor.encode(t.label));
        if (t.value && t.value.length > 0) parts.push(cbor.encode(t.value));
    }
    return Buffer.concat(parts);
}

/** Parse EAD items from decoded CBOR values */
export function parseEadItems(items: unknown[]): EdhocEAD[] {
    const result: EdhocEAD[] = [];
    let i = 0;
    while (i < items.length) {
        const label = items[i] as number;
        i++;
        let value = Buffer.alloc(0);
        if (i < items.length && typeof items[i] !== 'number') {
            value = Buffer.isBuffer(items[i]) ? items[i] as Buffer : Buffer.from(items[i] as Uint8Array);
            i++;
        }
        result.push({ label, value });
    }
    return result;
}
