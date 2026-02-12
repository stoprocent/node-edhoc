export interface CipherSuiteParams {
    id: number;
    aeadAlgorithm: string;
    aeadKeyLength: number;
    aeadTagLength: number;
    aeadIvLength: number;
    hashAlgorithm: string;
    hashLength: number;
    macLength: number;
    eccKeyLength: number;
    eccSignLength: number;
}

// RFC 9528 Section 3.6 - Cipher Suites
// Uses literal keys to avoid circular dependency with edhoc.ts
const CIPHER_SUITES: Record<number, CipherSuiteParams> = {
    0: { id: 0, aeadAlgorithm: 'AES-CCM-16-64-128',  aeadKeyLength: 16, aeadTagLength:  8, aeadIvLength: 13, hashAlgorithm: 'SHA-256',   hashLength: 32, macLength:  8, eccKeyLength: 32, eccSignLength:  64 },
    1: { id: 1, aeadAlgorithm: 'AES-CCM-16-128-128', aeadKeyLength: 16, aeadTagLength: 16, aeadIvLength: 13, hashAlgorithm: 'SHA-256',   hashLength: 32, macLength: 16, eccKeyLength: 32, eccSignLength:  64 },
    2: { id: 2, aeadAlgorithm: 'AES-CCM-16-64-128',  aeadKeyLength: 16, aeadTagLength:  8, aeadIvLength: 13, hashAlgorithm: 'SHA-256',   hashLength: 32, macLength:  8, eccKeyLength: 32, eccSignLength:  64 },
    3: { id: 3, aeadAlgorithm: 'AES-CCM-16-128-128', aeadKeyLength: 16, aeadTagLength: 16, aeadIvLength: 13, hashAlgorithm: 'SHA-256',   hashLength: 32, macLength: 16, eccKeyLength: 32, eccSignLength:  64 },
    4: { id: 4, aeadAlgorithm: 'ChaCha20/Poly1305',  aeadKeyLength: 32, aeadTagLength: 16, aeadIvLength: 12, hashAlgorithm: 'SHA-256',   hashLength: 32, macLength: 16, eccKeyLength: 32, eccSignLength:  64 },
    5: { id: 5, aeadAlgorithm: 'ChaCha20/Poly1305',  aeadKeyLength: 32, aeadTagLength: 16, aeadIvLength: 12, hashAlgorithm: 'SHA-256',   hashLength: 32, macLength: 16, eccKeyLength: 32, eccSignLength:  64 },
    6: { id: 6, aeadAlgorithm: 'AES-GCM-128',        aeadKeyLength: 16, aeadTagLength: 16, aeadIvLength: 12, hashAlgorithm: 'SHA-256',   hashLength: 32, macLength: 16, eccKeyLength: 32, eccSignLength:  64 },
   24: { id:24, aeadAlgorithm: 'AES-GCM-256',        aeadKeyLength: 32, aeadTagLength: 16, aeadIvLength: 12, hashAlgorithm: 'SHA-384',   hashLength: 48, macLength: 16, eccKeyLength: 48, eccSignLength:  96 },
   25: { id:25, aeadAlgorithm: 'ChaCha20/Poly1305',  aeadKeyLength: 32, aeadTagLength: 16, aeadIvLength: 12, hashAlgorithm: 'SHAKE256',  hashLength: 64, macLength: 16, eccKeyLength: 56, eccSignLength: 114 },
};

export function getCipherSuiteParams(suite: number): CipherSuiteParams {
    const params = CIPHER_SUITES[suite];
    if (!params) throw new Error(`Unsupported cipher suite: ${suite}`);
    return params;
}
