# EDHOC for Node.js

A pure TypeScript implementation of the Ephemeral Diffie-Hellman Over COSE (EDHOC) protocol, as specified in [RFC 9528](https://datatracker.ietf.org/doc/rfc9528/). It provides an efficient and lightweight way to establish secure communication with minimal overhead.

## Overview

EDHOC is designed for lightweight communication and is particularly suitable for protocols like CoAP and OSCORE, but can work independently of the application and transport layers, ensuring minimal overhead while maintaining strong security guarantees. The library provides a default software implementation for X.509 credentials, with support for additional formats such as C509, CWT, and CCS coming soon. It also includes a software-based cryptographic implementation utilizing [`@noble/curves`](https://www.npmjs.com/package/@noble/curves/v/1.0.0). Additionally, it exposes credential and cryptographic API interfaces to allow for custom implementations, such as PKCS#11-based solutions.

## Features

- Full implementation of the EDHOC protocol (RFC 9528)
- Pure TypeScript implementation with no native dependencies
- Type safety and excellent developer experience
- Software-based cryptography using [`@noble/curves`](https://www.npmjs.com/package/@noble/curves)

## Installation

Install the package via npm:

```bash
npm install edhoc
```

## Usage Examples

### Basic Handshake

The simplest EDHOC handshake using pre-shared keys (Method 0):

```typescript
import { EDHOC, EdhocMethod, EdhocSuite } from 'node-edhoc';

// ...

const initiator = new EDHOC(10, [ EdhocMethod.Method0 ], [ EdhocSuite.Suite0 ], credentialsManager, cryptoManager);
const responder = new EDHOC(20, [ EdhocMethod.Method0 ], [ EdhocSuite.Suite0 ], credentialsManager, cryptoManager);

// Message 1: Initiator → Responder
const message1 = await initiator.composeMessage1();
await responder.processMessage1(message1);

// Message 2: Responder → Initiator
const message2 = await responder.composeMessage2();
await initiator.processMessage2(message2);

// Message 3: Initiator → Responder
const message3 = await initiator.composeMessage3();
await responder.processMessage3(message3);

// ...

```

### Using External Authorization Data (EAD)

You can include additional authorization data in EDHOC messages:

```typescript
// initiator.js
const ead_1 = [{ 
  label: 1000, 
  value: Buffer.from('External Data') 
}];

const message1 = await initiator.composeMessage1(ead_1);

// responder.js
const receivedEAD = await responder.processMessage1(message1);
```

### Certificate-Based Authentication

Using X.509 certificates for authentication:

```typescript
import { 
  EDHOC, 
  X509CertificateCredentialManager, 
  DefaultEdhocCryptoManager 
} from 'node-edhoc';

// Setup credential managers
const initiatorCreds = new X509CertificateCredentialManager(
  [initiatorCert],
  initiatorKeyID
);
initiatorCreds.addTrustedCA(trustedCA);

// Setup crypto managers
const initiatorCrypto = new DefaultEdhocCryptoManager();

// Initialize EDHOC with certificate-based auth
const initiator = new EDHOC(
  10, 
  [ EdhocMethod.Method0 ], 
  [ EdhocSuite.Suite2 ],
  initiatorCreds,
  initiatorCrypto
);
```

### X.509 Certificate Credentials

```typescript
import {
  EDHOC,
  EdhocMethod,
  EdhocSuite,
  X509CertificateCredentialManager,
  DefaultEdhocCryptoManager,
} from 'node-edhoc';

// Set up credentials with the private key
const credMgr = new X509CertificateCredentialManager([myCert], myPrivateKey);
credMgr.addTrustedCA(caCert);

// Set up crypto
const crypto = new DefaultEdhocCryptoManager();

const session = new EDHOC(
  10,
  [EdhocMethod.Method0],
  [EdhocSuite.Suite2],
  credMgr,
  crypto,
);
```

### CCS/kid Credentials

CCS (CWT Claims Set) credentials are lightweight CBOR-encoded identity documents
commonly used in constrained IoT environments. Each CCS is a CBOR map containing
a subject name and a COSE_Key with the party's public key, identified by a `kid`
(key ID) value.

```typescript
import cbor from 'cbor';
import {
  EDHOC,
  EdhocMethod,
  EdhocSuite,
  CCSCredentialManager,
  DefaultEdhocCryptoManager,
} from 'node-edhoc';

// --- Step 1: Build CCS credentials as CBOR ---
//
// A CCS follows the structure from RFC 8747 (cnf claim) with a COSE_Key (RFC 9052):
//
//   {
//     2: "subject-name",      / sub: subject identifier /
//     8: {                    / cnf: confirmation claim  /
//       1: {                  / COSE_Key                 /
//         1: kty,             /   key type (2 = EC2)     /
//         2: kid_bstr,        /   kid as bstr            /
//        -1: crv,             /   curve (1 = P-256)      /
//        -2: x_coord,         /   x-coordinate (32 B)    /
//        -3: y_coord          /   y-coordinate (32 B)    /
//       }
//     }
//   }

function buildCCS(
  subject: string,
  kid: number,
  curve: number,
  publicKeyX: Buffer,
  publicKeyY: Buffer,
): Buffer {
  // kid on the wire is a 1-byte bstr containing the CBOR encoding of the kid value
  const kidCborByte = kid >= 0 ? kid : (0x20 | (-(kid + 1)));

  const coseKey = new Map<number, any>();
  coseKey.set(1, 2);                          // kty: EC2
  coseKey.set(2, Buffer.from([kidCborByte])); // kid
  coseKey.set(-1, curve);                     // crv: P-256 = 1
  coseKey.set(-2, publicKeyX);                // x (32 bytes)
  coseKey.set(-3, publicKeyY);                // y (32 bytes)

  const ccs = new Map<number, any>();
  ccs.set(2, subject);                        // sub
  ccs.set(8, new Map([[1, coseKey]]));         // cnf → COSE_Key

  return cbor.encode(ccs);
}

// Example using RFC 9529 Chapter 3 test vector values (P-256):
const myPublicKeyX  = Buffer.from('ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6', 'hex');
const myPublicKeyY  = Buffer.from('6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8', 'hex');
const myCCS = buildCCS('42-50-31-FF-EF-37-32-39', -12, 1, myPublicKeyX, myPublicKeyY);

const peerPublicKeyX = Buffer.from('bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0', 'hex');
const peerPublicKeyY = Buffer.from('4519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072', 'hex');
const peerCCS = buildCCS('example.edu', -19, 1, peerPublicKeyX, peerPublicKeyY);

// --- Step 2: Register credentials ---

const credMgr = new CCSCredentialManager();
credMgr.addOwnCredential(-12, myCCS, myPublicKeyX, myPrivateKey);      // kid, CCS bytes, public key (x-only), private key
credMgr.addPeerCredential(-19, peerCCS, peerPublicKeyX);               // kid, CCS bytes, public key (x-only)

// --- Step 3: Set up crypto ---

const crypto = new DefaultEdhocCryptoManager();

// --- Step 4: Create session (Method 3 = StaticDH both sides) ---

const session = new EDHOC(
  10,
  [EdhocMethod.Method3],
  [EdhocSuite.Suite2],
  credMgr,
  crypto,
);
```

### Exporting OSCORE Context

After a successful handshake, you can export the OSCORE security context:

```typescript
const initiatorContext = await initiator.exportOSCORE();
const responderContext = await responder.exportOSCORE();

console.log('Master Secret:', initiatorContext.masterSecret);
console.log('Master Salt:', initiatorContext.masterSalt);
console.log('Sender ID:', initiatorContext.senderId);
console.log('Recipient ID:', initiatorContext.recipientId);
```

### Key Update

Perform a key update for an existing OSCORE context:

```typescript
const keyUpdateContext = Buffer.from('new-entropy-data');

// Update keys for both parties
await initiator.keyUpdate(keyUpdateContext);
await responder.keyUpdate(keyUpdateContext);

// Export new OSCORE context
const newContext = await initiator.exportOSCORE();
```

### Custom Key Export

Export application-specific keys:

```typescript
// Export a 32-byte key with label 40001
const key = await initiator.exportKey(40001, 32);
```

For more detailed examples and API documentation, please refer to our [API Documentation](#).

## Documentation

For detailed documentation, refer to:

- [EDHOC Specification (RFC 9528)](https://datatracker.ietf.org/doc/rfc9528/)

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository and create a new branch.
2. Implement your feature or bugfix.
3. Write tests if applicable.
4. Open a pull request.

Please ensure your code follows the existing style and structure of the project.

## License

This project is licensed under the [MIT License](LICENSE).

## Related Projects

- [@noble/curves](https://github.com/paulmillr/noble-curves) - Audited & minimal JS implementation of elliptic curve cryptography
- [OSCORE](https://datatracker.ietf.org/doc/rfc8613/) - Object Security for Constrained RESTful Environments

## Acknowledgments

This implementation is based on the EDHOC specification as defined in RFC 9528. Special thanks to the developers of [`libedhoc`](https://github.com/kamil-kielbasa/libedhoc/) for their foundational work on EDHOC in C.

