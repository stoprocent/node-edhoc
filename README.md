# Node EDHOC

A TypeScript Node.js library implemented as a native addon, built on top of the C library [`libedhoc`](https://github.com/kamil-kielbasa/libedhoc/). It provides an efficient and lightweight way to use the Ephemeral Diffie-Hellman Over COSE (EDHOC) protocol, as specified in [RFC 9528](https://datatracker.ietf.org/doc/rfc9528/).

## Overview

EDHOC is designed for lightweight communication and is particularly suitable for protocols like CoAP and OSCORE, but can work independently of the application and transport layers, ensuring minimal overhead while maintaining strong security guarantees. The library provides a default software implementation for X.509 credentials, with support for additional formats such as C509, CWT, and CCS coming soon. It also includes a software-based cryptographic implementation utilizing [`@noble/curves`](https://www.npmjs.com/package/@noble/curves/v/1.0.0). Additionally, it exposes credential and cryptographic API interfaces to allow for custom implementations, such as PKCS#11-based solutions.

## Features

- Full implementation of the EDHOC protocol (RFC 9528)
- TypeScript support for type safety and better developer experience
- Based on [`libedhoc`](https://github.com/kamil-kielbasa/libedhoc), a proven C implementation

## Installation

Install the package via npm:

```bash
npm install node-edhoc
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
- [API Documentation](#) *(TODO: Link to generated API docs if available)*

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

- [libedhoc](https://github.com/kamil-kielbasa/libedhoc/) - A C implementation of the Ephemeral Diffie-Hellman Over COSE

## Acknowledgments

This implementation is based on the EDHOC specification as defined in RFC 9528. Special thanks to the developers of [`libedhoc`](https://github.com/kamil-kielbasa/libedhoc/) for their foundational work on EDHOC in C.

