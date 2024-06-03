const addon = require('../build/Debug/bindings');

const edhoc_1 = new addon.LibEDHOC(10, 1);
const edhoc_2 = new addon.LibEDHOC(1670, 2);
const edhoc_3 = new addon.LibEDHOC(Buffer.from('00112233', 'hex'), 3);

console.log("Connection Read")
console.log(edhoc_1.connectionID)
console.log(edhoc_2.connectionID)
console.log(edhoc_3.connectionID)

console.log("")
console.log("Method 1")
console.log(edhoc_1.method)
console.log(edhoc_2.method)
console.log(edhoc_3.method)

console.log("")
console.log("Connection Read 2")
edhoc_1.connectionID = Buffer.from('99887766', 'hex')
edhoc_2.connectionID = 23
edhoc_3.connectionID = 11223344;

edhoc_1.method = 3;
edhoc_2.method = 2;
edhoc_3.method = 1;

console.log(edhoc_1.connectionID)
console.log(edhoc_2.connectionID)
console.log(edhoc_3.connectionID)

console.log("")
console.log("Method 2")
console.log(edhoc_1.method)
console.log(edhoc_2.method)
console.log(edhoc_3.method)