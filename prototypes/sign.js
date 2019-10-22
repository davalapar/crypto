/* eslint-disable no-console */

const crypto = require('crypto');

// console.log(crypto.getCurves());
// console.log(crypto.getHashes());
// console.log(crypto.getCiphers());
// crypto.getCiphers().forEach((x) => console.log(x));

// ed25519:
const keys = crypto.generateKeyPairSync('ed25519', {
  publicKeyEncoding: {
    type: 'spki',
    format: 'der',
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'der', // pem=string, der=buffer
  },
});
console.log({ keys });
const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
console.log('yeh');
console.log({ privateKey, publicKey });
const signature = crypto.sign(null, Buffer.from('test'), privateKey);
console.log(signature.toString('hex'));
console.log(crypto.verify(null, Buffer.from('test'), publicKey, signature));

// chacha20-poly1305:
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('chacha20-poly1305', key, iv, { authTagLength: 12 });
let encrypted = cipher.update('some clear text data', 'utf8', 'hex');
encrypted += cipher.final('hex');
console.log(encrypted);
const decipher = crypto.createDecipheriv('chacha20-poly1305', key, iv, { authTagLength: 12 });
let decrypted = decipher.update(encrypted, 'hex', 'utf8');
decrypted += decipher.final('utf8');
console.log(decrypted);
