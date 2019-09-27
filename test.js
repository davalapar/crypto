/* eslint-disable no-console */

const { totpCreateSecret, totp, totpValidate } = require('./index');

const secret = totpCreateSecret();
console.log({ secret });
console.log();

const windowCounter = Math.floor(Math.round(Date.now() / 1000) / 30);
const code = totp('sha1', secret, windowCounter);

console.log('Test case 1: Code within 30s are valid.');
console.log({ code, windowCounter });
console.log(`Match? ${totpValidate('sha1', secret, code)}`);
console.log();

const windowCounter2 = windowCounter - 90;
const code2 = totp('sha1', secret, windowCounter2);
console.log('Test case 2: Code within 90s are valid.');
console.log({ code2, windowCounter2 });
console.log(`Match? ${totpValidate('sha1', secret, code2, 3)}`);
console.log();

const windowCounter3 = Math.floor(Math.round(Date.now() / 1000) / 30);
const code3 = totp('sha256', secret, windowCounter);

console.log('Test case 3: SHA256 support.');
console.log({ code3, windowCounter3 });
console.log(`Match? ${totpValidate('sha256', secret, code3)}`);
console.log();
