/* eslint-disable no-console */

const {
  randomBytes,
  totpCode,
  totpVerify,
  hotpKey,
  scryptKey,
  scryptSalt,
} = require('./index');

const key = hotpKey();
console.log({ key });
console.log();

const timeCounter = Math.floor(Math.round(Date.now() / 1000) / 30);
const code = totpCode('sha1', key, true, timeCounter);

console.log('Test case 1: Code within 30s are valid.');
console.log({ code, timeCounter });
console.log(`Match? ${totpVerify('sha1', key, true, code)}`);
console.log();

const timeCounter2 = timeCounter - 90;
const code2 = totpCode('sha1', key, true, timeCounter2);
console.log('Test case 2: Code within 90s are valid.');
console.log({ code2, timeCounter2 });
console.log(`Match? ${totpVerify('sha1', key, true, code2, 3)}`);
console.log();

const timeCounter3 = Math.floor(Math.round(Date.now() / 1000) / 30);
const code3 = totpCode('sha256', key, true, timeCounter);

console.log('Test case 3: SHA256 support.');
console.log({ code3, timeCounter3 });
console.log(`Match? ${totpVerify('sha256', key, true, code3)}`);
console.log();

(async () => {
  const salt = scryptSalt();
  const derivedKey = await scryptKey('asd', salt);
  console.log('salt:', salt.toString('hex'));
  console.log('key:', derivedKey.toString('hex'));
  const derivedKey2 = await scryptKey('asd', salt);
  console.log('key:', derivedKey2.toString('hex'));
})();

setTimeout(() => {
  console.log(randomBytes.sync(32).toString('hex'));
  randomBytes.async(32).then((buffer) => console.log(buffer.toString('hex')));
}, 1000);
