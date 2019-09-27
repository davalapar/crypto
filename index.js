/* eslint-disable no-console, no-bitwise */

const crypto = require('crypto');
const base32 = require('hi-base32');

/**
 * Links:
 * - https://pthree.org/2014/04/15/time-based-one-time-passwords-how-it-works/
 * - https://dev.to/al_khovansky/generating-2fa-one-time-passwords-in-js-using-web-crypto-api-1hfo
 * - http://blog.tinisles.com/2011/10/google-authenticator-one-time-password-algorithm-in-javascript/
 * - https://github.com/gbraad/gauth/blob/master/js/gauth.js
 * - https://gauth.apps.gbraad.nl/#main
 * - https://en.wikipedia.org/wiki/Google_Authenticator#Pseudocode_for_one-time_password_(OTP)
 * - https://github.com/guyht/notp/blob/master/index.js
 */

/**
 * Pointers:
 * - Secrets must be 128-bit, or 16 bytes
 */

const dec2hex = (s) => (s < 15.5 ? '0' : '') + Math.round(s).toString(16);

const totp = (secret) => {
  // message := floor(current Unix time / 30)
  const message = dec2hex(Math.floor(Math.round(Date.now() / 1000) / 30)).padStart(16, '0');
  console.log(message);

  // hash := HMAC-SHA1(secret, message)
  const hash = crypto.createHmac('sha1', Buffer.from(base32.decode.asBytes(secret))).update(message, 'hex').digest('hex');
  console.log(hash);

  // offset := last nibble of hash
  const offset = parseInt(hash.substring(hash.length - 1), 16);
  console.log(offset);

  // truncatedHash := hash[offset..offset+3]  //4 bytes starting at the offset
  // Set the first bit of truncatedHash to zero  //remove the most significant bit
  const truncated = '0'.concat(hash.substring(offset * 2, (offset * 2) + 8).substring(1));
  console.log(truncated);

  // code := truncatedHash mod 1000000
  // pad code with 0 from the left until length of code is 6
  return (parseInt(truncated, 16) % 1000000).toString().padStart(6, '0');
};

const code2 = totp('PFQW233NONQWQ33F');
console.log({ code2 });


const hotp = (key, counter) => {
  // message := floor(current Unix time / 30)
  const message = Buffer.alloc(8).fill(0);
  message.writeUInt32BE(counter, 4);

  // hash := HMAC-SHA1(secret, message)
  const secret = Buffer.from(key);
  const hash = crypto.createHmac('sha1', secret).update(message).digest();

  // offset := last nibble of hash
  const offset = hash[19] & 0xf;

  // truncatedHash := hash[offset..offset+3]  //4 bytes starting at the offset
  // Set the first bit of truncatedHash to zero  //remove the most significant bit
  let code = (hash[offset] & 0x7f) << 24;
  code |= (hash[offset + 1] & 0xff) << 16;
  code |= (hash[offset + 2] & 0xff) << 8;
  code |= (hash[offset + 3] & 0xff);

  // code := truncatedHash mod 1000000
  code %= 1000000;

  // pad code with 0 from the left until length of code is 6
  code = String(code).padStart(6, '0');
  return code;
};
const timestamp = Math.floor(Math.round(Date.now() / 1000) / 30);
console.log(hotp(base32.decode('PFQW233NONQWQ33F'), timestamp));

//
/*
const secret = 'PFQW233NONQWQ33F';
const timestamp = Math.floor(Math.round(Date.now() / 1000) / 30);
const buffer = crypto.createHmac('sha256', Buffer.from(base32.decode.asBytes(secret))).update(Buffer.from(String(timestamp))).digest();
const offset = parseInt(buffer.slice(buffer.byteLength - 1).toString('hex')[1], 16);
const sliced = buffer.slice(offset);
const code = String(parseInt(sliced.toString('hex'), 16) % 1000000);
console.log(code);
*/
