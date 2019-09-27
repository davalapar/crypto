/* eslint-disable no-console, no-bitwise */

const crypto = require('crypto');
const base32 = require('hi-base32');

/*
  Less-readable alternative:
    const offset = parseInt(hash.slice(hash.byteLength - 1).toString('hex')[1], 16);
    let code = (hash[offset] & 0x7f) << 24;
    code |= (hash[offset + 1] & 0xff) << 16;
    code |= (hash[offset + 2] & 0xff) << 8;
    code |= (hash[offset + 3] & 0xff);
    code %= 1000000;
    code = String(code).padStart(6, '0');
*/
const hotp = (algorithm, key, counter) => {
  // message := floor(current Unix time / 30)
  const message = Buffer.alloc(8).fill(0);
  message.writeUInt32BE(counter, 4);

  // hash := HMAC-SHA1(secret, message)
  const secret = Buffer.isBuffer(key) ? key : Buffer.from(key);
  const hash = crypto.createHmac(algorithm, secret).update(message).digest();

  // offset := last nibble of hash
  const offset = hash[hash.byteLength - 1] & 0xf;

  // truncatedHash := hash[offset..offset+3]  //4 bytes starting at the offset
  const truncated = hash.slice(offset, offset + 4);

  // Set the first bit of truncatedHash to zero  //remove the most significant bit
  truncated[0] &= 0x7f;

  // code := truncatedHash mod 1000000
  // pad code with 0 from the left until length of code is 6
  const code = String(truncated.readUInt32BE() % 1000000).padStart(6, '0');
  return code;
};

const totp = (algorithm, secret, windowCounter) => hotp(algorithm, base32.decode.asBytes(secret), windowCounter);

const totpValidate = (algorithm, secret, code, tolerance) => {
  // get our current 30-second window
  const windowCounter = Math.floor(Math.round(Date.now() / 1000) / 30);

  // iterate backwards on the amount of previous
  // 30-second windows we are wiling to accept
  for (let i = 0; i <= (tolerance || 1); i += 1) {
    if (totp(algorithm, secret, windowCounter - (i * 30)) === code) {
      return true;
    }
  }
  return false;
};

const totpCreateSecret = () => base32.encode(crypto.randomBytes(16)).replace(/=/g, '');

module.exports = {
  hotp,
  totp,
  totpValidate,
  totpCreateSecret,
};
