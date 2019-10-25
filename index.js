/* eslint-disable no-console, no-bitwise */

const os = require('os');
const fs = require('fs');
const util = require('util');
const crypto = require('crypto');
const base32 = require('hi-base32');
const prettyBytes = require('pretty-bytes');

const randomBytes = (() => {
  switch (os.platform()) {
    case 'linux':
    case 'darwin': {
      const fd = fs.openSync('/dev/urandom');
      return {
        sync: (length) => {
          const buffer = Buffer.allocUnsafe(length);
          fs.readSync(fd, buffer, 0, length, 0);
          return buffer;
        },
        async: (length) => new Promise((resolve, reject) => {
          const buffer = Buffer.allocUnsafe(length);
          fs.read(fd, buffer, 0, length, 0, (err) => {
            if (err !== null) {
              reject(err);
              return;
            }
            resolve(buffer);
          });
        }),
        close: () => fs.closeSync(fd),
      };
    }
    default: {
      return {
        sync: crypto.randomBytes,
        async: util.promisify(crypto.randomBytes),
      };
    }
  }
})();

const hotpAlgos = [
  'sha1',
  'sha224',
  'sha256',
  'sha3-224',
  'sha3-256',
  'sha3-384',
  'sha3-512',
  'sha384',
  'sha512',
  'sha512-224',
  'sha512-256',
];

const prettyError = (methodName, callStack, wrappedError, parameters) => {
  if (wrappedError.prettyErrored !== true) {
    if (typeof methodName !== 'string' || methodName === '') {
      throw Error('prettyError :: Invalid "methodName" value.');
    }
    if (callStack !== undefined && (typeof callStack !== 'string' || callStack === '')) {
      throw Error('prettyError :: Invalid "callStack" value.');
    }
    if (wrappedError instanceof Error === false) {
      throw Error('prettyError :: Invalid "wrappedError" value.');
    }
    if (parameters !== undefined && (typeof parameters !== 'object' || parameters === null)) {
      throw Error('prettyError :: Invalid "parameters" value.');
    }
    wrappedError.prettyErrored = true; // eslint-disable-line no-param-reassign
    console.error();
    console.error('<-- ERROR -->');
    console.error(`${wrappedError.name}: ${wrappedError.message}`);
    console.error(wrappedError.stack.split('\n').slice(1, 4).join('\n'));
    console.error();
    console.error('<-- CALL STACK -->');
  }
  console.error(callStack ? `${callStack}->${methodName}` : `${methodName}`, JSON.stringify(parameters, null, 2));
};

const hotpCode = (algo, key, isBase32Key, counter, callStack) => {
  try {
    if (hotpAlgos.includes(algo) === false) {
      throw Error('Invalid "algo" value.');
    }
    if (typeof key !== 'string' || key === '') {
      throw Error('Invalid "key" value.');
    }
    if (typeof isBase32Key !== 'boolean') {
      throw Error('Invalid "isBase32Key" value.');
    }
    if (counter !== undefined && (typeof counter !== 'number' || Number.isNaN(counter) === true || Number.isFinite(counter) === false || Math.floor(counter) !== counter || counter <= 0)) {
      throw Error('Invalid "counter" value.');
    }

    const keyBuffer = isBase32Key ? Buffer.from(base32.decode.asBytes(key)) : Buffer.from(key);

    // message := floor(current Unix time / 30)
    const messageBuffer = Buffer.alloc(8).fill(0);
    messageBuffer.writeUInt32BE(counter, 4);

    // hash := HMAC-SHA1(k, message)
    const hashBuffer = crypto.createHmac(algo, keyBuffer).update(messageBuffer).digest();

    // offset := last nibble of hash
    const offset = hashBuffer[hashBuffer.byteLength - 1] & 0xf;

    // truncatedHash := hash[offset..offset+3]  //4 bytes starting at the offset
    const truncatedHashBuffer = hashBuffer.slice(offset, offset + 4);

    // Set the first bit of truncatedHash to zero  //remove the most significant bit
    truncatedHashBuffer[0] &= 0x7f;

    // code := truncatedHash mod 1000000
    // pad code with 0 from the left until length of code is 6
    const code = String(truncatedHashBuffer.readUInt32BE() % 1000000).padStart(6, '0');

    return code;
  } catch (e) {
    prettyError('hotpCode', callStack, e, {
      algo,
      key,
      isBase32Key,
      counter,
    });
    throw e;
  }
};

const totpCode = (algo, key, isBase32Key, timeCounter, callStack) => {
  try {
    return hotpCode(algo, key, isBase32Key, timeCounter, 'totpCode');
  } catch (e) {
    prettyError('totpCode', callStack, e, {
      algo,
      key,
      isBase32Key,
      timeCounter,
    });
    throw e;
  }
};

const totpVerify = (algo, key, isBase32Key, code, tolerance, callStack) => {
  try {
    if (typeof code !== 'string' || code === '') {
      throw Error('Invalid "code" value.');
    }
    if (tolerance !== undefined && (typeof tolerance !== 'number' || Number.isNaN(tolerance) === true || Number.isFinite(tolerance) === false || Math.floor(tolerance) !== tolerance || tolerance <= 0)) {
      throw Error('Invalid "tolerance" value.');
    }

    // get our current 30-second window
    const timeCounter = Math.floor(Math.round(Date.now() / 1000) / 30);

    // iterate backwards on the amount of previous
    // 30-second windows we are wiling to accept
    for (let i = 0; i <= (tolerance || 1); i += 1) {
      if (totpCode(algo, key, isBase32Key, timeCounter - (i * 30), 'totpVerify') === code) {
        return true;
      }
    }

    return false;
  } catch (e) {
    prettyError('totpVerify', callStack, e, {
      algo,
      key,
      isBase32Key,
      code,
      tolerance,
    });
    throw e;
  }
};

const hotpKey = () => base32.encode(crypto.randomBytes(16)).replace(/=/g, '');

const scryptKey = (() => {
  const derivedKeyLength = 64;
  const options = {
    N: (2 ** 15),
    r: 8,
    p: 1,
    maxmem: 128 * (2 ** 16) * 8,
  };
  const scryptKeyFn = (password, salt) => new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, derivedKeyLength, options, (err, derivedKey) => {
      if (err !== null) {
        reject(err);
        return;
      }
      resolve(derivedKey);
    });
  });
  scryptKeyFn.estimatedUsage = 128 * options.N * options.r;
  scryptKeyFn.estimatedUsagePretty = prettyBytes(128 * options.N * options.r);
  return scryptKeyFn;
})();

const scryptSalt = () => crypto.randomBytes(32);

module.exports = {
  randomBytes,
  hotpCode,
  totpCode,
  totpVerify,
  hotpKey,
  scryptKey,
  scryptSalt,
};


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
