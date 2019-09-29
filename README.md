## @davalapar/crypto

#### Base32-encoded key

- totpKey - returns a Base32-encoded 16-byte / 128-bit key
  - returns - String

```js
const { totpKey } = require('@davalapar/crypto');
const key = totpKey();
```

#### HMAC-based one-time password (HOTP)

- hotpCode - returns a code from algo, key, and counter
  - algo - String
  - key - String
  - isBase32Key - Boolean
  - counter - Integer
  - callStack - String, Optional
  - returns - String

```js
const { hotpCode, totpKey } = require('@davalapar/crypto');
const key = totpKey();
const code = hotpCode('sha1', key, true, 1);
```

#### Time-based one-time password (TOTP)

- totpCode - returns a code from algo, key, and timeCounter; where timeCounter is a counter value based on the thirty-second windows of the unix time
  - algo - String
  - key - String
  - isBase32Key - Boolean
  - timeCounter - Integer
  - callStack - String, Optional
  - returns - String
- totpVerify - returns a validation result of code from algo, key, code, and tolerance; where tolerance is the amount of previous windows to be also considered as valid
  - algo - String
  - key - String
  - isBase32Key - Boolean
  - code - String
  - tolerance - Integer, Optional
  - callStack - String, Optional
  - returns - Boolean

```js
const { totpCode, totpVerify, totpKey } = require('@davalapar/crypto');
const key = totpKey();
const timeCounter = Math.floor(Math.round(Date.now() / 1000) / 30);
const code = totpCode('sha1', key, true, timeCounter);
const isCodeValid = totpVerify('sha1', key, true, code);
```

#### Accepted algorithms for HOTP & TOTP

- sha1
- sha224
- sha256
- sha3-224
- sha3-256
- sha3-384
- sha3-512
- sha384
- sha512
- sha512-224
- sha512-256

#### Scrypt

- scryptKey - returns a derived key
  - password - String
  - salt - Buffer
  - returns - Promise, Buffer
- scryptSalt - returns a 32-byte / 256-bit salt
  - returns - Buffer

```js
const { scryptKey, scryptSalt } = require('./index');
const salt = scryptSalt();
const derivedKey = await scryptKey('password', salt);
console.log('salt:', salt.toString('hex'));
console.log('key:', derivedKey.toString('hex'));
```

#### References

- All
  - https://nodejs.org/api/crypto.html
  - https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html
- HOTP, TOTP
  - https://en.wikipedia.org/wiki/Google_Authenticator
  - https://en.wikipedia.org/wiki/HMAC-based_One-time_Password_algorithm
  - https://en.wikipedia.org/wiki/Time-based_One-time_Password_algorithm
  - https://pthree.org/2014/04/15/time-based-one-time-passwords-how-it-works/
  - https://github.com/guyht/notp/
- Scrypt
  - https://en.wikipedia.org/wiki/Scrypt
  - https://github.com/Tarsnap/scrypt/issues/19#issuecomment-154765518
  - https://blog.filippo.io/the-scrypt-parameters/

#### License

MIT | @davalapar
