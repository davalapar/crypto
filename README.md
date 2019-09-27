## @davalapar/crypto

```js
const { hotp, totp, totpValidate, totpCreateSecret } = require('@davalapar/crypto');

const secret = totpCreateSecret();

 // counter-based otp
const hotpCode = hotp('sha1', secret, 1);

// time-based otp
const windowCounter = Math.floor(Math.round(Date.now() / 1000) / 30);
const totpCode = totp('sha1', secret, windowCounter);
totpValidate('sha1', secret, totpCode);
```

Reference links:

- https://github.com/guyht/notp/
- https://en.wikipedia.org/wiki/Google_Authenticator
- https://pthree.org/2014/04/15/time-based-one-time-passwords-how-it-works/
