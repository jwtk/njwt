# nJwt Change Log

### 0.4.0

* Added a key resolver interface, use `nJwt.createVerifier().withKeyResolver(function(kid, cb){ })`
* Added `jwt.setClaim(claim, value)` and `jwt.setHeader(param, value)` for setting body claims and header values in a chain-able way.

### 0.3.2

Added support for the `nbf`, "not before", claim.

### 0.3.1

Fixed to support proper signing and verification of ECDSA signatures.

### 0.3.0

The JWTs that are returned by `nJwt.verify()` and `nJwt.parse()` will no longer
populate the `iat` and `jti` fields with default random values.

### 0.2.3

Fixed to prevent the `jti` and `iat` claims of the passed token from being
over-written with default random values during verification.

### 0.2.2

`jwt.toString()` is now an alias for `jwt.compact()`.

### 0.2.1

When parsing a JWT string, the header values of the JWT are now populated on the
object that is returned.

### 0.2.0

The default `exp` field is now set to a default expiration of 1 hour.

### 0.1.0

First release.