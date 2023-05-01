# nJwt Change Log

### 3.0.0

* [#102](https://github.com/jwtk/njwt/pull/102) Breaking changes:
  - Changes `setIssuedAt` method signature to accept Date or milliseconds as input to be consistent with `setExpiration` and `setNotBefore`
  - Excludes `test` folder from the release package


### 2.0.0

* [#98](https://github.com/jwtk/njwt/pull/98) Bumps jsonwebtoken version, drop Node < 12 from engines

### 1.2.0

* [#84](https://github.com/jwtk/njwt/pull/84) Resolves `uuid` vulnerability.

### 1.1.0

* [#77](https://github.com/jwtk/njwt/pull/77) Adds TypeScript type definitions.

### 1.0.0

* Removed support for older Node versions.  Now requires Node 6+.

### 0.4.1

* Updated `nJwt.base64urlEncode()` to replace deprecated `new Buffer()` with `Buffer.from()`

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
