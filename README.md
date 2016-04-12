# nJwt - JWTs for Node.js

"Nin-Jot" /ˈnɪn.dʒɑt/

[![NPM Version](https://img.shields.io/npm/v/njwt.svg?style=flat)](https://npmjs.org/package/njwt)
[![NPM Downloads](http://img.shields.io/npm/dm/njwt.svg?style=flat)](https://npmjs.org/package/njwt)
[![Build Status](https://img.shields.io/travis/jwtk/njwt.svg?style=flat)](https://travis-ci.org/jwtk/njwt)
[![Coverage Status](https://coveralls.io/repos/jwtk/njwt/badge.svg?branch=master)](https://coveralls.io/r/jwtk/njwt?branch=master)

nJwt is the cleanest JSON Web Token (JWT) library for Node.js developers. nJwt
removes all the complexities around JWTs, and gives you a simple, intuitive API,
that allows you to securely make and use JWTs in your applications without
needing to read [rfc7519](http://www.rfc-editor.org/rfc/rfc7519.txt).

### Creating Secure, Signed JWTs

JWTs expect *"claims"*, they a set of assertions about who the user is and what
they can do.  The most common use case for JWTs is to declare the "scope" of the
access token, which is a list of things that the holder of the token (the user)
is allowed to do.

JWTs should be signed, otherwise you can't verify that they were created by you.
Our library expects that you give us a highly random signing key for
signing tokens.  We use the `HS256` algorithm by default.

While the claims are completely up to you, we do recommend setting the "Subject"
and "Audience" fields.

JWTs commonly contain the `iat` and `exp` claims, which declare the time the
token was issued and when it expires.  Our library will create these for you,
with a default expiration of 1 hour.

````javascript
var uuid = require('uuid');
var nJwt = require('njwt');
var signingKey = uuid.v4(); // For example purposes

var claims = {
  iss: "http://myapp.com/",  // The URL of your service
  sub: "users/user1234",    // The UID of the user in your system
  scope: "self, admins"
}

var jwt = nJwt.create(claims,signingKey)
````

Once you have creted the JWT, you can look at it's internal structure by
logging it to the console.  This is our internal representation of the token,
this is not what you'll send to your end user:
````javascript
console.log(jwt);
````
````json
{
  "header": {
    "typ": "JWT",
    "alg": "HS256"
  },
  "body": {
    "jti": "c84280e6-0021-4e69-ad76-7a3fdd3d4ede",
    "iat": 1434660338,
    "exp": 1434663938,
    "iss": "http://myapp.com/",
    "sub": "users/user1234",
    "scope": ["self","admins"]
  }
}
````
Our library has added the `jti` field for you, this is a random ID that will be
unique for every token.  You can use this if you want to create a database of
tokens that have been issued to the user.

When you are ready to give the token to your end user, you need to compact it.
This will turn it into a Base64 URL encoded string, so it'l be safe to pass
around in browsers without getting any strange formatting applied to it.
````javascript
var token = jwt.compact();
console.log(token);
````
````
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MzQ0Nzk4ODN9.HQyx15jWm1upqsrKSf89X_iP0sg7N46a9pqBVGPMYdiqZeuU_ZZOdU-zizHJoIHMIJxtEWzpSMaVubJW0AJsTqjqQf6GoJ4cmFAfmfUFXmMC4Xv5oc4UqvGizpoLjfZedd834PcwbS-WskZcL4pVNmBIGRtDXkoU1j2X1P5M_sNJ9lYZ5vITyqe4MYJovQzNdQziUNhcMI5wkXncV7XzGInBeQsPquASWVG4gb3Y--k1P3xWA4Df3rKeEQBbInDKXczvDpfIlTojx4Ch8OM8vXWWNxW-mIQrV31wRrS9XtNoig7irx8N0MzokiYKrQ8WP_ezPicHvVPIHhz-InOw
````

### Verifying Signed JWTs

The end user will use their JWT to authenticate themselves with your service.
When they present the JWT, you want to check the token to ensure that it's valid.
This library does the following checks when you call the `verify` method:

* It was created by you (by verifying the signature, using the secret signing key)
* It is hasn't been modified (e.g. some claims were maliciously added)
* It hasn't expired

To verify a previously issued token, use the `verify` method.  You must give it
the same signing key that you are using to create tokens:
````javascript
nJwt.verify(token,signingKey,function(err,verifiedJwt){
  if(err){
    console.log(err); // Token has expired, has been tampered with, etc
  }else{
    console.log(verifiedJwt); // Will contain the header and body
  }
});
````

If validation fails you can look at `err.message` to understand the problem.  If
the header and body of the JWT were parse-able (not not verifiable) they will
be provided as objects at `err.parsedHeader` and `err.parsedBody`.

You can also use verify synchronously, in which case the errors will be thrown:

````javascript
try{
  verifiedJwt = nJwt.verify(token,signingKey);
}catch(e){
  console.log(e);
}
````

### Changing the algorithm

If you want to change the algorithm from the default `HS256`, you can do so
by passing it as a third argument to the `create` or `verify` methods:

````javascript
var jwt = nJwt.create(claims,signingKey,'HS512');
````
````javascript
nJwt.verify(token,signingKey, 'HS512');
````

See the table below for a list of supported algorithms.  If using RSA key pairs,
the public key will be the signing key parameter.

### Customizing the token

While we've chosen secure, sensible defaults for you, you may need to change it
up.

#### Claims

If you need to provide custom claims, simply supply them to the `create` method
or add them manually to the claims body after JWT is created.  These two
examples create the same claims body:

```javascript
var claims = {
  scope: 'admins'
}
var jwt = nJwt.create(claims,secret);
````
```javascript
var jwt = nJwt.create({},secret);
jwt.body.scope = 'admins';
````

#### Expiration Claim

A convenience method is supplied for modifying the `exp` claim.  You can modify
the `exp` claim by passing a `Date` object, or a millisecond value, to the
`setExpiration` method:

```javascript
var jwt = nJwt.create(claims,secret);

jwt.setExpiration(new Date('2015-07-01')); // A specific date
jwt.setExpiration(new Date().getTime() + (60*60*1000)); // One hour from now
jwt.setExpiration(); // Remove the exp claim
```


## Supported Algorithms

"alg" Value | Algorithm used
------------|----------------------------
HS256 | HMAC using SHA-256 hash algorithm
HS384 | HMAC using SHA-384 hash algorithm
HS512 | HMAC using SHA-512 hash algorithm
RS256 | RSASSA using SHA-256 hash algorithm
RS384 | RSASSA using SHA-384 hash algorithm
RS512 | RSASSA using SHA-512 hash algorithm
ES256 | ECDSA using P-256 curve and SHA-256 hash algorithm
ES384 | ECDSA using P-384 curve and SHA-384 hash algorithm
ES512 | ECDSA using P-521 curve and SHA-512 hash algorithm
none | No digital signature or MAC value included

## Unsupported features

The following features are not yet supported by this library:

* Encrypting the JWT (aka JWE)
* Signing key resolver (using the `kid` field)
