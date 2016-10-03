'use strict';

var crypto = require('crypto');
var ecdsaSigFormatter = require('ecdsa-sig-formatter');
var enums = require('./enums');
var errors = require('./errors');
var helpers = require('./helpers');
var Parser = require('./parser');
var Jwt = require('./jwt');
var JwtHeader = require('./jwt-header');

function Verifier() {
  this.setSigningAlgorithm('HS256');
}

Verifier.prototype.setSigningAlgorithm = function setSigningAlgorithm(alg) {
  if (!helpers.isSupportedAlg(alg)) {
    throw new errors.UnsupportedSigningAlgorithmJwtError();
  }

  this.signingAlgorithm = alg;

  return this;
};

Verifier.prototype.setSigningKey = function setSigningKey(keyStr) {
  this.signingKey = keyStr;
  return this;
};

Verifier.prototype.isSupportedAlg = helpers.isSupportedAlg;

Verifier.prototype.verify = function verify(jwtString, cb) {
  var jwt;
  var done = helpers.handleError.bind(null, cb);

  try {
    jwt = new Parser().parse(jwtString);
  } catch (e) {
    return done(e);
  }

  var body = jwt.body;
  var header = jwt.header;
  var signature = jwt.signature;

  var cryptoAlgName = enums.algCryptoMap[header.alg];
  var signingType = enums.algTypeMap[header.alg];

  if (header.alg !== this.signingAlgorithm) {
    return done(new errors.SignatureAlgorithmMismatchJwtParseError(jwtString, header, body));
  }

  if (jwt.isExpired()) {
    return done(new errors.ExpiredJwtParseError(jwtString, header, body));
  }

  if (jwt.isNotBefore()) {
    return done(new errors.NotActiveJwtParseError(jwtString, header, body));
  }

  var digstInput = jwt.verificationInput;
  var verified, digest;

  if (cryptoAlgName === 'none') {
    verified = true;
  } else if (signingType === 'hmac') {
    digest = crypto.createHmac(cryptoAlgName, this.signingKey)
      .update(digstInput)
      .digest('base64');
    verified = signature === digest;
  } else {
    var unescapedSignature;
    var signatureType = undefined;

    if (helpers.isECDSA(header.alg)) {
      try {
        unescapedSignature = ecdsaSigFormatter.joseToDer(signature, header.alg);
      } catch (err) {
        return done(new errors.SignatureMismatchJwtParseError(jwtString, header, body, err));
      }
    } else {
      signatureType = 'base64';
      unescapedSignature = helpers.base64urlUnescape(signature);
    }

    verified = crypto.createVerify(cryptoAlgName)
      .update(digstInput)
      .verify(this.signingKey, unescapedSignature, signatureType);
  }

  var newJwt = new Jwt(body, false);

  newJwt.toString = function () {
    return jwtString;
  };

  newJwt.header = new JwtHeader(header);

  if (!verified) {
    return done(new errors.SignatureMismatchJwtParseError(jwtString, header, body));
  }

  return done(null, newJwt);
};

module.exports = Verifier;