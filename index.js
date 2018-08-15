'use strict';

var util = require('util');
var uuid = require('uuid');
var crypto = require('crypto');
var ecdsaSigFormatter = require('ecdsa-sig-formatter');
var properties = require('./properties.json');

var algCryptoMap = {
  HS256: 'SHA256',
  HS384: 'SHA384',
  HS512: 'SHA512',
  RS256: 'RSA-SHA256',
  RS384: 'RSA-SHA384',
  RS512: 'RSA-SHA512',
  ES256: 'RSA-SHA256',
  ES384: 'RSA-SHA384',
  ES512: 'RSA-SHA512',
  none: 'none'
};

var algTypeMap = {
  HS256: 'hmac',
  HS384: 'hmac',
  HS512: 'hmac',
  RS256: 'sign',
  RS384: 'sign',
  RS512: 'sign',
  ES256: 'sign',
  ES384: 'sign',
  ES512: 'sign'
};

function isECDSA(algorithm) {
  return algorithm.indexOf('ES') === 0;
}

function nowEpochSeconds(){
  return Math.floor(new Date().getTime()/1000);
}

function base64urlEncode(data) {
  const str = typeof data === 'number' ? data.toString() : data;
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function base64urlUnescape(str) {
  str += new Array(5 - str.length % 4).join('=');
  return str.replace(/\-/g, '+').replace(/_/g, '/');
}

function isSupportedAlg(alg){
  return !!algCryptoMap[alg];
}

function handleError(cb,err,value){
  if(typeof cb==='function'){
    return process.nextTick(function() {
      cb(err,value);
    });
  }else if(err){
    throw err;
  }else{
    return value;
  }
}

function defaultKeyResolver(kid, cb) {
  return cb(null, this.signingKey);
}

function JwtError(message) {
  this.name = 'JwtError';
  this.message = this.userMessage = message;
}
util.inherits(JwtError, Error);

function JwtParseError(message,jwtString,parsedHeader,parsedBody,innerError) {
  this.name = 'JwtParseError';
  this.message = this.userMessage = message;
  this.jwtString = jwtString;
  this.parsedHeader = parsedHeader;
  this.parsedBody = parsedBody;
  this.innerError = innerError;
}
util.inherits(JwtParseError, Error);

function JwtBody(claims){
  if(!(this instanceof JwtBody)){
    return new JwtBody(claims);
  }
  var self = this;
  if(claims){
    Object.keys(claims).forEach(function(k){
      self[k] = claims[k];
    });
  }
  return this;
}

JwtBody.prototype.toJSON = function() {
  var self = this;
  return Object.keys(self).reduce(function(acc,key){
    acc[key] = self[key];
    return acc;
  },{});
};
JwtBody.prototype.compact = function compact(){
  return base64urlEncode(JSON.stringify(this));
};

function JwtHeader(header){
  if(!(this instanceof JwtHeader)){
    return new JwtHeader(header);
  }
  var self = this;
  this.typ = header && header.typ || 'JWT';
  this.alg = header && header.alg || 'HS256';

  if(header){
    return Object.keys(header).reduce(function(acc,key){
      if(self.reservedKeys.indexOf(key)===-1 && header.hasOwnProperty(key)){
        acc[key] = header[key];
      }
      return acc;
    },this);
  }else{
    return this;
  }
}
JwtHeader.prototype.reservedKeys = ['typ','alg'];
JwtHeader.prototype.compact = function compact(){
  return base64urlEncode(JSON.stringify(this));
};

function Jwt(claims, enforceDefaultFields){
  if(!(this instanceof Jwt)){
    return new Jwt(claims, enforceDefaultFields);
  }

  this.header = new JwtHeader();
  this.body = new JwtBody(claims);

  if (enforceDefaultFields !== false) {
    this.setSigningAlgorithm('none');

    if (!this.body.jti) {
      this.setJti(uuid.v4());
    }

    if (!this.body.iat) {
      this.setIssuedAt(nowEpochSeconds());
    }
  }

  return this;
}
Jwt.prototype.setClaim = function setClaim(claim, value) {
  this.body[claim] = value;
  return this;
};
Jwt.prototype.setHeader = function setHeader(param, value) {
  this.header[param] = value;
  return this;
};
Jwt.prototype.setJti = function setJti(jti) {
  this.body.jti = jti;
  return this;
};
Jwt.prototype.setSubject = function setSubject(sub) {
  this.body.sub = sub;
  return this;
};
Jwt.prototype.setIssuer = function setIssuer(iss) {
  this.body.iss = iss;
  return this;
};
Jwt.prototype.setIssuedAt = function setIssuedAt(iat) {
  this.body.iat = iat;
  return this;
};
Jwt.prototype.setExpiration = function setExpiration(exp) {
  if(exp){
    this.body.exp = Math.floor((exp instanceof Date ? exp : new Date(exp)).getTime() / 1000);
  }else{
    delete this.body.exp;
  }

  return this;
};
Jwt.prototype.setNotBefore = function setNotBefore(nbf) {
  if(nbf) {
    this.body.nbf = Math.floor((nbf instanceof Date ? nbf : new Date(nbf)).getTime() / 1000);
  } else {
    delete this.body.nbf;
  }

  return this;
};
Jwt.prototype.setSigningKey = function setSigningKey(key) {
  this.signingKey = key;
  return this;
};
Jwt.prototype.setSigningAlgorithm = function setSigningAlgorithm(alg) {
  if(!this.isSupportedAlg(alg)){
    throw new JwtError(properties.errors.UNSUPPORTED_SIGNING_ALG);
  }
  this.header.alg = alg;
  return this;
};

Jwt.prototype.sign = function sign(payload, algorithm, cryptoInput) {
  var buffer;
  var signature;
  var cryptoAlgName = algCryptoMap[algorithm];
  var signingType = algTypeMap[algorithm];

  if (!cryptoAlgName) {
    throw new JwtError(properties.errors.UNSUPPORTED_SIGNING_ALG);
  }

  if (signingType === 'hmac') {
    buffer = crypto.createHmac(cryptoAlgName, cryptoInput).update(payload).digest();
  } else {
    buffer = crypto.createSign(cryptoAlgName).update(payload).sign(cryptoInput);
  }

  if (isECDSA(algorithm)) {
    signature = ecdsaSigFormatter.derToJose(buffer, algorithm);
  } else {
    signature = base64urlEncode(buffer);
  }

  return signature;
};

Jwt.prototype.isSupportedAlg = isSupportedAlg;

Jwt.prototype.compact = function compact() {

  var segments = [];
  segments.push(this.header.compact());
  segments.push(this.body.compact());

  if(this.header.alg !== 'none'){
    if (this.signingKey) {
      this.signature = this.sign(segments.join('.'), this.header.alg, this.signingKey);
      segments.push(this.signature);
    }else{
      throw new Error(properties.errors.SIGNING_KEY_REQUIRED);
    }
  }

  return segments.join('.');
};

Jwt.prototype.toString = function(){
  return this.compact();
};

Jwt.prototype.isExpired = function() {
  return new Date(this.body.exp*1000) < new Date();
};

Jwt.prototype.isNotBefore = function() {
  return new Date(this.body.nbf * 1000) >= new Date();
};

function Parser(options){
  return this;
}

Parser.prototype.isSupportedAlg = isSupportedAlg;
Parser.prototype.safeJsonParse = function(input) {
  var result;
  try{
    result = JSON.parse(Buffer.from(base64urlUnescape(input),'base64'));
  }catch(e){
    return e;
  }
  return result;
};
Parser.prototype.parse = function parse(jwtString,cb){

  var done = handleError.bind(null,cb);
  var segments = jwtString.split('.');
  var signature;

  if(segments.length<2 || segments.length>3){
    return done(new JwtParseError(properties.errors.PARSE_ERROR,jwtString,null,null));
  }

  var header = this.safeJsonParse(segments[0]);
  var body = this.safeJsonParse(segments[1]);

  if(segments[2]){
    signature = Buffer.from(base64urlUnescape(segments[2]),'base64')
      .toString('base64');
  }

  if(header instanceof Error){
    return done(new JwtParseError(properties.errors.PARSE_ERROR,jwtString,null,null,header));
  }
  if(body instanceof Error){
    return done(new JwtParseError(properties.errors.PARSE_ERROR,jwtString,header,null,body));
  }
  var jwt = new Jwt(body, false);
  jwt.setSigningAlgorithm(header.alg);
  jwt.signature = signature;
  jwt.verificationInput = segments[0] +'.' + segments[1];
  jwt.header = new JwtHeader(header);
  return done(null,jwt);
};

function Verifier(){
  if(!(this instanceof Verifier)){
    return new Verifier();
  }
  this.setSigningAlgorithm('HS256');
  this.setKeyResolver(defaultKeyResolver.bind(this));
  return this;
}
Verifier.prototype.setSigningAlgorithm = function setSigningAlgorithm(alg) {
  if(!this.isSupportedAlg(alg)){
    throw new JwtError(properties.errors.UNSUPPORTED_SIGNING_ALG);
  }
  this.signingAlgorithm = alg;
  return this;
};
Verifier.prototype.setSigningKey = function setSigningKey(keyStr) {
  this.signingKey = keyStr;
  return this;
};
Verifier.prototype.setKeyResolver = function setKeyResolver(keyResolver) {
  this.keyResolver = keyResolver.bind(this);
};
Verifier.prototype.isSupportedAlg = isSupportedAlg;

Verifier.prototype.verify = function verify(jwtString,cb){
  var jwt;

  var done = handleError.bind(null,cb);

  try {
    jwt = new Parser().parse(jwtString);
  } catch(e) {
    return done(e);
  }

  var body = jwt.body;
  var header = jwt.header;
  var signature = jwt.signature;

  var cryptoAlgName = algCryptoMap[header.alg];
  var signingType = algTypeMap[header.alg];

  if (header.alg !== this.signingAlgorithm) {
    return done(new JwtParseError(properties.errors.SIGNATURE_ALGORITHM_MISMTACH,jwtString,header,body));
  }

  if (jwt.isExpired()) {
    return done(new JwtParseError(properties.errors.EXPIRED,jwtString,header,body));
  }

  if (jwt.isNotBefore()) {
    return done(new JwtParseError(properties.errors.NOT_ACTIVE,jwtString,header,body));
  }

  var digstInput = jwt.verificationInput;
  var verified, digest;

  return this.keyResolver(header.kid, function(err, signingKey) {

    if (err) {
      return done(new JwtParseError(util.format(properties.errors.KEY_RESOLVER_ERROR, header.kid),jwtString,header,body, err));
    }


    if( cryptoAlgName==='none') {
      verified = true;
    } else if(signingType === 'hmac') {
      digest = crypto.createHmac(cryptoAlgName, signingKey)
        .update(digstInput)
        .digest('base64');
      verified = signature === digest;
    } else {
      var unescapedSignature;
      var signatureType = undefined;

      if (isECDSA(header.alg)) {
        try {
          unescapedSignature = ecdsaSigFormatter.joseToDer(signature, header.alg);
        } catch (err) {
          return done(new JwtParseError(properties.errors.SIGNATURE_MISMTACH,jwtString,header,body,err));
        }
      } else {
        signatureType = 'base64';
        unescapedSignature = base64urlUnescape(signature);
      }

      verified = crypto.createVerify(cryptoAlgName)
        .update(digstInput)
        .verify(signingKey, unescapedSignature, signatureType);
    }

    var newJwt = new Jwt(body, false);

    newJwt.toString = function () {
      return jwtString;
    };

    newJwt.header = new JwtHeader(header);

    if (!verified) {
      return done(new JwtParseError(properties.errors.SIGNATURE_MISMTACH,jwtString,header,body));
    }

    return done(null, newJwt);
  });
};

Verifier.prototype.withKeyResolver = function withKeyResolver(keyResolver) {
  this.keyResolver = keyResolver;
  return this;
};

var jwtLib = {
  Jwt: Jwt,
  JwtBody: JwtBody,
  JwtHeader: JwtHeader,
  Verifier: Verifier,
  base64urlEncode: base64urlEncode,
  base64urlUnescape:base64urlUnescape,
  verify: function(/*jwtTokenString, [signingKey], [algOverride], [callbck] */){

    var args = Array.prototype.slice.call(arguments);
    var cb = typeof args[args.length-1] === 'function' ? args.pop() : null;

    var verifier = new Verifier();

    if(args.length===3){
      verifier.setSigningAlgorithm(args[2]);
      verifier.setSigningKey(args[1]);
    }

    if(args.length===2){
      verifier.setSigningKey(args[1]);
    }

    if(args.length===1){
      verifier.setSigningAlgorithm('none');
    }

    return verifier.verify(args[0], cb);

  },
  createVerifier: function(){
    return new Verifier();
  },
  create: function(claims,secret,alg){
    var args = Array.prototype.slice.call(arguments);
    var jwt;
    if(args.length >= 2){
      jwt = new Jwt(claims);
    }else if (args.length===1 && typeof claims === 'string'){
      jwt = new Jwt({});
      secret = claims;
    }else{
      jwt = new Jwt(claims);
    }
    if(alg!=='none' && !secret){
      throw new Error(properties.errors.SIGNING_KEY_REQUIRED);
    }else{
      jwt.setSigningAlgorithm(args.length===3 ? alg : 'HS256');
      jwt.setSigningKey(secret);
    }
    jwt.setExpiration((nowEpochSeconds() + (60*60))*1000); // one hour
    return jwt;
  }
};

module.exports = jwtLib;
