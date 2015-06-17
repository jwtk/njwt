'use strict';

var crypto = require('crypto');
var util = require('util');
var properties = require('./properties.json');
var uuid = require('uuid');

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

function nowEpochSeconds(){
  return Math.floor(new Date().getTime()/1000);
}

function base64urlEncode(str) {
  return new Buffer(str)
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

function JwtError(data) {
  this.name = 'JwtError';
  this.userMessage = typeof data === 'string' ? data : (data || {}).userMessage;
  this.message = this.userMessage;
}
util.inherits(JwtError, Error);

module.exports = JwtError;

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
  this.typ = header && header.typ || 'JWT';
  this.alg = header && header.alg || 'HS256';
}
JwtHeader.prototype.compact = function compact(){
  return base64urlEncode(JSON.stringify(this));
};

function Jwt(claims){

  if(!(this instanceof Jwt)){
    return new Jwt(claims);
  }
  this.header = new JwtHeader();
  this.setSigningAlgorithm('none');
  this.body = new JwtBody(claims);
  this.setJti(uuid.v4());
  this.setIssuedAt(nowEpochSeconds());
  return this;
}
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
  this.body.exp = Math.floor((exp instanceof Date ? exp : new Date(exp)).getTime() / 1000);
  return this;
};
Jwt.prototype.setTtl = function setTtl(ttlSeconds) {
  this.ttl = ttlSeconds;
  this.body.exp = nowEpochSeconds() + this.ttl;
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

Jwt.prototype.sign = function sign(payload, alg, cyrptoInput) {
  var buffer;

  var cryptoAlgName = algCryptoMap[alg];
  var signingType = algTypeMap[alg];

  if(signingType === 'hmac') {
    buffer = crypto.createHmac(cryptoAlgName, cyrptoInput).update(payload).digest();
  }
  else if(signingType === 'sign') {
    buffer = crypto.createSign(cryptoAlgName).update(payload).sign(cyrptoInput);
  }

  return base64urlEncode(buffer);
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


Jwt.prototype.isValid = function() {
  var self = this;
  return Object.keys(self).reduce(function(acc,key){
    acc[key] = self[key];
    return acc;
  },{});
};

Jwt.prototype.isExpired = function() {
  return new Date(this.body.exp*1000) < new Date();
};

Jwt.prototype.getBody = function getBody() {
  return this.body;
};


function Parser(options){
  if(!(this instanceof Parser)){
    return new Parser(options);
  }
  this.setSigningAlgorithm('none');
  return this;
}
Parser.prototype.setSigningAlgorithm = function setSigningAlgorithm(alg) {
  if(!this.isSupportedAlg(alg)){
    throw new JwtError(properties.errors.UNSUPPORTED_SIGNING_ALG);
  }
  this.signingAlgorithm = alg;
  return this;
};
Parser.prototype.setSigningKey = function setSigningKey(keyStr) {
  this.signingKey = keyStr;
  return this;
};
Parser.prototype.isSupportedAlg = isSupportedAlg;
Parser.prototype.safeJsonParse = function(input) {
  var result;
  try{
    result = JSON.parse(new Buffer(base64urlUnescape(input),'base64'));
  }catch(e){
    return e;
  }
  return result;
};
Parser.prototype.parse = function parse(jwtString){
  var segments = jwtString.split('.');
  var signature;
  if(segments.length<2 || segments.length>3){
    throw new JwtError(properties.errors.PARSE_ERROR);
  }

  var header = new JwtHeader(this.safeJsonParse(segments[0]));
  var body = new JwtBody(this.safeJsonParse(segments[1]));

  if(segments[2]){
    signature = new Buffer(base64urlUnescape(segments[2]),'base64')
      .toString('base64');
  }

  if(header instanceof Error){
    throw new JwtError(properties.errors.PARSE_ERROR);
  }
  if(body instanceof Error){
    throw new JwtError(properties.errors.PARSE_ERROR);
  }
  var jwt = new Jwt(body);
  jwt.setSigningAlgorithm(header.alg);
  jwt.signature = signature;
  jwt.verificationInput = segments[0] +'.' + segments[1];
  return jwt;
};

function Verifier(){
  if(!(this instanceof Verifier)){
    return new Verifier();
  }
  this.setSigningAlgorithm('HS256');
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
Verifier.prototype.isSupportedAlg = isSupportedAlg;

Verifier.prototype.handleError = function(cb,err){
  if(typeof cb==='function'){
    return process.nextTick(function() {
      cb(err);
    });
  }else{
    throw err;
  }
};

Verifier.prototype.verify = function verify(jwtString,cb){

  var jwt;

  var done = this.handleError.bind(cb);

  try{
    jwt = new Parser().parse(jwtString);
  }catch(e){
    return done(cb,e);
  }

  var body = jwt.body;
  var header = jwt.header;
  var signature = jwt.signature;

  var signingMethod = algCryptoMap[header.alg];
  var signingType = algTypeMap[header.alg];

  if(header.alg!==this.signingAlgorithm){
    return done(cb,new JwtError(properties.errors.SIGNATURE_ALGORITHM_MISMTACH));
  }

  if(!signingMethod){
    return done(cb,new JwtError(properties.errors.UNSUPPORTED_SIGNING_ALG));
  }

  if(jwt.isExpired()){
    return done(cb,new JwtError(properties.errors.EXPIRED));
  }

  // TODO add nbf checking

  var digstInput = jwt.verificationInput;

  var verified, digest;

  if(signingType === 'hmac') {
    digest = crypto.createHmac(signingMethod, this.signingKey)
      .update(digstInput)
      .digest('base64');
    verified = ( signature === digest );
  }
  else if(signingType === 'sign') {
    verified = crypto.createVerify(signingMethod)
      .update(digstInput)
      .verify(this.signingKey, base64urlUnescape(signature), 'base64');
  }else if(signingMethod==='none'){
    verified = true;
  }

  var newJwt = new Jwt(body);

  if ( verified ) {
    return cb ? cb(null,newJwt) : newJwt;
  }else{
    return cb(new JwtError(properties.errors.SIGNATURE_MISMTACH));
  }
};
Verifier.prototype.setAssertions = function setAssertions(){
  // todo
  return this;
};

var jwtLib = {
  Jwt: Jwt,
  Parser: Parser,
  Verifier: Verifier,
  base64urlEncode: base64urlEncode,
  base64urlUnescape:base64urlUnescape,
  verify: function(jwtString,secret,alg,cb){
    var args = Array.prototype.slice.call(arguments);
    var verifier = new Verifier();
    if(args.length>2){
      verifier.setSigningKey(secret);
    }
    if(args.length>3){
      verifier.setSigningAlgorithm(alg);
    }
    cb = args.pop();
    return verifier.verify(jwtString,cb);
  },
  create: function(claims,secret,alg){
    var args = Array.prototype.slice.call(arguments);
    var jwt = new Jwt(claims);
    jwt.setSigningAlgorithm(args.length===3 ? alg : 'HS256');

    if(jwt.header.alg!=='none' && !secret){
      throw new Error(properties.errors.SIGNING_KEY_REQUIRED);
    }
    if(args.length>1){
      jwt.setSigningKey(secret);
    }

    return jwt;
  }
};
module.exports = jwtLib;