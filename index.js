'use strict';

var crypto = require('crypto');
var util = require('util');
var properties = require('./properties.json');
var uuid = require('uuid');

var algCryptoMap = {
  HS256: 'sha256',
  HS384: 'sha384',
  HS512: 'sha512',
  RS256: 'RSA-SHA256',
  none: 'none'
};

var algTypeMap = {
  HS256: 'hmac',
  HS384: 'hmac',
  HS512: 'hmac',
  RS256: 'sign'
};

function nowEpochSeconds(){
  return Math.round(new Date().getTime()/1000);
}
function base64urlEscape(str) {
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
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
  return new Buffer(JSON.stringify(this)).toString('base64');
};

function JwtHeader(header){
  this.typ = header && header.typ || 'JWT';
  this.alg = header && header.alg || 'HS256';
}
JwtHeader.prototype.compact = function compact(){
  return new Buffer(JSON.stringify(this)).toString('base64');
};

function Jwt(claims){

  if(!(this instanceof Jwt)){
    return new Jwt(claims);
  }
  this.header = new JwtHeader();
  this.setJti(uuid.v4());
  this.setSigningAlgorithm('none');
  this.body = new JwtBody(claims);
  this.body.iat = nowEpochSeconds();
  return this;
}
Jwt.prototype.setJti = function setJti(jti) {
  this.jti = jti;
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

Jwt.prototype.sign = function sign(payload, jwsHeader, cyrptoInput) {
  var base64str;
  var algorithm = jwsHeader.alg;
  var cryptoAlgName = algCryptoMap[algorithm];
  var signingType = algTypeMap[algorithm];

  if(signingType === 'hmac') {
    base64str = crypto.createHmac(cryptoAlgName, cyrptoInput).update(payload).digest('base64');
  }
  else if(signingType === 'sign') {
    base64str = crypto.createSign(cryptoAlgName).update(payload).sign(cyrptoInput, 'base64');
  }
  return base64urlEscape(base64str);
};

Jwt.prototype.isSupportedAlg = isSupportedAlg;

Jwt.prototype.compact = function compact() {

  var segments = [];
  segments.push(this.header.compact());
  segments.push(this.body.compact());

  if(this.header.alg !== 'none'){
    if (this.signingKey) {
      this.signature = this.sign(segments.join('.'), this.header, this.signingKey);
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
    result = JSON.parse(new Buffer(input,'base64'));
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
    signature = new Buffer(segments[2],'base64').toString('base64');
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
Verifier.prototype.safeJsonParse = function(input) {
  var result;
  try{
    result = JSON.parse(new Buffer(input,'base64'));
  }catch(e){
    return e;
  }
  return result;
};
Verifier.prototype.verify = function verify(jwtString,cb){

  var jwt;

  try{
    jwt = new Parser().parse(jwtString);
  }catch(e){
    return cb(e);
  }

  var body = jwt.body;
  var header = jwt.header;
  var signature = jwt.signature;

  var signingMethod = algCryptoMap[header.alg];
  var signingType = algTypeMap[header.alg];

  if(header.alg!==this.signingAlgorithm){
    return cb(new JwtError(properties.errors.SIGNATURE_ALGORITHM_MISMTACH));
  }

  if(!signingMethod){
    return cb(new JwtError(properties.errors.UNSUPPORTED_SIGNING_ALG));
  }

  if(jwt.isExpired()){
    return cb(new JwtError(properties.errors.EXPIRED));
  }

  // TODO add nbf checking

  var digstInput = [ header.compact(), body.compact()].join('.');

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

  if ( verified ) {
    cb(null,new Jwt(body));
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



  }
};
module.exports = jwtLib;