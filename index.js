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

function JwtError(message) {
  this.name = 'JwtError';
  this.message = this.userMessage = message;
}
util.inherits(JwtError, Error);

function JwtParseError(message,jwtString,parsedHeader,parsedBody) {
  this.name = 'JwtParseError';
  this.message = this.userMessage = message;
  this.jwtString = jwtString;
  this.parsedHeader = parsedHeader;
  this.parsedBody = parsedBody;
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

function Jwt(claims){

  if(!(this instanceof Jwt)){
    return new Jwt(claims);
  }
  this.header = new JwtHeader();
  this.setSigningAlgorithm('none');
  this.body = new JwtBody(claims);
  if (!this.body.jti) {
    this.setJti(uuid.v4());
  }
  if (!this.body.iat) {
    this.setIssuedAt(nowEpochSeconds());
  }
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
  if(exp){
    this.body.exp = Math.floor((exp instanceof Date ? exp : new Date(exp)).getTime() / 1000);
  }else{
    delete this.body.exp;
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

Jwt.prototype.sign = function sign(payload, alg, cyrptoInput) {
  var buffer;

  var cryptoAlgName = algCryptoMap[alg];
  var signingType = algTypeMap[alg];

  if(cryptoAlgName){
    if(signingType === 'hmac') {
      buffer = crypto.createHmac(cryptoAlgName, cyrptoInput).update(payload).digest();
    }
    else{
      buffer = crypto.createSign(cryptoAlgName).update(payload).sign(cyrptoInput);
    }
  }else{
    throw new JwtError(properties.errors.UNSUPPORTED_SIGNING_ALG);
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

Jwt.prototype.toString = function(){
  return this.compact();
};

Jwt.prototype.isExpired = function() {
  return new Date(this.body.exp*1000) < new Date();
};


function Parser(options){
  return this;
}

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
    signature = new Buffer(base64urlUnescape(segments[2]),'base64')
      .toString('base64');
  }

  if(header instanceof Error){
    return done(new JwtParseError(properties.errors.PARSE_ERROR,jwtString,null,null));
  }
  if(body instanceof Error){
    return done(new JwtParseError(properties.errors.PARSE_ERROR,jwtString,header,null));
  }
  var jwt = new Jwt(body);
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

Verifier.prototype.verify = function verify(jwtString,cb){

  var jwt;

  var done = handleError.bind(null,cb);

  try{
    jwt = new Parser().parse(jwtString);
  }catch(e){
    return done(e);
  }

  var body = jwt.body;
  var header = jwt.header;
  var signature = jwt.signature;

  var cryptoAlgName = algCryptoMap[header.alg];
  var signingType = algTypeMap[header.alg];

  if(header.alg!==this.signingAlgorithm){
    return done(new JwtParseError(properties.errors.SIGNATURE_ALGORITHM_MISMTACH,jwtString,header,body));
  }

  if(jwt.isExpired()){
    return done(new JwtParseError(properties.errors.EXPIRED,jwtString,header,body));
  }


  var digstInput = jwt.verificationInput;

  var verified, digest;

  if(cryptoAlgName==='none'){
    verified = true;
  }
  else if(signingType === 'hmac') {
    digest = crypto.createHmac(cryptoAlgName, this.signingKey)
      .update(digstInput)
      .digest('base64');
    verified = ( signature === digest );
  }
  else{
    verified = crypto.createVerify(cryptoAlgName)
      .update(digstInput)
      .verify(this.signingKey, base64urlUnescape(signature), 'base64');
  }


  var newJwt = new Jwt(body);

  newJwt.toString = function(){ return jwtString;};

  newJwt.header = new JwtHeader(header);

  if ( verified ) {
    return done(null,newJwt);
  }else{
    return done(new JwtParseError(properties.errors.SIGNATURE_MISMTACH,jwtString,header,body));
  }
};

var jwtLib = {
  Jwt: Jwt,
  JwtBody: JwtBody,
  JwtHeader: JwtHeader,
  Verifier: Verifier,
  base64urlEncode: base64urlEncode,
  base64urlUnescape:base64urlUnescape,
  verify: function(jwtString,secret,alg,cb){
    var args = Array.prototype.slice.call(arguments);

    if(typeof args[args.length-1]==='function'){
      cb = args.pop();
    }else{
      cb = null;
    }

    var verifier = new Verifier();

    if(args.length===3){
      verifier.setSigningAlgorithm(alg);
    }else{
      verifier.setSigningAlgorithm('HS256');
    }

    if(args.length===1){
      verifier.setSigningAlgorithm('none');
    }else{
      verifier.setSigningKey(secret);
    }

    return verifier.verify(jwtString,cb);
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