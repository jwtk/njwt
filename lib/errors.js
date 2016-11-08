'use strict';

var util = require('util');

function JwtError(message) {
  this.name = 'JwtError';
  this.message = this.userMessage = message;
}
util.inherits(JwtError, Error);

function JwtParseError(jwtString, parsedHeader, parsedBody, innerError) {
  this.name = 'JwtParseError';
  this.message = this.userMessage = 'Jwt cannot be parsed';
  this.jwtString = jwtString;
  this.parsedHeader = parsedHeader;
  this.parsedBody = parsedBody;
  this.innerError = innerError;
}
util.inherits(JwtParseError, JwtError);

function UnsupportedSigningAlgorithmJwtError() {
  UnsupportedSigningAlgorithmJwtError.super_.call(this, 'Unsupported signing algorithm');
  this.name = 'UnsupportedSigningAlgorithmJwtError';
}
util.inherits(UnsupportedSigningAlgorithmJwtError, JwtError);

function SigningKeyRequiredJwtError() {
  SigningKeyRequiredJwtError.super_.call(this, 'Signing key is required');
  this.name = 'SigningKeyRequiredJwtError';
}
util.inherits(SigningKeyRequiredJwtError, JwtError);

function NotActiveJwtParseError(jwtString, parsedHeader, parsedBody) {
  NotActiveJwtParseError.super_.call(this, jwtString, parsedHeader, parsedBody);
  this.name = 'NotActiveJwtParseError';
  this.message = this.userMessage = 'Jwt not active';
}
util.inherits(NotActiveJwtParseError, JwtParseError);

function ExpiredJwtParseError(jwtString, parsedHeader, parsedBody) {
  ExpiredJwtParseError.super_.call(this, jwtString, parsedHeader, parsedBody);
  this.name = 'ExpiredJwtParseError';
  this.message = this.userMessage = 'Jwt is expired';
}
util.inherits(ExpiredJwtParseError, JwtParseError);

function SignatureAlgorithmMismatchJwtParseError(jwtString, parsedHeader, parsedBody) {
  SignatureAlgorithmMismatchJwtParseError.super_.call(this, jwtString, parsedHeader, parsedBody);
  this.name = 'SignatureAlgorithmMismatchJwtParseError';
  this.message = this.userMessage = 'Unexpected signature algorithm';
}
util.inherits(SignatureAlgorithmMismatchJwtParseError, JwtParseError);

function SignatureMismatchJwtParseError(jwtString, parsedHeader, parsedBody, innerError) {
  SignatureMismatchJwtParseError.super_.call(this, jwtString, parsedHeader, parsedBody, innerError);
  this.name = 'SignatureMismatchJwtParseError';
  this.message = this.userMessage = 'Signature verification failed';
}
util.inherits(SignatureMismatchJwtParseError, JwtParseError);

module.exports = {
  JwtError: JwtError,
  JwtParseError: JwtParseError,
  UnsupportedSigningAlgorithmJwtError: UnsupportedSigningAlgorithmJwtError,
  SigningKeyRequiredJwtError: SigningKeyRequiredJwtError,
  NotActiveJwtParseError: NotActiveJwtParseError,
  ExpiredJwtParseError: ExpiredJwtParseError,
  SignatureAlgorithmMismatchJwtParseError: SignatureAlgorithmMismatchJwtParseError,
  SignatureMismatchJwtParseError: SignatureMismatchJwtParseError
};