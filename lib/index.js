'use strict';

var errors = require('./errors');
var helpers = require('./helpers');
var Jwt = require('./jwt');
var JwtBody = require('./jwt-body');
var JwtHeader = require('./jwt-header');
var Verifier = require('./verifier');

var exports = {};

exports.Jwt = Jwt;
exports.Verifier = Verifier;
exports.JwtBody = JwtBody;
exports.JwtHeader = JwtHeader;
exports.base64urlEncode = helpers.base64urlEncode;
exports.base64urlUnescape = helpers.base64urlUnescape;

exports.verify = function verify(jwtString, secret, alg, cb) {
  var args = Array.prototype.slice.call(arguments);

  if (typeof args[args.length - 1] === 'function') {
    cb = args.pop();
  } else {
    cb = null;
  }

  var verifier = new Verifier();

  if (args.length === 3) {
    verifier.setSigningAlgorithm(alg);
  } else {
    verifier.setSigningAlgorithm('HS256');
  }

  if (args.length === 1) {
    verifier.setSigningAlgorithm('none');
  } else {
    verifier.setSigningKey(secret);
  }

  return verifier.verify(jwtString, cb);
};

exports.create = function create(claims, secret, alg) {
  var jwt;
  var args = Array.prototype.slice.call(arguments);

  if (args.length >= 2) {
    jwt = new Jwt(claims);
  } else if (args.length === 1 && typeof claims === 'string') {
    jwt = new Jwt({});
    secret = claims;
  } else {
    jwt = new Jwt(claims);
  }

  if (alg !== 'none' && !secret) {
    throw new errors.SigningKeyRequiredJwtError();
  }

  jwt.setSigningAlgorithm(args.length === 3 ? alg : 'HS256');
  jwt.setSigningKey(secret);
  jwt.setExpiration((helpers.nowEpochSeconds() + (60 * 60)) * 1000); // one hour

  return jwt;
};

// Export all errors.
for (var key in errors) {
  exports[key] = errors[key];
}

module.exports = exports;