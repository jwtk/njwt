'use strict';

var errors = require('./errors');
var helpers = require('./helpers');
var Jwt = require('./jwt');
var JwtHeader = require('./jwt-header');

function Parser() {
}

Parser.prototype.isSupportedAlg = helpers.isSupportedAlg;

Parser.prototype.parse = function parse(jwtString, cb) {
  var signature;
  var done = helpers.handleError.bind(null, cb);
  var segments = jwtString.split('.');

  if (segments.length < 2 || segments.length > 3) {
    return done(new errors.JwtParseError(jwtString));
  }

  var header = helpers.safeJsonParse(segments[0]);
  var body = helpers.safeJsonParse(segments[1]);

  if (segments[2]) {
    signature = new Buffer(helpers.base64urlUnescape(segments[2]), 'base64')
      .toString('base64');
  }

  if (header instanceof Error) {
    return done(new errors.JwtParseError(jwtString, null, null, header));
  }

  if (body instanceof Error) {
    return done(new errors.JwtParseError(jwtString, header, null, body));
  }

  var jwt = new Jwt(body, false);

  jwt.setSigningAlgorithm(header.alg);
  jwt.signature = signature;
  jwt.verificationInput = segments[0] + '.' + segments[1];
  jwt.header = new JwtHeader(header);

  return done(null, jwt);
};

module.exports = Parser;