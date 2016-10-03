'use strict';

var helpers = require('./helpers');

function JwtHeader(header) {
  this.typ = header && header.typ || 'JWT';
  this.alg = header && header.alg || 'HS256';

  if (header) {
    var self = this;
    return Object.keys(header).reduce(function (acc, key) {
      if (self.reservedKeys.indexOf(key) === -1 && header.hasOwnProperty(key)) {
        acc[key] = header[key];
      }
      return acc;
    }, this);
  }
}

JwtHeader.prototype.reservedKeys = ['typ', 'alg'];

JwtHeader.prototype.compact = function compact() {
  return helpers.base64urlEncode(JSON.stringify(this));
};

module.exports = JwtHeader;