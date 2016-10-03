'use strict';

var helpers = require('./helpers');

function JwtBody(claims) {
  if (claims) {
    var self = this;
    Object.keys(claims).forEach(function (k) {
      self[k] = claims[k];
    });
  }
}

JwtBody.prototype.toJSON = function toJSON() {
  var self = this;
  return Object.keys(self).reduce(function (acc, key) {
    acc[key] = self[key];
    return acc;
  }, {});
};

JwtBody.prototype.compact = function compact() {
  return helpers.base64urlEncode(JSON.stringify(this));
};

module.exports = JwtBody;