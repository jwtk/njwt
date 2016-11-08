'use strict';

var assert = require('chai').assert;
var nJwt = require('../');

describe('JwtHeader', function () {
  it('should construct itself if called without new', function () {
    assert(nJwt.JwtHeader() instanceof nJwt.JwtHeader);
  });
});