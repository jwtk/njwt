'use strict';

var assert = require('chai').assert;
var nJwt = require('../');

describe('JwtBody', function () {
  it('should construct itself if called without new', function () {
    assert(nJwt.JwtBody() instanceof nJwt.JwtBody);
  });
});