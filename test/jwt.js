'use strict';

var assert = require('chai').assert;
var nJwt = require('../');
var uuid = require('uuid');

describe('Jwt', function () {
  it('should construct itself if called without new', function () {
    assert(nJwt.Jwt() instanceof nJwt.Jwt);
  });

  describe('.setSubject()', function () {
    it('should set the sub claim', function () {
      var sub = uuid();
      assert.equal(new nJwt.Jwt().setSubject(sub).body.sub, sub);
    });
  });

  describe('.setIssuer()', function () {
    it('should set the iss claim', function () {
      var iss = uuid();
      assert.equal(new nJwt.Jwt().setIssuer(iss).body.iss, iss);
    });
  });

  describe('.setExpiration()', function () {
    it('should accept Date types and set the exp claim to a UNIX timestamp value', function () {
      var future = new Date('2025');
      assert.equal(
        new nJwt.Jwt().setExpiration(future).body.exp,
        future.getTime() / 1000
      );
    });

    it('should accept milliseconds values and set the exp claim to a UNIX timestamp value', function () {
      var future = new Date('2025').getTime();
      assert.equal(
        new nJwt.Jwt().setExpiration(future).body.exp,
        future / 1000
      );
    });

    it('should allow me to remove the exp field', function () {
      var jwt = nJwt.create({}, uuid());
      var oneHourFromNow = Math.floor(new Date().getTime() / 1000) + (60 * 60);
      assert.equal(nJwt.create({}, uuid()).body.exp, oneHourFromNow);
      assert.equal(jwt.setExpiration().body.exp, undefined);
      assert.equal(jwt.setExpiration(false).body.exp, undefined);
      assert.equal(jwt.setExpiration(null).body.exp, undefined);
      assert.equal(jwt.setExpiration(0).body.exp, undefined);
    });
  });

  describe('.setNotBefore()', function () {
    it('should accept Date types and set the nbf claim to a UNIX timestamp value', function () {
      var future = new Date('2025');
      assert.equal(
        new nJwt.Jwt().setNotBefore(future).body.nbf,
        future.getTime() / 1000
      );
    });

    it('should accept milliseconds values and set the nbf claim to a UNIX timestamp value', function () {
      var future = new Date('2025').getTime();
      assert.equal(
        new nJwt.Jwt().setNotBefore(future).body.nbf,
        future / 1000
      );
    });

    it('should allow me to remove the nbf field', function () {
      var jwt = nJwt.create({}, uuid());
      assert.equal(nJwt.create({}, uuid()).body.nbf, undefined);
      assert.equal(jwt.setNotBefore().body.nbf, undefined);
      assert.equal(jwt.setNotBefore(false).body.nbf, undefined);
      assert.equal(jwt.setNotBefore(null).body.nbf, undefined);
      assert.equal(jwt.setNotBefore(0).body.nbf, undefined);
    });
  });

  describe('.setSigningAlgorithm()', function () {
    it('should throw if you specify an alg but not a key', function () {
      assert.throws(function () {
        new nJwt.Jwt().setSigningAlgorithm('HS256').compact();
      }, nJwt.SigningKeyRequiredJwtError);
    });
  });

  describe('.sign()', function () {
    it('should throw if you give it an unknown algoritm', function () {
      assert.throws(function () {
        new nJwt.Jwt().sign('hello');
      }, nJwt.UnsupportedSigningAlgorithmJwtError);
    });
  });

  describe('.toString()', function () {
    it('should return the compacted JWT string', function () {
      var jwt = nJwt.create({}, uuid());
      assert.equal(jwt.compact(), jwt.toString());
    });
  });
});
