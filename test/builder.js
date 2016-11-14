'use strict';

var uuid = require('uuid');
var assert = require('chai').assert;
var nJwt = require('../');

describe('Jwt()', function () {
  describe('signWith()', function () {
    describe('if called with an unsupported algorithm', function () {
      it('should throw', function () {
        assert.throws(function () {
          new nJwt.Jwt().setSigningAlgorithm('unsupported');
        }, nJwt.UnsupportedSigningAlgorithmJwtError);
      });
    });
  });

});

describe('create()', function () {
  it('should throw UnsupportedSigningAlgorithmJwtError if passed no options', function () {
    assert.throws(function () {
      nJwt.create();
    }, nJwt.SigningKeyRequiredJwtError);
  });

  it('should create a default token if the scret is the only value', function () {
    assert(nJwt.create(uuid()) instanceof nJwt.Jwt);
  });

  it('should throw if using defaults without a secret key', function () {
    assert.throws(function () {
      nJwt.create({});
    }, nJwt.SigningKeyRequiredJwtError);
  });

  it('should not throw if none is specified when omitting the key', function () {
    assert.doesNotThrow(function () {
      nJwt.create({}, null, 'none');
    });
  });

  describe('with a signing key', function () {
    it('should return a JWT', function () {
      assert(nJwt.create({}, uuid()) instanceof nJwt.Jwt);
    });

    it('should use HS256 by default', function () {
      assert.equal(nJwt.create({}, uuid()).header.alg, 'HS256');
    });

    it('should create the iat field', function () {
      var nowUnix = Math.floor(new Date().getTime() / 1000);
      assert.equal(nJwt.create({}, uuid()).body.iat, nowUnix);
    });

    it('should not overwrite a defined iat field', function () {
      assert.equal(nJwt.create({iat: 1}, uuid()).body.iat, 1);
    });

    it('should create the exp field, defaulted to 1 hour', function () {
      var oneHourFromNow = Math.floor(new Date().getTime() / 1000) + (60 * 60);
      assert.equal(nJwt.create({}, uuid()).body.exp, oneHourFromNow);
    });

    it('should not overwrite a defined jti field', function () {
      assert.equal(nJwt.create({jti: 1}, uuid()).body.jti, 1);
    });

    it('should create the jti field', function () {
      var jwt = nJwt.create({}, uuid());
      assert(jwt.body.jti.match(/[a-zA-Z0-9]+[-]/));
    });
  });
});

describe('base64 URL Encoding', function () {
  it('should do what rfc7515 says', function () {
    var key = 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow';
    var headerString = '{"typ":"JWT",\r\n "alg":"HS256"}';
    var payloadString = '{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}';
    var compactHeader = nJwt.base64urlEncode(headerString);
    var compactBody = nJwt.base64urlEncode(payloadString);

    assert.equal(
      compactHeader,
      'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'
    );

    assert.equal(
      compactBody,
      'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
    );

    var expectedSignature = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    assert.equal(
      nJwt.Jwt.prototype.sign(
        [compactHeader, compactBody].join('.'),
        'HS256', new Buffer(key, 'base64')
      ),
      expectedSignature
    );
  });
});