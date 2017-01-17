var uuid = require('uuid');
var assert = require('chai').assert;

var nJwt = require('../');

describe('njwt.createVerifier', function() {
  it('should create a JwtVerifier instance', function() {
    var verifier = nJwt.createVerifier();
    assert(verifier instanceof nJwt.JwtVerifier);
  });
});

describe('JwtVerifier', function() {
  it('should construct itself if called without new', function() {
    assert((new nJwt.JwtVerifier()) instanceof nJwt.JwtVerifier);
  });

  describe('.withKeyResolver()', function() {
    var resolver;

    before(function() {
      resolver = function() {};
    });

    it('should set the ._keyResolver', function() {
      var jwtVerifier = new nJwt.JwtVerifier();
      jwtVerifier.withKeyResolver(resolver);
      assert(jwtVerifier._keyResolver === resolver);
    });

    it('should return the JwtVerifier', function() {
      var jwtVerifier = new nJwt.JwtVerifier();
      assert(jwtVerifier.withKeyResolver(function() {}) === jwtVerifier);
    });
  });

  describe('.verify', function() {
    describe('with key resolver set', function() {
      var callCount;
      var keyResolver;
      var keyKid;
      var signingKey;
      var mutatedSigningKey;
      var jwtVerifier;
      var jwtToken;

      beforeEach(function() {
        callCount = 0;
        keyKid = '123';
        signingKey = uuid();
        mutatedSigningKey = signingKey + uuid();
        keyResolver = function(kid, cb) {
          callCount++;
          assert(kid === keyKid);
          cb(null, signingKey);
        };

        jwtVerifier = nJwt.createVerifier().withKeyResolver(keyResolver);

        var jwt = new nJwt.Jwt().setSigningAlgorithm('none');
        jwt.header.kid = keyKid;
        jwtToken = jwt.compact();
      });

      it('should work synchronously', function() {
        var verify = function() {
          jwtVerifier.verify(jwtToken, mutatedSigningKey, 'none');
        };

        assert.doesNotThrow(verify);
        assert.equal(callCount, 1);
      });

      it('should work asynchronously', function(done) {
        jwtVerifier.verify(jwtToken, mutatedSigningKey, 'none', function(err, token) {
          assert.isNull(err);
          assert.isNotNull(token);
          assert.equal(callCount, 1);
          done();
        });
      });
    });
  });
});
