var assert = require('chai').assert;
var util = require('util');
var uuid = require('uuid');

var nJwt = require('../');
var properties = require('../properties.json');

describe('Verifier', function() {
  it('should construct itself if called without new', function() {
    assert(nJwt.Verifier() instanceof nJwt.Verifier);
  });

  describe('.withKeyResolver()', function() {
    var resolver;

    before(function() {
      resolver = function() {};
    });

    it('should set the .keyResolver', function() {
      var jwtVerifier = new nJwt.Verifier();
      jwtVerifier.withKeyResolver(resolver);
      assert.isDefined(jwtVerifier.keyResolver);
    });

    it('should return the Verifier', function() {
      var jwtVerifier = new nJwt.Verifier();
      assert(jwtVerifier.withKeyResolver(function() {}) === jwtVerifier);
    });
  });

  describe('.verify', function() {
    describe('with key resolver set', function() {
      var callCount;
      var keyResolver;
      var keyKid;
      var signingKey;
      var jwtVerifier;
      var jwtToken;

      beforeEach(function() {
        callCount = 0;
        keyKid = '123';
        signingKey = uuid();
        keyResolver = function(kid, cb) {
          callCount++;
          assert(kid === keyKid);
          cb(null, signingKey);
        };

        jwtVerifier = nJwt.createVerifier().withKeyResolver(keyResolver);

        var jwt = new nJwt.create({}, signingKey).setHeader('kid', keyKid);
        jwtToken = jwt.compact();
      });

      it('should work synchronously', function() {
        var verify = function() {
          jwtVerifier.verify(jwtToken);
        };

        assert.doesNotThrow(verify);
        assert.equal(callCount, 1);
      });

      it('should work asynchronously', function(done) {
        jwtVerifier.verify(jwtToken, function(err, token) {
          assert.isNull(err);
          assert.isNotNull(token);
          assert.equal(callCount, 1);
          done();
        });
      });
    });

    describe('passing the error from the keyResolver', function() {
      var keyResolver;
      var error;
      var jwtToken;
      var jwtVerifier;

      beforeEach(function() {
        error = new Error('key resolver error');
        keyResolver = function(kid, cb) {
          cb(error);
        };

        jwtVerifier = nJwt.createVerifier().withKeyResolver(keyResolver);
        var jwt = new nJwt.create({},'foo');
        jwt.header.kid = 'foo'
        jwtToken = jwt.compact();
      });

      describe('synchronously', function() {
        it('should throw the error', function() {
          var verify = function() {
            jwtVerifier.verify(jwtToken);
          };

          assert.throws(verify, util.format(properties.errors.KEY_RESOLVER_ERROR, 'foo'));
        });
      });

      describe('asynchronously', function() {
        it('should pass the error to the callback', function(done) {
          jwtVerifier.verify(jwtToken, function(err) {
            assert.instanceOf(err, Error);
            assert.equal(err.message, util.format(properties.errors.KEY_RESOLVER_ERROR, 'foo'));
            assert.equal(err.innerError, error);
            done();
          });
        });
      });
    });
  });
});
