'use strict';

var fs = require('fs');
var path = require('path');
var uuid = require('uuid');
var secureRandom = require('secure-random');
var assert = require('chai').assert;
var nJwt = require('../');

describe('Verifier', function () {
  it('should construct itself if called without new', function () {
    assert(nJwt.Verifier() instanceof nJwt.Verifier);
  });

  describe('.setSigningAlgorithm()', function () {
    describe('if called with an unsupported algorithm', function () {
      it('should throw UnsupportedSigningAlgorithmJwtError', function () {
        assert.throws(function () {
          new nJwt.Verifier().setSigningAlgorithm('unsupported');
        }, nJwt.UnsupportedSigningAlgorithmJwtError);
      });
    });
  });

  describe('.verify()', function () {
    it('should persist the original token to the toString() invocation', function () {
      var token = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ.p6bizskaJLAheVyRhQEMR-60PkH_jtLVYgMy1qTjCoc';
      assert.equal(token, nJwt.verify(token).toString());
    });

    it('should not alter the JWT, it should be compact-able as the same token', function () {
      var orignalJwt = new nJwt.Jwt({hello: uuid()}, false).setSigningAlgorithm('none');
      var originalToken = orignalJwt.compact();
      var verifiedJwt = nJwt.verify(originalToken);
      assert.equal(originalToken, verifiedJwt.compact());
    });

    describe('if given only a token', function () {
      it('should verify tokens that are alg none', function () {
        var claims = {hello: uuid()};
        var token = new nJwt.Jwt(claims)
          .setSigningAlgorithm('none')
          .compact();

        assert.doesNotThrow(function () {
          nJwt.verify(token);
        });
      });

      it('should reject tokens that specify an alg', function () {
        var claims = {hello: uuid()};
        var key = uuid();
        var token = new nJwt.create(claims, key)
          .compact();

        assert.throws(function () {
          nJwt.verify(token);
        }, nJwt.SignatureAlgorithmMismatchJwtParseError);
      });
    });

    it('should return JwtParseError if the header is not JSON', function () {
      assert.throws(function () {
        nJwt.verify('noavalidheader.notavalidbody');
      }, nJwt.JwtParseError);
    });

    it('should give me the original string on the parse error object', function (done) {
      var invalidJwt = 'noavalidheader.notavalidbody';
      nJwt.verify(invalidJwt, function (err) {
        assert.equal(err.jwtString, invalidJwt);
        done();
      });
    });

    it('should return JwtParseError if the body is not JSON', function () {
      var header = new nJwt.JwtHeader({type: 'JWT', alg: 'HS256'}).compact();
      assert.throws(function () {
        nJwt.verify(header + '.notavalidbody');
      }, nJwt.JwtParseError);
    });

    it('should give me the parsed header on the error object if the body fails', function (done) {
      var header = new nJwt.JwtHeader({typ: 'JWT', alg: uuid()});
      var invalidJwt = header.compact() + '.notavalidbody';
      nJwt.verify(invalidJwt, function (err) {
        assert.equal(err.jwtString, invalidJwt);
        assert.equal(err.parsedHeader.alg, header.alg);
        done();
      });
    });

    it('should support sync usage', function () {
      var verifier = new nJwt.Verifier()
        .setSigningAlgorithm('none');
      var claims = {hello: uuid()};
      var token = new nJwt.Jwt(claims).compact();
      var verifiedToken;

      assert.doesNotThrow(function () {
        verifiedToken = verifier.verify(token);
      });

      assert(verifiedToken instanceof nJwt.Jwt);
      assert.equal(verifiedToken.body.hello, claims.hello);

      assert.throws(function () {
        verifiedToken = verifier.verify('invalid token');
      }, nJwt.JwtParseError);

    });

    it('should return the jwt string, header and body on error objects', function (done) {
      var jwt = new nJwt.Jwt({expiredToken: uuid()})
        .setExpiration(new Date().getTime() - 1000);
      var token = jwt.compact();

      nJwt.verify(token, function (err) {
        assert.equal(err.jwtString, token);
        assert.equal(err.parsedHeader.alg, jwt.header.alg);
        assert.equal(err.parsedBody.expiredToken, jwt.body.expiredToken);
        assert.instanceOf(err, nJwt.ExpiredJwtParseError);
        done();
      });
    });

    it('should return the jwt string, header and body on error objects with not active message', function (done) {
      var jwt = new nJwt.Jwt({notActiveToken: uuid()})
        .setNotBefore(new Date().getTime() + 1000);
      var token = jwt.compact();
      nJwt.verify(token, function (err) {
        assert.equal(err.jwtString, token);
        assert.equal(err.parsedHeader.alg, jwt.header.alg);
        assert.equal(err.parsedBody.notActiveToken, jwt.body.notActiveToken);
        assert.instanceOf(err, nJwt.NotActiveJwtParseError);
        done();
      });
    });

    it('should return the jwt string, header and body with null error objects', function (done) {
      var jwt = new nJwt.Jwt({notActiveToken: uuid()});
      var token = jwt.compact();
      nJwt.verify(token, function (err) {
        assert.isNull(err);
        assert.isNotNull(token);
        done();
      });
    });

    describe('when configured to expect no verification', function () {
      var verifier = new nJwt.Verifier()
        .setSigningAlgorithm('none');

      var claims = {hello: uuid()};

      describe('and given an unsigned token', function () {
        var result;
        var token = new nJwt.Jwt(claims).compact();

        before(function (done) {
          verifier.verify(token, function (err, res) {
            result = [err, res];
            done();
          });
        });

        it('should return the JWT object', function () {
          assert.isNull(result[0], 'An unexpcted error was returned');
          assert.equal(result[1].body.hello, claims.hello);
        });
      });

      describe('and given an expired token', function () {
        var result;
        var jwt = new nJwt.Jwt({expiredToken: 'x'})
          .setExpiration(new Date().getTime() - (10 * 1000));

        before(function (done) {
          verifier.verify(jwt.compact(), function (err, res) {
            result = [err, res];
            done();
          });
        });

        it('should return ExpiredJwtParseError error', function () {
          assert.isNotNull(result[0], 'An error was not returned');
          assert.instanceOf(result[0], nJwt.ExpiredJwtParseError);
        });
      });

      describe('and given a not active token', function () {
        var result;
        var jwt = new nJwt.Jwt({notActiveToken: 'x'})
          .setNotBefore(new Date().getTime() + (10 * 1000));

        before(function (done) {
          verifier.verify(jwt.compact(), function (err, res) {
            result = [err, res];
            done();
          });
        });

        it('should return NotActiveJwtParseError error', function () {
          assert.isNotNull(result[0], 'An error was not returned');
          assert.instanceOf(result[0], nJwt.NotActiveJwtParseError);
        });
      });

      describe('and given an signed token', function () {
        var result;
        var token = new nJwt.Jwt({foo: 'bar'})
          .setSigningAlgorithm('HS256')
          .setSigningKey('foo')
          .compact();

        before(function (done) {
          verifier.verify(token, function (err, res) {
            result = [err, res];
            done();
          });
        });

        it('should return an unexpected algorithm error', function () {
          assert.isNotNull(result[0], 'An error was not returned');
          assert.instanceOf(result[0], nJwt.SignatureAlgorithmMismatchJwtParseError);
        });
      });
    });

    describe('when configured to expect signature verification', function () {
      var verifier = new nJwt.Verifier()
        .setSigningAlgorithm('HS256')
        .setSigningKey('hello');

      describe('and given an unsigned token', function () {
        var result;
        var token = new nJwt.Jwt({foo: 'bar'}).compact();

        before(function (done) {
          verifier.verify(token, function (err, res) {
            result = [err, res];
            done();
          });
        });

        it('should return SignatureAlgorithmMismatchJwtParseError error', function () {
          assert.isNotNull(result[0], 'An error was not returned');
          assert.instanceOf(result[0], nJwt.SignatureAlgorithmMismatchJwtParseError);
        });
      });
    });

    describe('when configured to expect signature verification', function () {
      var key = secureRandom(256, {type: 'Buffer'});

      var verifier = new nJwt.Verifier()
        .setSigningAlgorithm('HS256')
        .setSigningKey(key);

      var claims = {hello: uuid()};

      describe('and given a token that was signed with the same key', function () {
        var result;

        var token = new nJwt.Jwt(claims)
          .setSigningAlgorithm('HS256')
          .setSigningKey(key)
          .compact();

        before(function (done) {
          verifier.verify(token, function (err, res) {
            result = [err, res];
            done();
          });
        });

        it('should return the JWT object', function () {
          assert.isNull(result[0], 'An unexpcted error was returned');
          assert.equal(result[1].body.hello, claims.hello);
        });
      });

      describe('and given a token that was signed with a different key', function () {
        var result;

        var token = new nJwt.Jwt(claims)
          .setSigningAlgorithm('HS256')
          .setSigningKey('not the same key')
          .compact();

        before(function (done) {
          verifier.verify(token, function (err, res) {
            result = [err, res];
            done();
          });
        });

        it('should return SignatureMismatchJwtParseError error', function () {
          assert.isNotNull(result[0], 'An error was not returned');
          assert.instanceOf(result[0], nJwt.SignatureMismatchJwtParseError);
        });
      });
    });

    describe('when verifying an invalid ECDSA token', function () {
      var result = null;
      var ecdsaPublicKey = fs.readFileSync(path.join(__dirname, 'ecdsa.pub'), 'utf8');
      var invalidToken = 'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.82wXTCDa4VHEAaDlq7PyqOqNbMGwDiXSt_n1nKGH43w';

      before(function (done) {
        var verifier = new nJwt.Verifier()
          .setSigningAlgorithm('ES512')
          .setSigningKey(ecdsaPublicKey);

        verifier.verify(invalidToken, function (err, res) {
          result = [err, res];
          done();
        });
      });

      it('should return SignatureMismatchJwtParseError', function () {
        assert.isNotNull(result[0], 'An error was not returned');
        assert.instanceOf(result[0], nJwt.SignatureMismatchJwtParseError);
      });
    });
  });
});
