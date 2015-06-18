var assert = require('chai').assert;
var nJwt = require('../');
var uuid = require('uuid');
var properties = require('../properties.json');

describe('Jwt',function() {
  it('should construct itself if called without new',function(){
    assert(nJwt.Jwt() instanceof nJwt.Jwt);
  });

  describe('.setSubject()',function(){
    it('should set the sub claim',function(){
      var sub = uuid();
      assert.equal(nJwt.Jwt().setSubject(sub).body.sub,sub);
    });
  });
  describe('.setIssuer()',function(){
    it('should set the iss claim',function(){
      var iss = uuid();
      assert.equal(nJwt.Jwt().setIssuer(iss).body.iss,iss);
    });
  });

  describe('.setIssuer()',function(){
    it('should accept Date types and set the exp claim to a UNIX timestamp value',function(){
      var future = new Date('2025');
      assert.equal(
        nJwt.Jwt().setExpiration(future).body.exp,
        future.getTime()/1000
      );
    });
    it('should accept milliseconds values and set the exp claim to a UNIX timestamp value',function(){
      var future = new Date('2025').getTime();
      assert.equal(
        nJwt.Jwt().setExpiration(future).body.exp,
        future/1000
      );
    });
  });

  describe('.compact()',function(){
    it('should throw if you specify an alg but not a key',function(){
      assert.throws(function(){
        nJwt.Jwt().setSigningAlgorithm('HS256').compact();
      },properties.errors.SIGNING_KEY_REQUIRED);
    });
  });

  describe('.sign()',function(){
    it('should throw if you give it an unknown algoritm',function(){
      assert.throws(function(){
        nJwt.Jwt().sign('hello');
      },properties.errors.UNSUPPORTED_SIGNING_ALG);
    });
  });

});