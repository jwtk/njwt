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

  describe('.setExpiration()',function(){
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
    it('should allow me to remove the exp field',function(){
      var jwt = nJwt.create({},uuid());
      var oneHourFromNow = Math.floor(new Date().getTime()/1000) + (60*60);
      assert.equal(nJwt.create({},uuid()).body.exp , oneHourFromNow);
      assert.equal(jwt.setExpiration().body.exp, undefined);
      assert.equal(jwt.setExpiration(false).body.exp, undefined);
      assert.equal(jwt.setExpiration(null).body.exp, undefined);
      assert.equal(jwt.setExpiration(0).body.exp, undefined);
    });
  });


  describe('.setSigningAlgorithm()',function(){
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
  describe('.toString()',function(){
    it('should return the compacted JWT string',function(){
      var jwt = nJwt.create({},uuid());
      assert.equal(jwt.compact(),jwt.toString());
    });
  });
});