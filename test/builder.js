var assert = require('chai').assert;

var nJwt = require('../');
var uuid = require('uuid');

var properties = require('../properties.json');

describe('Jwt()',function(){
  describe('signWith()',function(){
    describe('if called with an unsupported algorithm',function(){
      it('should throw',function(){
        assert.throws(function(){
          new nJwt.Jwt().setSigningAlgorithm('unsupported');
        },properties.errors.UNSUPPORTED_SIGNING_ALG);
      });
    });
  });

});

describe('create()',function(){

  it('should throw if using defaults without a secret key',function(){
    assert.throws(function(){
      nJwt.create({});
    },properties.errors.SIGNING_KEY_REQUIRED);
  });

  it('should not throw if none is specified when omitting the key',function(){
    assert.doesNotThrow(function(){
      nJwt.create({},null,'none');
    });
  });

  describe('with a signing key',function(){

    it('should return a JWT',function(){
      assert(nJwt.create({},uuid()) instanceof nJwt.Jwt);
    });

    it('should use HS256 by default',function(){
      assert.equal(nJwt.create({},uuid()).header.alg,'HS256');
    });

    it('should create the iat field',function(){
      var nowUnix = Math.floor(new Date().getTime()/1000);
      assert.equal(nJwt.create({},uuid()).body.iat , nowUnix);
    });
    // it('should create the jti field',function(){
    //   var jwt = nJwt.create({},uuid());
    //   assert(jwt.body.jti.match(/[a-zA-Z]+[-]/));
    // });

  });

});



