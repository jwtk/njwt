var assert = require('chai').assert;

var nJwt = require('../');

var properties = require('../properties.json');

describe('Jwt()',function(){
  describe('signWith()',function(){
    describe('if called with an unsupported algorithm',function(){
      it('should throw',function(){
        assert.throws(function(){
          new nJwt.Jwt().signWith('unsupported');
        },properties.errors.UNSUPPORTED_SIGNING_ALG);
      });
    });
  });

});



