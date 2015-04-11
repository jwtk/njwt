var assert = require('chai').assert;

var nJwt = require('../');

var properties = require('../properties.json');

describe('Parser()',function(){
  describe('setSigningKey()',function(){
    describe('if called with an unsupported algorithm',function(){
      it('should throw',function(){
        assert.throws(function(){
          new nJwt.Parser().setSigningKey('unsupported');
        },properties.errors.UNSUPPORTED_SIGNING_ALG);
      });
    });
  });

  describe('parseClaimsJws()',function() {

    describe('when configured to expect signature verification',function(){

      var parser = new nJwt.Parser().setSigningKey('HS256','hello');

      describe('and given an unsigned token',function(){

        var result;
        var token = new nJwt.Jwt({foo:'bar'}).compact();

        before(function(done){
          parser.parseClaimsJws(token,function(err,res){
            result = [err,res];
            done();
          });
        });

        it('should return an unexpected algorithm error',function(){
          assert.isNotNull(result[0],'An error was not returned');
          assert.equal(result[0].userMessage,properties.errors.SIGNATURE_ALGORITHM_MISMTACH);
        });
      });

    });

  });
});



