var assert = require('chai').assert;

var nJwt = require('../');

var uuid = require('uuid');

var properties = require('../properties.json');

describe('Parser().setSigningAlgorithm() ',function(){
  describe('if called with an unsupported algorithm',function(){

    it('should throw UNSUPPORTED_SIGNING_ALG',function(){
      assert.throws(function(){
        new nJwt.Parser().setSigningAlgorithm('unsupported');
      },properties.errors.UNSUPPORTED_SIGNING_ALG);
    });

  });
});

describe('Parser().parse() ',function(){
  describe('when configured to expect no verification',function(){

    var parser = new nJwt.Parser();

    var claims = {hello: uuid()};

    describe('and given an unsigned token',function(){

      var result;
      var token = new nJwt.Jwt(claims).compact();

      before(function(done){
        parser.parse(token,function(err,res){
          result = [err,res];
          done();
        });
      });

      it('should return the JWT object',function(){
        assert.isNull(result[0],'An unexpcted error was returned');
        assert.equal(result[1].body.hello,claims.hello);
      });
    });

    describe('and given an expired token',function(){

      var result;
      var token = new nJwt.Jwt({expiredToken:'x'})
        .setExpiration(new Date().getTime()-1000)
        .compact();

      before(function(done){
        parser.parse(token,function(err,res){
          result = [err,res];
          done();
        });
      });

      it('should return EXPIRED',function(){
        assert.isNotNull(result[0],'An error was not returned');
        assert.equal(result[0].userMessage,properties.errors.EXPIRED);
      });
    });

  });


  describe('when configured to expect signature verification',function(){

    var parser = new nJwt.Parser()
      .setSigningAlgorithm('HS256')
      .setSigningKey('hello');

    describe('and given an unsigned token',function(){

      var result;
      var token = new nJwt.Jwt({foo:'bar'}).compact();

      before(function(done){
        parser.parse(token,function(err,res){
          result = [err,res];
          done();
        });
      });

      it('should return SIGNATURE_ALGORITHM_MISMTACH',function(){
        assert.isNotNull(result[0],'An error was not returned');
        assert.equal(result[0].userMessage,properties.errors.SIGNATURE_ALGORITHM_MISMTACH);
      });
    });

  });

  describe('when configured to expect signature verification',function(){

    var key = 'the key';

    var parser = new nJwt.Parser()
      .setSigningAlgorithm('HS256')
      .setSigningKey(key);

    var claims = {hello:uuid()};

    describe('and given a token that was signed with the same key',function(){

      var result;
      var token = new nJwt.Jwt(claims)
        .setSigningAlgorithm('HS256')
        .setSigningKey(key)
        .compact();

      before(function(done){
        parser.parse(token,function(err,res){
          result = [err,res];
          done();
        });
      });

      it('should return the JWT object',function(){
        assert.isNull(result[0],'An unexpcted error was returned');
        assert.equal(result[1].body.hello,claims.hello);
      });
    });

    describe('and given a token that was signed with a different key',function(){

      var result;
      var token = new nJwt.Jwt(claims)
        .setSigningAlgorithm('HS256')
        .setSigningKey('not the same key')
        .compact();

      before(function(done){
        parser.parse(token,function(err,res){
          result = [err,res];
          done();
        });
      });

      it('should return SIGNATURE_MISMTACH',function(){
        assert.isNotNull(result[0],'An error was not returned');
        assert.equal(result[0].userMessage,properties.errors.SIGNATURE_MISMTACH);
      });
    });

  });

  describe('when configured to expect no verification',function(){

    var parser = new nJwt.Parser();

    describe('and given an signed token',function(){

      var result;
      var token = new nJwt.Jwt({foo:'bar'})
        .setSigningAlgorithm('HS256')
        .setSigningKey('foo')
        .compact();

      before(function(done){
        parser.parse(token,function(err,res){
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



