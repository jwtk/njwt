var assert = require('chai').assert;
var nJwt = require('../');
var uuid = require('uuid');
var properties = require('../properties.json');

describe('Parser',function(){
  it('should construct itself if called without new',function(){
    assert(nJwt.Parser() instanceof nJwt.Parser);
  });
});

describe('Parser().parse()',function(){
  it('should return PARSE_ERROR if the header is not JSON',function(){
    assert.throws(function(){
      nJwt.Parser().parse("noavalidheader.notavalidbody");
    },properties.errors.PARSE_ERROR);
  });
  it('should return PARSE_ERROR if the body is not JSON',function(){
    var header = nJwt.JwtHeader({type:'JWT',alg:'HS256'}).compact();
    assert.throws(function(){
      nJwt.Parser().parse(header+".notavalidbody");
    },properties.errors.PARSE_ERROR);
  });
});

describe('parse() ',function(){

  it('should support sync usage',function(){
    var claims = {hello: uuid()};
    var token = new nJwt.Jwt(claims).compact();
    var parsedJwt = nJwt.parse(token);
    assert(parsedJwt instanceof nJwt.Jwt);
    assert.equal(parsedJwt.body.hello,claims.hello);

    assert.throws(function(){
      nJwt.parse('invalid token');
    },properties.errors.PARSE_ERROR);
  });

  it('should support async usage in success case',function(done){
    var claims = {hello: uuid()};
    var token = new nJwt.Jwt(claims).compact();
    nJwt.parse(token,function(err,parsedJwt){
      assert.isNull(err,'An unexpcted error was returned');
      assert(parsedJwt instanceof nJwt.Jwt);
      assert.equal(parsedJwt.body.hello,claims.hello);
      done();
    });
  });

  it('should support async usage in error case',function(done){
    nJwt.parse('invalid token',function(err){
      assert.equal(err.userMessage,properties.errors.PARSE_ERROR);
      done();
    });
  });
});