var assert = require('chai').assert;

var nJwt = require('../');

var properties = require('../properties.json');

var fs = require('fs');
var path = require('path');

var pair = {
  public: fs.readFileSync(path.join(__dirname,'rsa.pub'),'utf8'),
  private: fs.readFileSync(path.join(__dirname,'rsa.priv'),'utf8')
};

describe('JWT Builder',function(){
  describe('when RS256 is specified',function(){
    var token = new nJwt.Jwt({}).signWith('RS256',pair.private).compact();
    it('should create the token with the appropriate header values',function(){
      assert.isNotNull(token);
    });
  });
});

describe('a token that is signed with an RSA private key',function() {

  var claims = {foo:'bar'};
  var token = new nJwt.Jwt(claims).signWith('RS256',pair.private).compact();

  describe('and a parser that is configurd with the RSA public key',function(){

    var parser = new nJwt.Parser().setSigningKey('RS256',pair.public);

    var result;

    before(function(done){
      parser.parseClaimsJws(token,function(err,res){
        result = [err,res];
        done();
      });
    });

    it('should validate and return the token payload',function(){
      assert.isNull(result[0],'An unexpected error was returned');
      assert.isObject(result[1],'A result was not returned');
      assert.equal(result[1].body.foo,claims.foo);
    });
  });

  // describe('and a parser that is configurd with the RSA private key',function(){

  //   // The crypto library is throwing errors when i try to verify with
  //   // the private key, why?

  //   var parser = new nJwt.Parser().setSigningKey('RS256',pair.private);

  //   var result;

  //   before(function(done){
  //     parser.parseClaimsJws(token,function(err,res){
  //       result = [err,res];
  //       done();
  //     });
  //   });

  //   it('should validate and return the token payload',function(){
  //     assert.isNull(result[0],'An unexpected error was returned');
  //     assert.isObject(result[1],'A result was not returned');
  //     assert.equal(result[1].body.foo,claims.foo);
  //   });
  // });

});

describe('a token that is signed with an RSA public key but header alg of HS256',function(){

  var token = new nJwt.Jwt({foo:'bar'}).signWith('HS256',pair.public).compact();

  describe('and a parser configured with RS256 and the same public key for vefification',function(){

    var parser = new nJwt.Parser().setSigningKey('RS256',pair.public);

    var result;

    before(function(done){
      parser.parseClaimsJws(token,function(err,res){
        result = [err,res];
        done();
      });
    });

    it('should return SIGNATURE_ALGORITHM_MISMTACH error',function(){
      assert.isNotNull(result[0],'An error was not returned');
      assert.equal(result[0].message,properties.errors.SIGNATURE_ALGORITHM_MISMTACH);
    });
  });

});
