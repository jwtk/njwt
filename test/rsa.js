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

describe('parseClaimsJws',function() {



  describe('with a token that is signed with an RSA private key',function(){
    var claims = {foo:'bar'};
    var token = new nJwt.Jwt(claims).signWith('RS256',pair.private).compact();

    describe('and verified with the public key',function(){

      var result;

      before(function(done){
        new nJwt.Parser().setSigningKey(pair.public).parseClaimsJws(token,function(err,res){
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

    describe('and verified with the private key',function(){

      var result;

      before(function(done){
        new nJwt.Parser().setSigningKey(pair.private).parseClaimsJws(token,function(err,res){
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
  });


  describe('with a token that is signed with an RSA public key',function(){

    var token = new nJwt.Jwt({foo:'bar'}).signWith('HS256',pair.public).compact();

    describe('and verified with the public key and the header is maliciously set to HS256',function(){

      var result;

      before(function(done){
        new nJwt.Parser().setSigningKey(pair.public).parseClaimsJws(token,function(err,res){
          result = [err,res];
          done();
        });
      });

      it('should return a signature mismatch error',function(){
        assert.isNotNull(result[0],'An error was not returned');
        assert.equal(result[0].userMessage,properties.errors.SIGNATURE_MISMTACH);
      });
    });

  });
});

