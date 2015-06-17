var assert = require('chai').assert;
var uuid = require('uuid');
var nJwt = require('../');
var fs = require('fs');
var path = require('path');

function itShouldBeAValidJwt(jwt){
  assert(nJwt.create({},uuid()) instanceof nJwt.Jwt);
  var nowUnix = Math.floor(new Date().getTime()/1000);
  assert.equal(nJwt.create({},uuid()).body.iat , nowUnix);
  assert(jwt.body.jti.match(/[a-zA-Z0-9]+[-]/));
}

function testHmacAlg(alg,done){
  var key = uuid();
  var claims = { hello: uuid(), debug: true };
  var jwt = nJwt.create(claims,key,alg);
  var token = jwt.compact();

  itShouldBeAValidJwt(jwt);
  nJwt.verify(token,key,alg,function(err,jwt){
    assert.isNull(err,'An unexpcted error was returned');
    itShouldBeAValidJwt(jwt);
    done();
  });
}

function testRsaAlg(alg,done){
  var pair = {
    public: fs.readFileSync(path.join(__dirname,'rsa.pub'),'utf8'),
    private: fs.readFileSync(path.join(__dirname,'rsa.priv'),'utf8')
  };
  var claims = { hello: uuid(), debug: true };
  var jwt = nJwt.create(claims,pair.private,alg);
  var token = jwt.compact();

  itShouldBeAValidJwt(jwt);
  nJwt.verify(token,pair.public,alg,function(err,jwt){
    assert.isNull(err,'An unexpcted error was returned');
    itShouldBeAValidJwt(jwt);
    done();
  });
}

describe('this library',function () {
  it('should support creation and veification of HS256 JWT tokens',function(done){
    testHmacAlg('HS256',done);
  });
  it('should support creation and veification of HS384 JWT tokens',function(done){
    testHmacAlg('HS384',done);
  });
  it('should support creation and veification of HS512 JWT tokens',function(done){
    testHmacAlg('HS512',done);
  });
  it('should support creation and veification of RS256 JWT tokens',function(done){
    testRsaAlg('RS256',done);
  });
  it('should support creation and veification of RS384 JWT tokens',function(done){
    testRsaAlg('RS384',done);
  });
  it('should support creation and veification of RS512 JWT tokens',function(done){
    testRsaAlg('RS512',done);
  });
});