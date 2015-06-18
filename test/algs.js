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

function testKeyAlg(alg,keyPair,done){

  var claims = { hello: uuid(), debug: true };
  var jwt = nJwt.create(claims,keyPair.private,alg);
  var token = jwt.compact();

  itShouldBeAValidJwt(jwt);
  nJwt.verify(token,keyPair.public,alg,function(err,jwt){
    assert.isNull(err,'An unexpcted error was returned');
    itShouldBeAValidJwt(jwt);
    done();
  });
}

var rsaPair = {
  public: fs.readFileSync(path.join(__dirname,'rsa.pub'),'utf8'),
  private: fs.readFileSync(path.join(__dirname,'rsa.priv'),'utf8')
};

var ecdsaPair = {
  public: fs.readFileSync(path.join(__dirname,'ecdsa.pub'),'utf8'),
  private: fs.readFileSync(path.join(__dirname,'ecdsa.priv'),'utf8')
};

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
    testKeyAlg('RS256',rsaPair,done);
  });
  it('should support creation and veification of RS384 JWT tokens',function(done){
    testKeyAlg('RS384',rsaPair,done);
  });
  it('should support creation and veification of RS512 JWT tokens',function(done){
    testKeyAlg('RS512',rsaPair,done);
  });
  it('should support creation and veification of ES256 JWT tokens',function(done){
    testKeyAlg('ES256',ecdsaPair,done);
  });
  it('should support creation and veification of ES384 JWT tokens',function(done){
    testKeyAlg('ES384',ecdsaPair,done);
  });
  it('should support creation and veification of ES512 JWT tokens',function(done){
    testKeyAlg('ES512',ecdsaPair,done);
  });
});