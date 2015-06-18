var assert = require('chai').assert;
var uuid = require('uuid');
var nJwt = require('../');
var jsonwebtoken = require('jsonwebtoken');
var jwtSimple = require('jwt-simple');

describe('this library',function () {
  it('should generate tokens that can be verified by jsonwebtoken',function(done){
    var key = uuid();
    var claims = {hello:uuid()};
    var jwt = nJwt.create(claims,key);
    var token = jwt.compact();
    assert.doesNotThrow(function(){
      jsonwebtoken.verify(token,key);
    });
    jsonwebtoken.verify(token,key,function(err,claimsResult){
      assert.isNull(err,'An unexpcted error was returned');
      assert.equal(jwt.body.hello,claimsResult.hello);
      assert.equal(jwt.body.jti,claimsResult.jti);
      assert.equal(jwt.body.iat,claimsResult.iat);
      done();
    });
  });

  it('should be able to verify tokens from jsonwebtoken',function(done){
    var claims = {hello:uuid()};
    var key = uuid();
    var token = jsonwebtoken.sign(claims, key);
    nJwt.verify(token,key,function(err,jwt){
      assert.isNull(err,'An unexpcted error was returned');
      assert.equal(jwt.body.hello,claims.hello);
      done();
    });
  });

  it('should generate tokens that can be verified by jwt-simple',function(done){
    var key = uuid();
    var claims = {hello:uuid()};
    var jwt = nJwt.create(claims,key);
    var token = jwt.compact();
    var decoded;
    assert.doesNotThrow(function(){
      decoded = jwtSimple.decode(token, key);
    });

    assert.equal(jwt.body.hello,decoded.hello);
    assert.equal(jwt.body.jti,decoded.jti);
    assert.equal(jwt.body.iat,decoded.iat);
    done();

  });

  it('should be able to verify tokens from jwt-simple',function(done){
    var claims = {hello:uuid()};
    var key = uuid();
    var token = jwtSimple.encode(claims, key);
    nJwt.verify(token,key,function(err,jwt){
      assert.isNull(err,'An unexpcted error was returned');
      assert.equal(jwt.body.hello,claims.hello);
      done();
    });
  });
});