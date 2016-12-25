var assert = require('chai').assert;
var uuid = require('uuid');
var nJwt = require('../');

describe('demonstrate a key lookup on verify', function () {
  describe('and given an signed token', function () {
    var result;
    var claims = {hello: 'world'}
    var keys = [
      {keyid: 'key1', secret: '12345'}, 
      {keyid: 'key2',secret: 'abcd'}
    ];
    var currentKey = 0
    var expectedSecret = keys[currentKey].secret

    var token = new nJwt.Jwt(claims)
      .setSigningAlgorithm('HS256')
      .setSigningKey(expectedSecret)
      .setSigningKeyId(keys[currentKey].keyid)
      .compact();

    var jwt = new nJwt.Parser().parse(token);
    var found = keys.find(k => k.keyid === jwt.header.keyid)

    assert.equal(found.secret, expectedSecret);

    before(function (done) {
      var verifier = new nJwt.Verifier()
        .setSigningAlgorithm('HS256')
        .setSigningKey(found.secret)
      verifier.verify(token, function (err, res) {
        result = [err, res];
        done();
      });
    });

    it('the jwt should be equal', function () {
      assert.equal(result[1].body.hello, claims.hello);
    });
  });


  describe('demo key lookup', function () {
    var claims = {hello: 'world'}

    var keys = [
      {keyid: 'key1', secret: '12345'}, 
      {keyid: 'key2',secret: 'abcd'}
    ];
    var currentKey = 0

    // create a token
    var token = new nJwt.Jwt(claims)
      .setSigningAlgorithm('HS256')
      .setSigningKey(keys[currentKey].secret)
      .setSigningKeyId(keys[currentKey].keyid)
      .compact();

    // Parse the tokent
    var jwt = new nJwt.Parser().parse(token);
    // lookup the key
    var found = keys.find(k => k.keyid === jwt.header.keyid)
    // then verify
    var verifier = new nJwt.Verifier()
      .setSigningAlgorithm('HS256')
      .setSigningKey(found.secret)
      .verify(token, function (err, res) {
        if (res.body.hello !== claims.hello)
          throw(new Error('lookup didnt work'))
      });
  });

});