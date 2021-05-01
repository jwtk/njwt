var assert = require('chai').assert;
var uuid = require('uuid');
var nJwt = require('../');


describe('Parser', function () {
  it('should construct itself if called without new', function () {
    assert(nJwt.Parser() instanceof nJwt.Parser);
  });
});
describe('Parser.parse()', function () {
  var result = null
  var claims = {hello: 'world'}
  before(function(done){
    var token = new nJwt.Jwt(claims, false)
      .setSigningAlgorithm('none')
      .compact();
    var parser = nJwt.Parser();
    parser.parse(token, function(err,res){
        result = [err,res];
        done();
    });
  });
  it('should parse a valid token', function () {
      assert.isNull(result[0], 'An error was not returned');
      assert.equal(result[1].body.hello,claims.hello);
  });

});