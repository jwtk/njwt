var assert = require('assert');
var nJwt = require('../');
var uuid = require('uuid');
describe('Jwt',function() {
  it('should construct itself if called without new',function(){
    assert(nJwt.Jwt() instanceof nJwt.Jwt);
  });

  describe('.setSubject()',function(){
    it('should set the sub claim',function(){
      var sub = uuid();
      assert.equal(nJwt.Jwt().setSubject(sub).body.sub,sub);
    });
  });
  describe('.setIssuer()',function(){
    it('should set the iss claim',function(){
      var iss = uuid();
      assert.equal(nJwt.Jwt().setIssuer(iss).body.iss,iss);
    });
  });

});