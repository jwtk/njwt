var assert = require('chai').assert;
var nJwt = require('..');

describe('njwt module exports',function () {
  // https://github.com/chrisandoryan/vuln-advisory/blob/main/nJwt/CVE-2024-34273.md
  describe('CVE-2024-34273', function () {
    it('should export classes with frozen prototypes', function(){
      assert.frozen(nJwt.Jwt);
      assert.frozen(nJwt.Jwt.prototype);
      assert.frozen(nJwt.JwtBody);
      assert.frozen(nJwt.JwtBody.prototype);
      assert.frozen(nJwt.JwtHeader);
      assert.frozen(nJwt.JwtHeader.prototype);
      assert.frozen(nJwt.Verifier);
      assert.frozen(nJwt.Verifier.prototype);
    });

    it('should not allow prototype pollution', function () {

      // based on: https://github.com/chrisandoryan/vuln-advisory/blob/main/nJwt/CVE-2024-34273.md#proof-of-concept-poc
      var token = `ewogICJ0eXAiOiAiSldUIiwKICAiYWxnIjogIm5vbmUiLAogICJfX3Byb3RvX18iOiB7CiAgICAidHlwIjogIkpXVCIsCiAgICAiYWxnIjogIkhTMjU
      2IiwKICAgICJfX3Byb3RvX18iOiB7CiAgICAgICJjb21wYWN0IjogbnVsbCwKICAgICAgInJlc2VydmVkS2V5cyI6IFsKICAgICAgICAidHlwIiwKICAgICAgICAicmF
      uZG9tX2dpYmJlcmlzaCIKICAgICAgXQogICAgfQogIH0KfQ.ewogICJzdWIiOiAxLAogICJzY29wZSI6ICJ1c2VyIiwKICAianRpIjogImJhZmIxNmNlLTIwZDYtNGNk
      Ny05NDgzLTY1YTA5NThhOGU2NCIsCiAgImlhdCI6IDI1Mzc0Nzg1MDYsCiAgImV4cCI6IDI1Mzc0Nzg1MDYsCiAgIl9fcHJvdG9fXyI6IHsKICAgICJjb21wYWN0Ijog
      bnVsbCwKICAgICJ0b0pTT04iOiBudWxsLAogICAgInBvbGx1dGVkIjogdHJ1ZQogIH0KfQ`.replace(/\s/g, '');

      assert.isOk(nJwt.JwtBody.prototype.hasOwnProperty('toJSON'))
      assert.isOk(nJwt.JwtBody.prototype.hasOwnProperty('compact'))
      assert.isOk(nJwt.JwtHeader.prototype.hasOwnProperty('compact'))
      
      nJwt.verify(token);

      assert.isOk(nJwt.JwtBody.prototype.hasOwnProperty('toJSON'))
      assert.isOk(nJwt.JwtBody.prototype.hasOwnProperty('compact'))
      assert.isOk(nJwt.JwtHeader.prototype.hasOwnProperty('compact'))
    });
  });

});
