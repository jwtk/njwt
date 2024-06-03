var assert = require('chai').assert;
var nJwt = require('..');
var secureRandom = require('secure-random');

describe('njwt exports',function () {
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

  // https://github.com/chrisandoryan/vuln-advisory/blob/main/nJwt/CVE-2024-34273.md
  describe('foo', function () {
    it('should no longer be vulnerable', function () {
      // const claims = {
      //   "sub": 1,
      //   "scope": "user",
      //   "jti": "bafb16ce-20d6-4cd7-9483-65a0958a8e64",
      //   "iat": 2537478506,
      //   "exp": 2537478506,
      //   "__proto__": {
      //     "compact": null,
      //     "toJSON": null,
      //     "polluted": true
      //   }
      // };
      // console.log(claims);
      // const str = `{\n  \"sub\": 1,\n  \"scope\": \"user\",\n  \"jti\": \"bafb16ce-20d6-4cd7-9483-65a0958a8e64\",\n  \"iat\": 2537478506,\n  \"exp\": 2537478506,\n  \"__proto__\": {\n    \"compact\": null,\n    \"toJSON\": null,\n    \"polluted\": true\n  }\n}`
      // console.log(nJwt.base64urlEncode(str));

      const str = `{\n  \"typ\": \"JWT\",\n  \"alg\": \"none\",\n  \"__proto__\": {\n    \"typ\": \"JWT\",\n    \"alg\": \"HS256\",\n    \"__proto__\": {\n      \"compact\": null,\n      \"reservedKeys\": [\n        \"typ\",\n        \"random_gibberish\"\n      ]\n    }\n  }\n}`;
      console.log(nJwt.base64urlEncode(str));

      var signingKey = secureRandom(256, {type: 'Buffer'});

      // based on: https://github.com/chrisandoryan/vuln-advisory/blob/main/nJwt/CVE-2024-34273.md#proof-of-concept-poc
      var token = `ewogICJ0eXAiOiAiSldUIiwKICAiYWxnIjogIm5vbmUiLAogICJfX3Byb3RvX18iOiB7CiAgICAidHlwIjogIkpXVCIsCiAgICAiY
      WxnIjogIkhTMjU2IiwKICAgICJfX3Byb3RvX18iOiB7CiAgICAgICJjb21wYWN0IjogbnVsbCwKICAgICAgInJlc2VydmVkS2V5cyI6IFsKICAgICA
      gICAidHlwIiwKICAgICAgICAicmFuZG9tX2dpYmJlcmlzaCIKICAgICAgXQogICAgfQogIH0KfQ.ewogICJ0eXAiOiAiSldUIiwKICAiYWxnIjogIm
      5vbmUiLAogICJfX3Byb3RvX18iOiB7CiAgICAidHlwIjogIkpXVCIsCiAgICAiYWxnIjogIkhTMjU2IiwKICAgICJfX3Byb3RvX18iOiB7CiAgICAg
      ICJjb21wYWN0IjogbnVsbCwKICAgICAgInJlc2VydmVkS2V5cyI6IFsKICAgICAgICAidHlwIiwKICAgICAgICAicmFuZG9tX2dpYmJlcmlzaCIKIC
      AgICAgXQogICAgfQogIH0KfQ`.replaceAll(/\s/g, '');


      console.log(nJwt.JwtBody.prototype);
      console.log(nJwt.JwtHeader.prototype);

      nJwt.verify(token);

      console.log(nJwt.JwtBody.prototype);
      console.log(nJwt.JwtHeader.prototype);
    });
  });

});
