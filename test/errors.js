var assert = require('chai').assert;
var errors = require('../errors');

describe('Errors', function () {
  describe('JwtError', function () {
    describe('when creating a new JwtError instance', function () {
      it('should be an instance of Error', function () {
        var error = new errors.JwtError();
        assert.instanceOf(error, Error);
      });

      it('should be an instance of JwtError', function () {
        var error = new errors.JwtError();
        assert.instanceOf(error, errors.JwtError);
      });

      it('should set the message property', function () {
        var fakeMessage = 'c9b9ec16-8c6a-41b8-ba12-eec5bff7d437';
        var error = new errors.JwtError(fakeMessage);
        assert.equal(error.message, fakeMessage);
      });

      it('should set the userMessage property', function () {
        var fakeMessage = '36e4439b-8036-4ce6-af8c-434e6343fca1';
        var error = new errors.JwtError(fakeMessage);
        assert.equal(error.userMessage, fakeMessage);
      });

      it('should set the name property', function () {
        var error = new errors.JwtError();
        assert.equal(error.name, 'JwtError');
      });

      it('should set the message property', function () {
        var fakeMessage = '9ac2400c-22f7-413c-8777-97f2ab2ab266';
        var error = new errors.JwtError(fakeMessage);
        assert.equal(error.message, fakeMessage);
      });
    });
  });

  describe('UnsupportedSigningAlgorithmJwtError', function () {
    describe('when creating a new UnsupportedSigningAlgorithmJwtError instance', function () {
      it('should be an instance of Error', function () {
        var error = new errors.UnsupportedSigningAlgorithmJwtError();
        assert.instanceOf(error, Error);
      });

      it('should be an instance of JwtError', function () {
        var error = new errors.UnsupportedSigningAlgorithmJwtError();
        assert.instanceOf(error, errors.JwtError);
      });

      it('should be an instance of UnsupportedSigningAlgorithmJwtError', function () {
        var error = new errors.UnsupportedSigningAlgorithmJwtError();
        assert.instanceOf(error, errors.UnsupportedSigningAlgorithmJwtError);
      });

      it('should set the name property', function () {
        var error = new errors.UnsupportedSigningAlgorithmJwtError();
        assert.equal(error.name, 'UnsupportedSigningAlgorithmJwtError');
      });

      it('should set the message property', function () {
        var error = new errors.UnsupportedSigningAlgorithmJwtError();
        assert.equal(error.message, 'Unsupported signing algorithm');
      });

      it('should set the userMessage property', function () {
        var error = new errors.UnsupportedSigningAlgorithmJwtError();
        assert.equal(error.userMessage, 'Unsupported signing algorithm');
      });
    });
  });

  describe('SigningKeyRequiredJwtError', function () {
    describe('when creating a new SigningKeyRequiredJwtError instance', function () {
      it('should be an instance of Error', function () {
        var error = new errors.SigningKeyRequiredJwtError();
        assert.instanceOf(error, Error);
      });

      it('should be an instance of JwtError', function () {
        var error = new errors.SigningKeyRequiredJwtError();
        assert.instanceOf(error, errors.JwtError);
      });

      it('should be an instance of SigningKeyRequiredJwtError', function () {
        var error = new errors.SigningKeyRequiredJwtError();
        assert.instanceOf(error, errors.SigningKeyRequiredJwtError);
      });

      it('should set the name property', function () {
        var error = new errors.SigningKeyRequiredJwtError();
        assert.equal(error.name, 'SigningKeyRequiredJwtError');
      });

      it('should set the message property', function () {
        var error = new errors.SigningKeyRequiredJwtError();
        assert.equal(error.message, 'Signing key is required');
      });

      it('should set the userMessage property', function () {
        var error = new errors.SigningKeyRequiredJwtError();
        assert.equal(error.userMessage, 'Signing key is required');
      });
    });
  });

  describe('JwtParseError', function () {
    describe('when creating a new JwtParseError instance', function () {
      it('should be an instance of Error', function () {
        var error = new errors.JwtParseError();
        assert.instanceOf(error, Error);
      });

      it('should be an instance of JwtError', function () {
        var error = new errors.JwtParseError();
        assert.instanceOf(error, errors.JwtError);
      });

      it('should be an instance of JwtParseError', function () {
        var error = new errors.JwtParseError();
        assert.instanceOf(error, errors.JwtParseError);
      });

      it('should set the name property', function () {
        var error = new errors.JwtParseError();
        assert.equal(error.name, 'JwtParseError');
      });

      it('should set the message property', function () {
        var error = new errors.JwtParseError();
        assert.equal(error.message, 'Jwt cannot be parsed');
      });

      it('should set the userMessage property', function () {
        var error = new errors.JwtParseError();
        assert.equal(error.userMessage, 'Jwt cannot be parsed');
      });

      it('should set the jwtString property', function () {
        var fakeJwtString = 'c23a1805-a8de-4829-aa0e-5977fe7e1447';
        var error = new errors.JwtParseError(fakeJwtString);
        assert.equal(error.jwtString, fakeJwtString);
      });

      it('should set the parsedHeader property', function () {
        var fakeParsedHeader = '6764e3a7-ea19-49e7-82e8-7f1e9bbf5ccf';
        var error = new errors.JwtParseError(null, fakeParsedHeader);
        assert.equal(error.parsedHeader, fakeParsedHeader);
      });

      it('should set the parsedBody property', function () {
        var fakeParsedBody = '938fd5d9-72e8-41a7-941a-3df0bcfa88cb';
        var error = new errors.JwtParseError(null, null, fakeParsedBody);
        assert.equal(error.parsedBody, fakeParsedBody);
      });

      it('should set the innerError property', function () {
        var fakeFnnerError = '07bee824-a6a6-45b5-b844-42407466adc7';
        var error = new errors.JwtParseError(null, null, null, fakeFnnerError);
        assert.equal(error.innerError, fakeFnnerError);
      });
    });
  });

  describe('NotActiveJwtParseError', function () {
    describe('when creating a new NotActiveJwtParseError instance', function () {
      it('should be an instance of Error', function () {
        var error = new errors.NotActiveJwtParseError();
        assert.instanceOf(error, Error);
      });

      it('should be an instance of JwtError', function () {
        var error = new errors.NotActiveJwtParseError();
        assert.instanceOf(error, errors.JwtError);
      });

      it('should be an instance of JwtParseError', function () {
        var error = new errors.NotActiveJwtParseError();
        assert.instanceOf(error, errors.JwtParseError);
      });

      it('should be an instance of NotActiveJwtParseError', function () {
        var error = new errors.NotActiveJwtParseError();
        assert.instanceOf(error, errors.NotActiveJwtParseError);
      });

      it('should set the name property', function () {
        var error = new errors.NotActiveJwtParseError();
        assert.equal(error.name, 'NotActiveJwtParseError');
      });

      it('should set the message property', function () {
        var error = new errors.NotActiveJwtParseError();
        assert.equal(error.message, 'Jwt not active');
      });

      it('should set the userMessage property', function () {
        var error = new errors.NotActiveJwtParseError();
        assert.equal(error.userMessage, 'Jwt not active');
      });

      it('should set the jwtString property', function () {
        var fakeJwtString = 'c23a1805-a8de-4829-aa0e-5977fe7e1447';
        var error = new errors.NotActiveJwtParseError(fakeJwtString);
        assert.equal(error.jwtString, fakeJwtString);
      });

      it('should set the parsedHeader property', function () {
        var fakeParsedHeader = '6764e3a7-ea19-49e7-82e8-7f1e9bbf5ccf';
        var error = new errors.NotActiveJwtParseError(null, fakeParsedHeader);
        assert.equal(error.parsedHeader, fakeParsedHeader);
      });

      it('should set the parsedBody property', function () {
        var fakeParsedBody = '938fd5d9-72e8-41a7-941a-3df0bcfa88cb';
        var error = new errors.NotActiveJwtParseError(null, null, fakeParsedBody);
        assert.equal(error.parsedBody, fakeParsedBody);
      });
    });
  });

  describe('ExpiredJwtParseError', function () {
    describe('when creating a new ExpiredJwtParseError instance', function () {
      it('should be an instance of Error', function () {
        var error = new errors.ExpiredJwtParseError();
        assert.instanceOf(error, Error);
      });

      it('should be an instance of JwtError', function () {
        var error = new errors.ExpiredJwtParseError();
        assert.instanceOf(error, errors.JwtError);
      });

      it('should be an instance of JwtParseError', function () {
        var error = new errors.ExpiredJwtParseError();
        assert.instanceOf(error, errors.JwtParseError);
      });

      it('should be an instance of ExpiredJwtParseError', function () {
        var error = new errors.ExpiredJwtParseError();
        assert.instanceOf(error, errors.ExpiredJwtParseError);
      });

      it('should set the name property', function () {
        var error = new errors.ExpiredJwtParseError();
        assert.equal(error.name, 'ExpiredJwtParseError');
      });

      it('should set the message property', function () {
        var error = new errors.ExpiredJwtParseError();
        assert.equal(error.message, 'Jwt is expired');
      });

      it('should set the userMessage property', function () {
        var error = new errors.ExpiredJwtParseError();
        assert.equal(error.userMessage, 'Jwt is expired');
      });

      it('should set the jwtString property', function () {
        var fakeJwtString = 'c23a1805-a8de-4829-aa0e-5977fe7e1447';
        var error = new errors.ExpiredJwtParseError(fakeJwtString);
        assert.equal(error.jwtString, fakeJwtString);
      });

      it('should set the parsedHeader property', function () {
        var fakeParsedHeader = '6764e3a7-ea19-49e7-82e8-7f1e9bbf5ccf';
        var error = new errors.ExpiredJwtParseError(null, fakeParsedHeader);
        assert.equal(error.parsedHeader, fakeParsedHeader);
      });

      it('should set the parsedBody property', function () {
        var fakeParsedBody = '938fd5d9-72e8-41a7-941a-3df0bcfa88cb';
        var error = new errors.ExpiredJwtParseError(null, null, fakeParsedBody);
        assert.equal(error.parsedBody, fakeParsedBody);
      });
    });
  });

  describe('SignatureAlgorithmMismatchJwtParseError', function () {
    describe('when creating a new SignatureAlgorithmMismatchJwtParseError instance', function () {
      it('should be an instance of Error', function () {
        var error = new errors.SignatureAlgorithmMismatchJwtParseError();
        assert.instanceOf(error, Error);
      });

      it('should be an instance of JwtError', function () {
        var error = new errors.SignatureAlgorithmMismatchJwtParseError();
        assert.instanceOf(error, errors.JwtError);
      });

      it('should be an instance of JwtParseError', function () {
        var error = new errors.SignatureAlgorithmMismatchJwtParseError();
        assert.instanceOf(error, errors.JwtParseError);
      });

      it('should be an instance of SignatureAlgorithmMismatchJwtParseError', function () {
        var error = new errors.SignatureAlgorithmMismatchJwtParseError();
        assert.instanceOf(error, errors.SignatureAlgorithmMismatchJwtParseError);
      });

      it('should set the name property', function () {
        var error = new errors.SignatureAlgorithmMismatchJwtParseError();
        assert.equal(error.name, 'SignatureAlgorithmMismatchJwtParseError');
      });

      it('should set the message property', function () {
        var error = new errors.SignatureAlgorithmMismatchJwtParseError();
        assert.equal(error.message, 'Unexpected signature algorithm');
      });

      it('should set the userMessage property', function () {
        var error = new errors.SignatureAlgorithmMismatchJwtParseError();
        assert.equal(error.userMessage, 'Unexpected signature algorithm');
      });

      it('should set the jwtString property', function () {
        var fakeJwtString = 'c23a1805-a8de-4829-aa0e-5977fe7e1447';
        var error = new errors.SignatureAlgorithmMismatchJwtParseError(fakeJwtString);
        assert.equal(error.jwtString, fakeJwtString);
      });

      it('should set the parsedHeader property', function () {
        var fakeParsedHeader = '6764e3a7-ea19-49e7-82e8-7f1e9bbf5ccf';
        var error = new errors.SignatureAlgorithmMismatchJwtParseError(null, fakeParsedHeader);
        assert.equal(error.parsedHeader, fakeParsedHeader);
      });

      it('should set the parsedBody property', function () {
        var fakeParsedBody = '938fd5d9-72e8-41a7-941a-3df0bcfa88cb';
        var error = new errors.SignatureAlgorithmMismatchJwtParseError(null, null, fakeParsedBody);
        assert.equal(error.parsedBody, fakeParsedBody);
      });
    });
  });

  describe('SignatureMismatchJwtParseError', function () {
    describe('when creating a new SignatureMismatchJwtParseError instance', function () {
      it('should be an instance of Error', function () {
        var error = new errors.SignatureMismatchJwtParseError();
        assert.instanceOf(error, Error);
      });

      it('should be an instance of JwtError', function () {
        var error = new errors.SignatureMismatchJwtParseError();
        assert.instanceOf(error, errors.JwtError);
      });

      it('should be an instance of JwtParseError', function () {
        var error = new errors.SignatureMismatchJwtParseError();
        assert.instanceOf(error, errors.JwtParseError);
      });

      it('should be an instance of SignatureMismatchJwtParseError', function () {
        var error = new errors.SignatureMismatchJwtParseError();
        assert.instanceOf(error, errors.SignatureMismatchJwtParseError);
      });

      it('should set the name property', function () {
        var error = new errors.SignatureMismatchJwtParseError();
        assert.equal(error.name, 'SignatureMismatchJwtParseError');
      });

      it('should set the message property', function () {
        var error = new errors.SignatureMismatchJwtParseError();
        assert.equal(error.message, 'Signature verification failed');
      });

      it('should set the userMessage property', function () {
        var error = new errors.SignatureMismatchJwtParseError();
        assert.equal(error.userMessage, 'Signature verification failed');
      });

      it('should set the jwtString property', function () {
        var fakeJwtString = 'c23a1805-a8de-4829-aa0e-5977fe7e1447';
        var error = new errors.SignatureMismatchJwtParseError(fakeJwtString);
        assert.equal(error.jwtString, fakeJwtString);
      });

      it('should set the parsedHeader property', function () {
        var fakeParsedHeader = '6764e3a7-ea19-49e7-82e8-7f1e9bbf5ccf';
        var error = new errors.SignatureMismatchJwtParseError(null, fakeParsedHeader);
        assert.equal(error.parsedHeader, fakeParsedHeader);
      });

      it('should set the parsedBody property', function () {
        var fakeParsedBody = '938fd5d9-72e8-41a7-941a-3df0bcfa88cb';
        var error = new errors.SignatureMismatchJwtParseError(null, null, fakeParsedBody);
        assert.equal(error.parsedBody, fakeParsedBody);
      });
    });
  });
});