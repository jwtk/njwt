'use strict';

var algCryptoMap = {
  HS256: 'SHA256',
  HS384: 'SHA384',
  HS512: 'SHA512',
  RS256: 'RSA-SHA256',
  RS384: 'RSA-SHA384',
  RS512: 'RSA-SHA512',
  ES256: 'RSA-SHA256',
  ES384: 'RSA-SHA384',
  ES512: 'RSA-SHA512',
  none: 'none'
};

var algTypeMap = {
  HS256: 'hmac',
  HS384: 'hmac',
  HS512: 'hmac',
  RS256: 'sign',
  RS384: 'sign',
  RS512: 'sign',
  ES256: 'sign',
  ES384: 'sign',
  ES512: 'sign'
};

module.exports = {
  algCryptoMap: algCryptoMap,
  algTypeMap: algTypeMap
};