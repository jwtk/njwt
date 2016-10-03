'use strict';

var enums = require('./enums');

function isECDSA(algorithm) {
  return algorithm.indexOf('ES') === 0;
}

function nowEpochSeconds() {
  return Math.floor(new Date().getTime() / 1000);
}

function base64urlEncode(str) {
  return new Buffer(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function base64urlUnescape(str) {
  str += new Array(5 - str.length % 4).join('=');
  return str.replace(/\-/g, '+').replace(/_/g, '/');
}

function isSupportedAlg(alg) {
  return !!enums.algCryptoMap[alg];
}

function handleError(cb, err, value) {
  if (typeof cb === 'function') {
    return process.nextTick(function () {
      cb(err, value);
    });
  } else if (err) {
    throw err;
  }

  return value;
}

function safeJsonParse(input) {
  var result;

  try {
    result = JSON.parse(new Buffer(base64urlUnescape(input), 'base64'));
  } catch (e) {
    return e;
  }

  return result;
}

module.exports = {
  isECDSA: isECDSA,
  nowEpochSeconds: nowEpochSeconds,
  base64urlUnescape: base64urlUnescape,
  base64urlEncode: base64urlEncode,
  isSupportedAlg: isSupportedAlg,
  handleError: handleError,
  safeJsonParse: safeJsonParse
};