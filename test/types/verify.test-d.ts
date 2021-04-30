/* eslint-disable no-unused-vars */

import { Jwt, Verifier, verify, createVerifier } from 'njwt';
import { expectType, expectError } from 'tsd';

expectType<Verifier>(Verifier());
const verifier = new Verifier();
expectType<Verifier>(verifier.setSigningAlgorithm('none'));

expectType<void>(verifier.setKeyResolver(function (keyId: string, callback: (err: Error | null, resolvedKey: string) => Jwt | undefined) {
  return callback(null, 'resolvedKey');
}));

// eslint-disable-next-line @typescript-eslint/no-unused-vars
expectType<void>(verifier.setKeyResolver(function (keyId: string, callback: (err: Error | null, resolvedKey: string) => Jwt | undefined) {
  throw new Error();
}));

expectType<Verifier>(verifier.withKeyResolver(function (keyId: string, callback: (err: Error | null, resolvedKey: string) => Jwt | undefined) {
  return callback(null, 'resolvedKey');
}));

// callback signature is enforced
expectError<Verifier>(verifier.withKeyResolver(function (keyId: string, callback: (err: string | null, resolvedKey: string) => Jwt | undefined) {
  return callback(null, 'resolvedKey');
}));

expectType<Verifier>(verifier.setSigningKey(Buffer.from([])));

expectType<Jwt>(verifier.verify('tokenString'));
expectType<void>(verifier.verify('tokenString', function (err: Error | null, token: Jwt) {
  console.log(token);
}));

expectType<Jwt | undefined>(verify(Buffer.from('tokenString')));
expectType<Verifier>(createVerifier());
