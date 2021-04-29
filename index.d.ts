/// <reference types="node" />
import { KeyObject } from 'crypto';

declare type JSONValue = string | number | boolean | null | JSONValue[] | JSONMap;
declare type JSONMap = {[key: string]: JSONValue};

declare interface JwtHeaderOptions {
  alg: string;
  typ?: string;
  kid?: string;
  jku?: string;
  x5c?: string;
  x5u?: string;
  x5t?: string;
  'x5t#s256'?: string;
}

declare type SupportedAlgorithms =
'HS256' |
'HS384' |
'HS512' |
'RS256' |
'RS512' |
'ES256' |
'ES384' |
'ES512' |
'none';

declare type IsSupportedAlg = (algName: string | SupportedAlgorithms) => boolean;
declare type KeyResolverCallback = (err: Error | null, signingKey: string | Buffer) => Jwt | undefined | never;

export declare type KeyResolver = (kid: string, cb: KeyResolverCallback) => Jwt | undefined | never;

export declare function Jwt(claims: JSONMap, enforceDefaultFields: boolean): Jwt;
export declare class Jwt {
  constructor(claims: JSONMap, enforceDefaultFields: boolean);
    header: JwtHeader;
    body: JwtBody;
    setClaim(claim: string, value: JSONValue): Jwt;
    setHeader(param: string, value: string): Jwt;
    setJti(jti: string): Jwt;
    setSubject(sub: string): Jwt;
    setIssuer(iss: string): Jwt;
    setIssuedAt(iat: number): Jwt;
    setExpiration(exp: Date | number | string): Jwt;
    setNotBefore(nbf: Date | number | string): Jwt;
    setSigningKey(key: string | Buffer): Jwt;
    signingKey: string | Buffer;
    setSigningAlgorithm(alg: string): Jwt;
    sign(payload: string | Buffer | JSONMap, algorithm: string, cryptoInput: string | Buffer | KeyObject): string;
    isSupportedAlg: IsSupportedAlg;
    compact(): string;
    signature: string;
    toString(): string;
    isExpired(): boolean;
    isNotBefore(): boolean;
}
export declare function JwtBody(claims: JSONMap): JwtBody;
export declare class JwtBody {
  constructor(claims: JSONMap);
  toJSON(): JSONMap;
  compact(): string;
}
export declare function JwtHeader(header: JwtHeaderOptions): JwtHeader;
export declare class JwtHeader {
  constructor(header: JwtHeaderOptions);
    typ: string;
    alg: string;
    reservedKeys: string[];
    compact(): string;
}

export declare function Verifier(): Verifier;
export declare class Verifier {
  setSigningAlgorithm(alg: string): Verifier | never;
  signingAlgorithm: SupportedAlgorithms;
  setSigningKey(keyStr: string | Buffer): Verifier;
  signingKey: string | Buffer;
  setKeyResolver(keyResolver: KeyResolver): void;
  keyResolver: KeyResolver;
  isSupportedAlg: IsSupportedAlg;
  /**
   * Synchronous mode.
   */
  verify(jwtString: string | Buffer): Jwt | never;
  /**
   * Async mode.
   */
  verify(jwtString: string | Buffer, cb: (err: Error | null, verifiedJwt: Jwt) => void): void | never;
  withKeyResolver(keyResolver: KeyResolver): Verifier;
}
export declare function base64urlEncode(number: number | string): Buffer;
export declare function base64urlUnescape(str: string): string;
export declare function verify(jwtTokenString: string | Buffer, signingKey?: string | Buffer, alg?: string, callback?: KeyResolver):  undefined | Jwt | never;
export declare function createVerifier(): Verifier;
export declare function create(claimsOrSecret: JSONMap | string | Buffer, ...args: unknown[]): Jwt;
