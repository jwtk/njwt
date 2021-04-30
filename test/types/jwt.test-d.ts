import { Jwt, JwtBody, JwtHeader, create, JSONMap, base64urlEncode, base64urlUnescape } from 'njwt';
import { expectType, expectError } from 'tsd';


expectType<Jwt>(Jwt({}, false));
expectType<Jwt>(new Jwt({}, false));
expectType<Jwt>(create({}));
expectType<Jwt>(create({}, 'signingKey'));
expectType<Jwt>(create('signingKey'));
expectType<Jwt>(create(Buffer.from([])));

const jwt = new Jwt({}, true);
expectType<string>(jwt.sign({}, 'alg', 'signingKeyValue'));
expectType<Jwt>(jwt.setHeader('headerParam', 'headerValue'));
expectType<Jwt>(jwt.setIssuedAt(123456));
expectType<Jwt>(jwt.setIssuer('atko'));
expectType<Jwt>(jwt.setJti('uuid'));
expectType<Jwt>(jwt.setNotBefore(new Date()));
expectType<Jwt>(jwt.setSigningAlgorithm('sha'));
expectType<Jwt>(jwt.setSigningKey(Buffer.from([])));
expectType<Jwt>(jwt.setSubject('userid'));
expectType<string>(jwt.toString());

const jwtBody = new JwtBody({});
expectType<string>(jwtBody.compact());
expectType<JSONMap>(jwtBody.toJSON());

const jwtHeader = new JwtHeader({alg: 'HS256'});
expectType<string>(jwtHeader.compact());

// alg property is required
expectError(new JwtHeader({}));

expectType<Buffer>(base64urlEncode('atob'));
expectType<string>(base64urlUnescape('btoa=='));
