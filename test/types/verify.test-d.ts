import { Verifier } from 'njwt';
import { expectType } from 'tsd';

const verifier = new Verifier();
expectType<Verifier>(verifier);

expectType<Verifier>(verifier.setSigningAlgorithm('none'));
