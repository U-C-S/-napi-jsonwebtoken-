import test from 'ava';
import { sign as signjwt } from 'jsonwebtoken';
import { JwtAlgorithm, sign, verify } from '../mappings/index.js';

let payload = {
  age: '20',
  exp: 2000000000,
  iat: 1650555500,
  name: 'JohnDoe',
};
let secret = 'secret';

test('Compare with jsonwebtoken npm package', (t) => {
  let node = signjwt(payload, secret, {
    algorithm: 'HS256',
  });

  let rust = sign(
    {
      alg: JwtAlgorithm.HS256,
      typ: 'JWT',
    },
    payload,
    secret,
  );

  t.is(node, rust);
});

test('Sign and Verify the JWT', (t) => {
  let jwtoken = sign(
    {
      typ: 'JWT',
      alg: JwtAlgorithm.HS256,
    },
    payload,
    secret,
  );

  let decodedInfo = verify(jwtoken, secret, {
    alg: JwtAlgorithm.HS256,
    leeway: 40,
    validateExp: false,
    validateNbf: false,
  });
  let x = JSON.parse(decodedInfo.claims).name;

  t.is(payload.name, x);
});
