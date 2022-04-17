import test from 'ava';
import { sign as signjwt } from 'jsonwebtoken';
import { JwtAlgorithm, sign } from '../index.js';

test('Compare with jsonwebtoken npm package', (t) => {
  let payload = {
    age: '20',
    iat: Math.floor(Date.now() / 1000),
    name: 'John Doe',
  };
  let secret = 'secret';

  let node = signjwt(payload, secret, {
    algorithm: 'HS256',
  });

  let rust = sign(
    {
      alg: JwtAlgorithm.HS256,
      typ: 'JWT',
    },
    JSON.stringify(payload),
    secret,
  );

  t.is(node, rust);
});
