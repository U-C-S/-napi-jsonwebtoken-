import test from 'ava';
import { sign as signjwt } from 'jsonwebtoken';
import { JwtAlgorithm, sign } from '../index.js';

test('Compare with jsonwebtoken npm package', (t) => {
  let payload = {
    name: 'John Doe',
    age: '20',
  };
  let secret = 'secret';

  let node = signjwt(payload, secret, {
    algorithm: 'HS256',
  });

  let rust = sign(
    {
      alg: JwtAlgorithm.HS256,
    },
    JSON.stringify(payload),
    secret,
  );

  t.is(node, rust);
});
