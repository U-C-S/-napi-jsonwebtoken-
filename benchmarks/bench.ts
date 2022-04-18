import b from 'benny';

import { sign as signjwt } from 'jsonwebtoken';
import { JwtAlgorithm, sign } from '../mappings';

let payload = {
  age: '20',
  iat: Math.floor(Date.now() / 1000),
  name: 'John Doe',
  exp: 10000000000,
};
let secret = 'secret';

async function run() {
  await b.suite(
    'jsonwebtoken vs rusty-jsonwebtoken',

    b.add('jsonwebtoken', () => {
      signjwt(payload, secret, {
        algorithm: 'HS256',
      });
    }),

    b.add('rusty-jsonwebtoken', () => {
      sign(
        {
          alg: JwtAlgorithm.HS256,
          typ: 'JWT',
        },
        JSON.stringify(payload),
        secret,
      );
    }),

    b.cycle(),
    b.complete(),
  );
}

run().catch((e) => {
  console.error(e);
});
