use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;

#[derive()]
struct Options {
    algorithm: Algorithm,
    expires_in: i64,
    notBefore: i64,
    Header: Header,
}

#[napi]
pub fn sign(payload: T, secret: U, options: Options) -> Result<String>
where
    T: Serialize,
    U: AsRef<str> + ToString,
{
    let opts = Header {
        alg: options.algorithm,
        typ: todo!(),
        cty: todo!(),
        jku: todo!(),
        jwk: todo!(),
        kid: todo!(),
        x5u: todo!(),
        x5c: todo!(),
        x5t: todo!(),
        x5t_s256: todo!(),
    };
    let secret_key = EncodingKey::from_secret(secret.as_ref());
    encode(options, payload, &secret_key)
}
