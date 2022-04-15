use std::collections::HashMap;

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;

#[derive()]
struct Options {
    algorithm: Algorithm,
    expires_in: usize,         //exp
    not_before: Option<usize>, //nbf
    header: Header,
    audience: Option<String>, //aud
    issuer: Option<String>,   //iss
    jwtid: String,
    subject: Option<String>, //sub
    no_timestamp: bool,
    header: String,
    keyid: Option<String>,
    mutate_payload: bool,
}

struct payload {
    // have any fields
}

#[napi]
pub fn sign(payload: HashMap<String, _>, secret: String, options: Options) -> Result<String>
where
    T: Serialize + ToString,
{
    let opts = Header {
        alg: options.algorithm,
        typ: Ok("JWT".to_string()),
        cty: todo!(),
        jku: todo!(),
        jwk: todo!(),
        kid: options.keyid,
        x5u: None,
        x5c: None,
        x5t: None,
        x5t_s256: None,
    };

    payload.insert("exp", options.expires_in);
    options.notBefore && payload.insert("nbf", options.not_before);
    options.audience && payload.insert("aud", options.audience);
    options.issuer && payload.insert("iss", options.issuer);
    options.subject && payload.insert("sub", options.subject);

    let secret_key = EncodingKey::from_secret(secret.as_ref());
    encode(&options.header, &payload, &secret_key)
}
