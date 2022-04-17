use crate::types::{map_header, JwtHeader};
use jsonwebtoken::{encode, EncodingKey};

#[napi]
pub fn sign(header: JwtHeader, payload: String, secret: String) -> String {
    let encode_header = map_header(header);
    let key = &EncodingKey::from_secret(secret.as_bytes());

    encode(&encode_header, &payload, key).unwrap()
}

// use std::collections::HashMap;
// use jsonwebtoken::errors::Result;
// use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
// #[derive()]
// struct Options {
//     algorithm: Algorithm,
//     expires_in: usize,         //exp
//     not_before: Option<usize>, //nbf
//     header: Header,
//     audience: Option<String>, //aud
//     issuer: Option<String>,   //iss
//     jwtid: String,
//     subject: Option<String>, //sub
//     no_timestamp: bool,
//     keyid: Option<String>,
//     mutate_payload: bool,
// }

// fn sign_archive(
//     payload: HashMap<String, String>,
//     secret: String,
//     options: Options,
// ) -> Result<String> {
//     let opts = Header {
//         alg: options.algorithm,
//         typ: Some("JWT".to_string()),
//         cty: None,
//         jku: None,
//         jwk: None,
//         kid: options.keyid,
//         x5u: None,
//         x5c: None,
//         x5t: None,
//         x5t_s256: None,
//     };

//     // payload.insert("exp", options.expires_in);
//     // options.not_before && payload.insert("nbf", options.not_before);
//     // options.audience && payload.insert("aud", options.audience);
//     // options.issuer && payload.insert("iss", options.issuer);
//     // options.subject && payload.insert("sub", options.subject);

//     let secret_key = EncodingKey::from_secret(secret.as_ref());
//     encode(&options.header, &payload, &secret_key)
// }
