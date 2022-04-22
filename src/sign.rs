use crate::{
    common::throw_napi_error,
    types::{map_header, JwtHeader},
};
use jsonwebtoken::{encode, EncodingKey};
use serde_json::Value;

#[napi]
pub fn sign(header: JwtHeader, payload: Value, secret: String) -> napi::Result<String> {
    let header = map_header(header);
    let key = EncodingKey::from_secret(secret.as_ref());

    if !(payload.is_object() || payload.is_string()) {
        return throw_napi_error(
            napi::Status::InvalidArg,
            "Payload must be an object or string",
        );
    }

    match encode(&header, &payload, &key) {
        Ok(token) => napi::Result::Ok(token),
        Err(err) => throw_napi_error(napi::Status::Unknown, &err.to_string()),
    }
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

#[cfg(test)]
pub mod tests {
    use crate::{
        sign::sign,
        types::{map_header, JwtAlgorithm, JwtHeader},
    };
    use jsonwebtoken::{encode, EncodingKey};
    use serde::Serialize;

    #[derive(Debug, Serialize, Clone)]
    struct Claims {
        pub age: String,
        pub exp: usize,
        pub iat: usize,
        pub name: String,
    }

    #[test]
    fn test_sign() {
        let jwtheader = JwtHeader {
            alg: JwtAlgorithm::HS256,
            cty: None,
            jku: None,
            kid: None,
            typ: Some("JWT".to_string()),
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
        };
        let header2 = map_header(jwtheader.clone());

        let payload = Claims {
            age: "20".to_string(),
            exp: 2000000000,
            iat: 1650555500,
            name: "JohnDoe".to_string(),
        };
        let payload2 = payload.serialize(serde_json::value::Serializer).unwrap();

        let secret_string = "baka".to_string();
        let secret_key = EncodingKey::from_secret(secret_string.as_ref());

        let token1 = encode(&header2, &payload, &secret_key).unwrap();
        let token2 = sign(jwtheader, payload2, secret_string).unwrap();

        println!("\n- {}\n- {}", &token1, &token2);

        assert_eq!(token1, token2, "Tokens are not equal");
    }
}
