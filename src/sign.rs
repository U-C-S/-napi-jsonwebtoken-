use crate::types::{map_header, JwtHeader};
use jsonwebtoken::{encode, EncodingKey};
use serde_json::Value;

#[napi]
pub fn sign(header: JwtHeader, payload: String, secret: String) -> String {
    let encode_header = map_header(header);
    let claims: Value = serde_json::from_str(&payload).unwrap();
    let key = &EncodingKey::from_secret(secret.as_bytes());

    encode(&encode_header, &claims, key).unwrap()
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
    use std::fs;

    use crate::{
        sign::sign,
        types::{map_header, JwtAlgorithm, JwtHeader},
    };
    use jsonwebtoken::{encode, EncodingKey};
    use serde::Serialize;

    #[derive(Debug, Serialize)]
    struct Claims {
        pub age: String,
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
            iat: 1650201983,
            name: "John Doe".to_string(),
        };
        let payload2 = serde_json::to_string(&payload).unwrap();

        let secret_string = "secret".to_string();
        let secret_key = EncodingKey::from_secret(secret_string.as_ref());

        let token1 = encode(&header2, &payload, &secret_key).unwrap();
        let token2 = sign(jwtheader, payload2, secret_string);

        // let mut lolly = token1.clone();
        // lolly.push_str(" ");
        // lolly.push_str(&token2);
        // fs::write("token1.txt", lolly).unwrap();
        // println!("\n- {}\n- {}", token1, token2);

        assert_eq!(token1, token2, "Tokens are not equal");
    }
}
