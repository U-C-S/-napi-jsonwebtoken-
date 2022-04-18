// use std::collections::HashSet;
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::Serialize;
use serde_json::Value;

use crate::types::{map_algorithm, map_header2, JwtAlgorithm, JwtHeader};

// #[derive(Debug, Deserialize, Serialize)]
// #[napi(object)]
// pub struct Claims {
//     pub exp: u32,
//     pub nbf: u32,
//     pub aud: String,
//     pub iss: String,
//     pub sub: String,
// }

// #[derive(Debug)]
#[napi(object)]
pub struct VerifyOptions {
    pub required_spec_claims: Option<Vec<String>>,
    pub leeway: u32,
    pub validate_exp: bool,
    pub validate_nbf: bool,
    pub aud: Option<String>,
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub alg: JwtAlgorithm,
}

#[derive(Serialize)]
#[napi(object)]
pub struct Decoded {
    pub header: JwtHeader,
    pub claims: String,
}

#[napi]
pub fn verify(token: String, secret: String, options: VerifyOptions) -> Decoded {
    // let validation_opts = Validation {
    //     required_spec_claims: HashSet::new(),
    //     leeway: 60,
    //     validate_exp: true,
    //     validate_nbf: true,
    //     aud: None,
    //     iss: None,
    //     sub: None,
    //     algorithms: vec![Algorithm::HS256],
    //     // validate_signature: false,
    // };

    let validation_opts = Validation::new(map_algorithm(options.alg));
    // validation_opts.aud = options.aud;
    // validation_opts.iss = options.iss;
    // validation_opts.sub = options.sub;
    // validation_opts.leeway = options.leeway;
    // validation_opts.validate_exp = options.validate_exp;
    // validation_opts.validate_nbf = options.validate_nbf;
    // options.required_spec_claims
    //     && validation_opts.set_required_spec_claims(&options.required_spec_claims.unwrap());

    let tokendata = decode::<Value>(
        &token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation_opts,
    )
    .unwrap();

    Decoded {
        header: map_header2(tokendata.header),
        claims: serde_json::to_string(&tokendata.claims).unwrap(),
    }
}
