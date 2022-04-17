// use std::collections::HashSet;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::types::JwtAlgorithm;

#[derive(Debug, Deserialize, Serialize)]
#[napi(object)]
pub struct Claims {
    pub exp: u32,
    pub nbf: u32,
    pub aud: String,
    pub iss: String,
    pub sub: String,
}

// #[derive(Debug)]
#[napi(object)]
pub struct VerifyOptions {
    pub leeway: u32,
    pub validate_exp: bool,
    pub validate_nbf: bool,
    pub aud: Option<String>,
    // pub audience: Option<String>,
    // pub issuer: Option<String>,
    // pub subject: Option<String>,
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub alg: JwtAlgorithm,
}

#[napi]
pub fn verify(token: String, secret: String, options: VerifyOptions) -> Claims {
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

    let validation_opts = Validation::new(Algorithm::HS256);

    let tokendata = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation_opts,
    );
    tokendata.unwrap().claims
}
