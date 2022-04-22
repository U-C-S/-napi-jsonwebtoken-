use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::Serialize;
use serde_json::Value;

use crate::{
    common::throw_napi_error,
    types::{map_algorithm, map_header2, JwtAlgorithm, JwtHeader},
};


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
    pub claims: Value,
}

#[napi]
pub fn verify(token: String, secret: String, options: VerifyOptions) -> napi::Result<Decoded> {
    let key = DecodingKey::from_secret(secret.as_ref());

    let mut validation_opts = Validation::new(map_algorithm(options.alg));
    // validation_opts.aud = options.aud;
    // validation_opts.iss = options.iss;
    // validation_opts.sub = options.sub;
    // validation_opts.leeway = options.leeway;
    // validation_opts.validate_exp = options.validate_exp;
    // validation_opts.validate_nbf = options.validate_nbf;
    // options.required_spec_claims
    //     && validation_opts.set_required_spec_claims(&options.required_spec_claims.unwrap());

    let tokendata = match decode::<Value>(&token, &key, &validation_opts) {
        Ok(tokendata) => tokendata,
        Err(err) => return throw_napi_error(napi::Status::Unknown, &err.to_string()),
    };

    napi::Result::Ok(Decoded {
        header: map_header2(tokendata.header),
        claims: tokendata.claims,
    })
}
