use jsonwebtoken::{Algorithm, Header};
use napi::bindgen_prelude::ToNapiValue;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[napi(object)]
pub struct JwtHeader {
    pub alg: JwtAlgorithm,
    pub cty: Option<String>,
    pub jku: Option<String>,
    // pub jwk: Option<jsonwebtoken::jwk::Jwk>,
    pub kid: Option<String>,
    pub typ: Option<String>,
    pub x5u: Option<String>,
    pub x5c: Option<Vec<String>>,
    pub x5t: Option<String>,
    pub x5t_s256: Option<String>,
}

#[derive(Debug, Serialize)]
#[napi]
pub enum JwtAlgorithm {
    HS256,
    HS384,
    HS512,
    ES256,
    ES384,
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    EdDSA,
}

pub fn map_header(header: JwtHeader) -> Header {
    Header {
        alg: map_algorithm(header.alg),
        cty: header.cty,
        jku: header.jku,
        jwk: None,
        kid: header.kid,
        typ: header.typ,
        x5u: header.x5u,
        x5c: header.x5c,
        x5t: header.x5t,
        x5t_s256: header.x5t_s256,
    }
}

pub fn map_header2(header: Header) -> JwtHeader {
    JwtHeader {
        alg: map_algorithm2(header.alg),
        cty: header.cty,
        jku: header.jku,
        kid: header.kid,
        typ: header.typ,
        x5u: header.x5u,
        x5c: header.x5c,
        x5t: header.x5t,
        x5t_s256: header.x5t_s256,
    }
}

pub fn map_algorithm(algo: JwtAlgorithm) -> Algorithm {
    match algo {
        JwtAlgorithm::HS256 => Algorithm::HS256,
        JwtAlgorithm::HS384 => Algorithm::HS384,
        JwtAlgorithm::HS512 => Algorithm::HS512,
        JwtAlgorithm::ES256 => Algorithm::ES256,
        JwtAlgorithm::ES384 => Algorithm::ES384,
        JwtAlgorithm::RS256 => Algorithm::RS256,
        JwtAlgorithm::RS384 => Algorithm::RS384,
        JwtAlgorithm::RS512 => Algorithm::RS512,
        JwtAlgorithm::PS256 => Algorithm::PS256,
        JwtAlgorithm::PS384 => Algorithm::PS384,
        JwtAlgorithm::PS512 => Algorithm::PS512,
        JwtAlgorithm::EdDSA => Algorithm::EdDSA,
    }
}

pub fn map_algorithm2(algo: Algorithm) -> JwtAlgorithm {
    match algo {
        Algorithm::HS256 => JwtAlgorithm::HS256,
        Algorithm::HS384 => JwtAlgorithm::HS384,
        Algorithm::HS512 => JwtAlgorithm::HS512,
        Algorithm::ES256 => JwtAlgorithm::ES256,
        Algorithm::ES384 => JwtAlgorithm::ES384,
        Algorithm::RS256 => JwtAlgorithm::RS256,
        Algorithm::RS384 => JwtAlgorithm::RS384,
        Algorithm::RS512 => JwtAlgorithm::RS512,
        Algorithm::PS256 => JwtAlgorithm::PS256,
        Algorithm::PS384 => JwtAlgorithm::PS384,
        Algorithm::PS512 => JwtAlgorithm::PS512,
        Algorithm::EdDSA => JwtAlgorithm::EdDSA,
    }
}
