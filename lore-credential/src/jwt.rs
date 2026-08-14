// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use jsonwebtoken::TokenData;
use lore_base::lore_debug;
use lore_error_set::prelude::*;
use serde::Deserialize;
use serde_with::OneOrMany;
use serde_with::formats::PreferMany;
use serde_with::serde_as;

use crate::token_store::IdentityToken;

#[derive(Debug, Default, Clone)]
pub struct UserInfo {
    pub id: String,
    pub name: String,
    pub token: String,
    pub preferred_username: String,
    pub is_service_account: bool,
    pub expires: u64,
}

// An AuthN or an AuthZ token
#[serde_as]
#[derive(Debug, Deserialize, Clone)]
pub struct JWTUserInfo {
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "sub")]
    pub user_id: String,
    pub name: String,
    pub preferred_username: Option<String>,
    pub is_service_account: Option<bool>,
    #[serde(rename = "exp")]
    pub expires: u64,
    #[serde_as(as = "OneOrMany<_, PreferMany>")]
    #[serde(rename = "aud")]
    pub audience: Vec<String>,
}

impl JWTUserInfo {
    /// All the root domains this token are intended for
    pub fn acceptable_root_domains(&self) -> Vec<String> {
        [
            // Whoever issued it already knows about the token and thus
            // the token can be given back to that endpoint.
            std::slice::from_ref(&self.issuer),
            // The Auth Service defines audienes as a list of root domains
            self.audience.as_slice(),
        ]
        .concat()
    }
}

pub async fn user_info<P>(auth_url: &str, identity: &str, token_filter: P) -> Option<UserInfo>
where
    P: FnMut(&&IdentityToken) -> bool,
{
    lore_debug!("Get user {identity} info from {auth_url}");

    let Ok(token) = crate::token_store::load_user_token(auth_url, identity, token_filter).await
    else {
        return None;
    };

    user_info_from_token(token)
}

pub fn insecure_decode_token(
    token: &str,
) -> Result<TokenData<JWTUserInfo>, jsonwebtoken::errors::Error> {
    jsonwebtoken::dangerous::insecure_decode(token)
}

pub fn user_info_from_token(token: String) -> Option<UserInfo> {
    let Ok(token_data) = insecure_decode_token(&token) else {
        return None;
    };
    Some(UserInfo {
        id: token_data.claims.user_id.clone(),
        name: token_data.claims.name.clone(),
        token,
        preferred_username: token_data.claims.preferred_username.unwrap_or_default(),
        is_service_account: token_data.claims.is_service_account.unwrap_or_default(),
        // JWT has number of seconds since UNIX epoch in UTC - we want milliseconds like
        // all other timestamps in Lore, also in UTC
        expires: token_data.claims.expires * 1000,
    })
}

#[error_set]
pub enum JwtUsageError {}

pub fn domain_in_root_domains(domain: &str, root_domains: &[String]) -> bool {
    root_domains
        .iter()
        .any(|acceptable_root| domain.ends_with(acceptable_root))
}

pub fn verify_jwt_usage_for_remote(
    jwt: &JWTUserInfo,
    remote_domain: &str,
) -> Result<(), JwtUsageError> {
    let root_domains = jwt.acceptable_root_domains();
    if domain_in_root_domains(remote_domain, &root_domains) {
        return Ok(());
    }

    lore_debug!(
        "JWT acceptable domains '{root_domains:?}' does not contain '{remote_domain}' - forbidding JWT leak"
    );
    Err(JwtUsageError::internal(format!(
        "JWT 'aud' does not specify remote domain '{remote_domain}'"
    )))
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::*;

    fn unsigned_token(payload: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        format!("{header}.{payload}.signature-is-intentionally-not-verified")
    }

    #[test]
    fn insecure_decode_parses_the_claim_shape_without_verifying_the_signature() {
        let token = unsigned_token(
            r#"{"iss":"https://auth.example","sub":"user-1","name":"User One","preferred_username":"user","exp":42,"aud":"example"}"#,
        );
        let decoded = insecure_decode_token(&token).unwrap();
        assert_eq!(decoded.claims.user_id, "user-1");
        assert_eq!(decoded.claims.expires, 42);
        assert_eq!(decoded.claims.audience, ["example"]);
    }

    #[test]
    fn malformed_standard_claim_types_are_rejected() {
        let token = unsigned_token(
            r#"{"iss":"https://auth.example","sub":"user-1","name":"User One","exp":"never","aud":"example"}"#,
        );
        assert!(insecure_decode_token(&token).is_err());
    }
}
