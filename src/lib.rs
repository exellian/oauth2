use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fmt;
use crate::util::AsStr;
use std::str::FromStr;
use std::cmp::Ordering;
use std::borrow::Cow;
use std::convert::TryFrom;

mod rfc6749;

/// The server module provides traits and default implementations to create
/// an authorization server1
///
/// # Guide
///
/// To implement an authorization server1 you first have to implement the following traits:
///
/// [OAuth2ClientAuthenticator]
/// [OAuth2State]
mod util;
mod server;

pub enum GrantType<'a> {
    Name(&'a str),
    Uri(uriparse::URI<'a>)
}

pub enum TokenType {
    Bearer
}

pub enum OAuth2ServerResponse<Str, Int> {
    AuthorizationResponse(rfc6749::OAuth2AuthorizationResponse<Str>),
    AuthorizationErrorResponse(rfc6749::OAuth2AuthorizationErrorResponse<Str>),
    SuccessResponse(rfc6749::OAuth2SuccessResponse<Str, Int>),
    ErrorResponse(rfc6749::OAuth2ErrorResponse<Str>),
}

pub struct Scope<Str> {
    scopes: Vec<Str>
}

pub type DynError = Box<dyn Error + Sync + Send>;

#[derive(Debug, Eq, PartialEq, Hash, Copy, Clone)]
pub enum OAuth2AuthorizationError {
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable
}

impl AsStr for TokenType {
    fn as_str(&self) -> &'static str {
        match self {
            TokenType::Bearer => "Bearer"
        }
    }
}

impl TryFrom<&str> for TokenType {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "Bearer" => Ok(TokenType::Bearer),
            _ => Err(())
        }
    }
}

impl AsStr for OAuth2AuthorizationError {
    fn as_str(&self) -> &'static str {
        match self {
            OAuth2AuthorizationError::InvalidRequest => "invalid_request",
            OAuth2AuthorizationError::UnauthorizedClient => "access_denied",
            OAuth2AuthorizationError::AccessDenied => "access_denied",
            OAuth2AuthorizationError::UnsupportedResponseType => "unsupported_response_type",
            OAuth2AuthorizationError::InvalidScope => "invalid_scope",
            OAuth2AuthorizationError::ServerError => "server_error",
            OAuth2AuthorizationError::TemporarilyUnavailable => "temporarily_unavailable"
        }
    }
}
impl Display for OAuth2AuthorizationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Error for OAuth2AuthorizationError {}

#[derive(Debug, Eq, PartialEq, Hash, Copy, Clone)]
pub enum OAuth2Error {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable
}

impl AsStr for OAuth2Error {
    fn as_str(&self) -> &'static str {
        match self {
            OAuth2Error::InvalidRequest => "invalid_request",
            OAuth2Error::InvalidClient => "invalid_client",
            OAuth2Error::InvalidGrant => "invalid_grant",
            OAuth2Error::UnauthorizedClient => "unauthorized_client",
            OAuth2Error::UnsupportedGrantType => "unsupported_grant_type",
            OAuth2Error::InvalidScope => "invalid_scope",
            OAuth2Error::ServerError => "server_error",
            OAuth2Error::TemporarilyUnavailable => "temporarily_unavailable"
        }
    }
}

impl Display for OAuth2Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Error for OAuth2Error {}

impl PartialEq for Scope<Cow<'_, str>> {
    fn eq(&self, other: &Self) -> bool {
        other.scopes.iter().all(|s| self.scopes.contains(s))
    }
}

impl PartialEq for Scope<String> {
    fn eq(&self, other: &Self) -> bool {
        other.scopes.iter().all(|s| self.scopes.contains(s))
    }
}

impl PartialEq for Scope<&str> {
    fn eq(&self, other: &Self) -> bool {
        other.scopes.iter().all(|s| self.scopes.contains(s))
    }
}

impl PartialOrd for Scope<Cow<'_, str>> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.scopes.iter().all(|s| other.scopes.contains(s)) {
            //When self scope tokens are all part from other scope tokens and len is equal
            //then they must be the same because duplicate scopes are not allowed.
            //Otherwise when len is not equal but self scope tokens are all contained in other
            //scope tokens then self must be less
            true => match self.scopes.len() == other.scopes.len() {
                true => Some(Ordering::Equal),
                false => Some(Ordering::Less)
            },
            //Otherwise the self scope tokens must be greater
            false => Some(Ordering::Greater)
        }
    }
}


#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    #[test]
    fn test_url_eq() {

        let mut u = uriparse::URI::try_from("https://a/b/c/%7Bfoo%7D").unwrap();
        let mut u1 = uriparse::URI::try_from("HttPs://a/./b/../b/c/%7bfoo%7d").unwrap();

        u.normalize();
        u1.normalize();

        println!("Uri0: {}", u);
        println!("Uri1: {}", u1);

        assert_eq!(u, u1);

    }

    #[test]
    fn test_split() {
        let str = "sad";
        let tokens = str.split(' ').collect::<Vec<&str>>();
        println!("Tokens: {:?}", tokens);
    }
}