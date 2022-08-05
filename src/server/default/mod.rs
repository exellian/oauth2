use std::borrow::Cow;
use std::collections::HashMap;
use std::convert::TryFrom;

use crate::{OAuth2AuthorizationError, OAuth2Error, util, Scope, TokenType};
use crate::rfc6749::{OAuth2AuthorizationErrorResponse, OAuth2ErrorResponse};
use crate::server::{internal, OAuth2AccessToken, OAuth2AuthenticatedAccessTokenRequest, OAuth2AuthenticatedTokenRefreshRequest, OAuth2AuthorizationRequest, OAuth2ValidatedAuthenticatedAccessTokenRequest, OAuth2ValidatedAuthenticatedTokenRefreshRequest, OAuth2ValidatedAuthorizationRequest, OAuth2AccessGrant, TokenGenerator, Token, OAuth2AuthorizationGrant, OAuth2RefreshGrant};
use crate::server::internal::{OAuth2InternalAccessTokenRequestValidate, OAuth2InternalAuthorizationRequestValidate, OAuth2InternalTokenRefreshRequestValidate};
use crate::util::AsStr;
use chrono::Utc;

mod http;

type DateTime = chrono::DateTime<chrono::Utc>;

pub trait TokenIssuer {
    fn acquire<G, G1>(&self, grant: AccessGrant, token_generator: G, refresh_token_generator: Option<G1>) -> Result<IssuedToken, ()> where G: TokenGenerator<DateTime>, G1: TokenGenerator<DateTime>;
    fn refresh<G, G1>(&self, grant: RefreshGrant, token_generator: G, refresh_token_generator: Option<G1>) -> Result<IssuedToken, ()> where G: TokenGenerator<DateTime>, G1: TokenGenerator<DateTime>;
    /// Verify that the token was issued and that the token is valid
    fn verify(&self, token: &str) -> Result<AccessGrant, ()>;
    fn verify_refresh(&self, refresh_token: &str) -> Result<RefreshGrant, ()>;
}

pub trait TokenAuthorizer {

    fn acquire(&self, grant: AuthorizationGrant) -> Result<Token<DateTime>, ()>;
    /// Verify that the token was issued and that the token is valid and that
    /// the token is not used twice
    fn release(&self, token: &str) -> Result<AuthorizationGrant, ()>;
}

pub enum Uri {
    Default(String),
    Full(String)
}

pub struct AuthorizationGrant<'a> {
    grant: OAuth2AuthorizationGrant<'a>,
    client_id: Cow<'a, str>,
    redirect_uri: Option<Cow<'a, str>>
}

pub struct AccessGrant<'a> {
    authorization_grant: AuthorizationGrant<'a>,
    grant: OAuth2AccessGrant<'a>
}

pub type RefreshGrant<'a> = AccessGrant<'a>;

pub struct IssuedToken {
    token: Token<DateTime>,
    refresh_token: Option<Token<DateTime>>
}

pub struct Client<C> {
    client_id: String,
    redirect_uris: Vec<Uri>,
    default_uri: Option<String>,
    scopes: Vec<String>,
    default_scope: Option<String>,
    auth_context: C
}



pub struct DefaultInternalState<TA, TI, AC> where
    TA: TokenAuthorizer,
    TI: TokenIssuer
{
    authorization_error_map: Option<HashMap<OAuth2AuthorizationError, String>>,
    error_map: Option<HashMap<OAuth2Error, String>>,
    clients: HashMap<String, Client<AC>>,
    authorizer: TA,
    issuer: TI
}

impl <C> Client<C> {
    fn check_uri(&self, uri: &uriparse::URI) -> bool {
        let normal_uri = uri.to_string();

        let mut normalized = uri.clone();
        normalized.normalize();
        self.redirect_uris.iter().any(|u| {
            match u {
                Uri::Default(u) => {
                    let mut u = uriparse::URI::try_from(u.as_str()).unwrap();
                    u.normalize();
                    u == normalized
                }
                Uri::Full(f) => f == &normal_uri
            }
        })
    }
}

impl <TA, TI, AC> internal::OAuth2InternalState<AuthorizationGrant<'_>, RefreshGrant<'_>> for DefaultInternalState<TA, TI, AC> where
    TA: TokenAuthorizer,
    TI: TokenIssuer
{}

impl <TA, TI, AC> OAuth2InternalAuthorizationRequestValidate for DefaultInternalState<TA, TI, AC> where
    TA: TokenAuthorizer,
    TI: TokenIssuer
{
    fn validate<'a>(&self, req: OAuth2AuthorizationRequest<'a>) -> Result<OAuth2ValidatedAuthorizationRequest<'a>, OAuth2AuthorizationError> {

        let client = match self.clients.get(req.client_id) {
            Some(c) => c,
            None => return Err(OAuth2AuthorizationError::UnauthorizedClient)
        };
        match &req.redirect_uri {
            Some(uri) => match client.check_uri(uri) {
                true => {},
                false => return Err(OAuth2AuthorizationError::InvalidRequest)
            },
            None => match &client.default_uri {
                Some(_) => {},
                None => return Err(OAuth2AuthorizationError::InvalidRequest)
            }
        };
        match &req.scope_tokens {
            Some(tokens) => match tokens.iter().all(|t| client.scopes.iter().any(|s| s == *t)) {
                true => {},
                false => return Err(OAuth2AuthorizationError::InvalidScope)
            }
            None => {}
        };
        Ok(OAuth2ValidatedAuthorizationRequest {
            request: req
        })
    }
}

impl <'b, TA, TI, AC> OAuth2InternalAccessTokenRequestValidate<AuthorizationGrant<'b>> for DefaultInternalState<TA, TI, AC> where
    TA: TokenAuthorizer,
    TI: TokenIssuer
{
    fn validate<'b>(&'b self, req: OAuth2AuthenticatedAccessTokenRequest<'b>) -> Result<OAuth2ValidatedAuthenticatedAccessTokenRequest<'b, AuthorizationGrant<'b>>, OAuth2Error> {
        let client = match self.clients.get(req.request.client_id) {
            Some(c) => c,
            None => return Err(OAuth2Error::InvalidClient)
        };
        let grant = match self.authorizer.release(req.request.code) {
            Ok(g) => g,
            Err(_) => return Err(OAuth2Error::InvalidGrant)
        };
        //Ensure that the authorization code was issued to the client
        match grant.client_id == client.client_id {
            true => {},
            false => return Err(OAuth2Error::InvalidGrant)
        }

        //See [RFC6749] 3.1.2.3.  Dynamic Configuration
        match &grant.redirect_uri {
            Some(uri) => match &req.request.redirect_uri {
                Some(ru) => match &ru.to_string() == uri {
                    true => {},
                    false => return Err(OAuth2Error::InvalidRequest)
                },
                None => return Err(OAuth2Error::InvalidRequest)
            },
            None => match &req.request.redirect_uri {
                Some(_u) => return Err(OAuth2Error::InvalidRequest),
                None => match &client.default_uri {
                    Some(_) => {},
                    None => return Err(OAuth2Error::InvalidRequest)
                }
            }
        };

        Ok(OAuth2ValidatedAuthenticatedAccessTokenRequest {
            request: req,
            context: grant,
        })
    }
}

impl <TA, TI, AC> OAuth2InternalTokenRefreshRequestValidate<RefreshGrant<'_>> for DefaultInternalState<TA, TI, AC> where
    TA: TokenAuthorizer,
    TI: TokenIssuer
{
    fn validate<'a>(&'a self, req: OAuth2AuthenticatedTokenRefreshRequest<'a>) -> Result<OAuth2ValidatedAuthenticatedTokenRefreshRequest<'a, RefreshGrant<'_>>, OAuth2Error> {
        let refresh = match self.issuer.verify_refresh(req.request.refresh_token) {
            Ok(r) => r,
            Err(_) => return Err(OAuth2Error::InvalidGrant)
        };

        match req.authenticated_client_id {
            Some(id) => match id == &refresh.authorization_grant.client_id {
                true => {},
                false => return Err(OAuth2Error::InvalidGrant)
            },
            None => {}
        };

        match &req.request.scope_tokens {
            Some(tokens) => match tokens.iter().all(|t| refresh.authorization_grant.grant.scope.scopes.iter().any(|s| t == s)) {
                true => {},
                false => return Err(OAuth2Error::InvalidScope)
            },
            None => {}
        };
        Ok(OAuth2ValidatedAuthenticatedTokenRefreshRequest {
            request: req,
            context: refresh
        })
    }
}

impl <TA, TI, AC> internal::OAuth2InternalAuthorizationCodeFlow<AuthorizationGrant<'_>, RefreshGrant<'_>> for DefaultInternalState<TA, TI, AC> where
    TA: TokenAuthorizer,
    TI: TokenIssuer
{
    type DateTime = DateTime;

    fn authorize<G>(&self, req: OAuth2ValidatedAuthorizationRequest, grant: Option<OAuth2AuthorizationGrant>, generator: G) -> Result<Cow<str>, OAuth2AuthorizationError> where G: TokenGenerator<Self::DateTime> {

        let grant = match grant {
            Some(grant) => grant,
            None => return Err(OAuth2AuthorizationError::AccessDenied)
        };
        let client = &self.clients[req.request.client_id];

        //Assertions
        assert!(util::check_no_duplicates(&grant.scope.scopes.iter().map(|s| s.as_ref()).collect()));
        assert!(grant.scope.scopes.iter().all(|t| client.scopes.contains(&t.as_ref().to_string())));

        let token = match self.authorizer.acquire(AuthorizationGrant {
            grant,
            client_id: client.client_id.into(),
            redirect_uri: req.request.redirect_uri.map(|u| u.to_string().into())
        }) {
            Ok(g) => g,
            Err(_) => return Err(OAuth2AuthorizationError::ServerError)
        };
        Ok(token.token.into())
    }

    fn grant<'a, G, G1>(&self, req: super::OAuth2ValidatedAuthenticatedAccessTokenRequest<'a, AuthorizationGrant>, grant: OAuth2AccessGrant<'a>, token_generator: G, refresh_token_generator: Option<G1>) -> Result<OAuth2AccessToken<'a>, OAuth2Error> where G: TokenGenerator<Self::DateTime>, G1: TokenGenerator<Self::DateTime> {

        let token = match self.issuer.acquire(AccessGrant {
            authorization_grant: req.context,
            grant
        }, token_generator, refresh_token_generator) {
            Ok(t) => t,
            Err(_) => return Err(OAuth2Error::ServerError)
        };
        let expires_in = token.token.valid - Utc::now();
        Ok(OAuth2AccessToken {
            token_type: token.token.token_type.as_str().into(),
            expires_in: Some(expires_in.num_seconds()),
            access_token: token.token.token.into(),
            refresh_token: token.refresh_token.map(|t| t.token.into()),
            scope_tokens: grant.scope.map(|v| v.scopes)
        })
    }

    fn refresh<'a, G, G1>(&self, req: super::OAuth2ValidatedAuthenticatedTokenRefreshRequest<'a, RefreshGrant>, grant: OAuth2RefreshGrant<'a>, token_generator: G, refresh_token_generator: Option<G1>) -> Result<OAuth2AccessToken<'a>, OAuth2Error> where G: TokenGenerator<Self::DateTime>, G1: TokenGenerator<Self::DateTime> {

        let token = match self.issuer.refresh(RefreshGrant {
            authorization_grant: req.context.authorization_grant,
            grant
        }, token_generator, refresh_token_generator) {
            Ok(t) => t,
            Err(_) => return Err(OAuth2Error::ServerError)
        };
        let expires_in = token.token.valid - Utc::now();
        Ok(OAuth2AccessToken {
            token_type: token.token.token_type.as_str().into(),
            expires_in: Some(expires_in.num_seconds()),
            access_token: token.token.token.into(),
            refresh_token: token.refresh_token.map(|t| t.token.into()),
            scope_tokens: grant.scope.map(|v| v.scopes)
        })
    }
}

impl <TA, TI, AC> internal::OAuth2InternalAuthorizationErrorHandler for DefaultInternalState<TA, TI, AC> where
    TA: TokenAuthorizer,
    TI: TokenIssuer
{
    fn handle<'a>(&'a self, error: OAuth2AuthorizationError, state: Option<&'a str>) -> OAuth2AuthorizationErrorResponse<Cow<'a, str>> {
        let state = state.map(|s| s.into());
        let desc = match error {
            OAuth2AuthorizationError::InvalidRequest => "The request was invalid! Please check your implementation details!",
            OAuth2AuthorizationError::UnauthorizedClient => "Forbidden! Unauthorized request!",
            OAuth2AuthorizationError::AccessDenied => "Access Denied! The request has been denied!",
            OAuth2AuthorizationError::UnsupportedResponseType => "The used response type is unsupported by the server!",
            OAuth2AuthorizationError::InvalidScope => "The requested scope is invalid!",
            OAuth2AuthorizationError::ServerError => "Internal server error!",
            OAuth2AuthorizationError::TemporarilyUnavailable => "The service is temporarily unavailable!"
        };
        let uri = match &self.authorization_error_map {
            Some(m) => m.get(&error).map(|v| v.into()),
            None => None
        };
        OAuth2AuthorizationErrorResponse::new(
            error.as_str().into(),
            Some(desc.into()),
            uri,
            state
        )
    }
}

impl <TA, TI, AC> internal::OAuth2InternalErrorHandler for DefaultInternalState<TA, TI, AC> where
    TA: TokenAuthorizer,
    TI: TokenIssuer
{
    fn handle(&self, error: OAuth2Error, _: Option<&str>) -> OAuth2ErrorResponse<Cow<str>> {
        let desc = match error {
            OAuth2Error::InvalidRequest => "The request was invalid! Please check your implementation details!",
            OAuth2Error::InvalidClient => "The request contained a invalid client!",
            OAuth2Error::InvalidGrant => "The used grant type is invalid!",
            OAuth2Error::UnauthorizedClient => "Forbidden! Unauthorized request!",
            OAuth2Error::UnsupportedGrantType => "The used grant type was not supported!",
            OAuth2Error::InvalidScope => "The requested scope is invalid!",
            OAuth2Error::TemporarilyUnavailable => "The service is temporarily unavailable",
            OAuth2Error::ServerError => "Internal server error!",
        };
        let uri = match &self.error_map {
            Some(m) => m.get(&error).map(|v| v.into()),
            None => None
        };
        OAuth2ErrorResponse::new(
            error.as_str().into(),
            Some(desc.into()),
            uri
        )
    }
}
