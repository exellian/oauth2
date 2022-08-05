use std::borrow::Cow;
use std::marker::PhantomData;

use crate::{OAuth2ServerResponse, rfc6749, TokenType, Scope};
use crate::util;
use crate::server::internal::OAuth2InternalAuthorizationCodeFlow;

mod internal;
mod default;
mod validation;

pub trait TokenGenerator<D> {
    fn generate(&self) -> Result<Token<D>, ()>;
}

pub struct Token<D> {
    token: String,
    token_type: TokenType,
    valid: D
}

pub struct OAuth2AccessToken<'a> {
    token_type: Cow<'a, str>,
    expires_in: Option<i64>,
    access_token: Cow<'a, str>,
    refresh_token: Option<Cow<'a, str>>,
    scope_tokens: Option<Vec<Cow<'a, str>>>
}

pub struct OAuth2AuthorizationRequest<'a> {
    client_id: &'a str,
    redirect_uri: Option<uriparse::URI<'a>>,
    scope_tokens: Option<Vec<&'a str>>,
    state: Option<&'a str>
}

pub struct OAuth2AccessTokenRequest<'a> {
    client_id: &'a str,
    code: &'a str,
    redirect_uri: Option<uriparse::URI<'a>>
}

pub struct OAuth2TokenRefreshRequest<'a> {
    refresh_token: &'a str,
    scope_tokens: Option<Vec<&'a str>>
}

pub struct OAuth2ValidatedAuthorizationRequest<'a> {
    request: OAuth2AuthorizationRequest<'a>,
}

/// [RFC6749] 4.1.3.  Access Token Request
///
/// The authorization server1 MUST:
///
///    o  require client authentication for confidential clients or for any
///       client that was issued client credentials (or with other
///       authentication requirements),
///
///    o  authenticate the client if client authentication is included,
///
pub struct OAuth2AuthenticatedAccessTokenRequest<'a> {

    /// The authenticated client. If the client is public and doesn't need
    /// authentication, then this value should should be set to None and
    /// the client_id attribute MUST exit on the [Self][request]
    authenticated_client_id: Option<&'a str>,

    /// The underlying [OAuth2AccessTokenRequest] parsed from an request
    request: OAuth2AccessTokenRequest<'a>
}

pub struct OAuth2ValidatedAuthenticatedAccessTokenRequest<'a, C> {
    request: OAuth2AuthenticatedAccessTokenRequest<'a>,
    context: C
}

/// [RFC6749] 6.  Refreshing an Access Token
///
/// The authorization server1 MUST:
///
///    o  require client authentication for confidential clients or for any
///       client that was issued client credentials (or with other
///       authentication requirements),
///
///    o  authenticate the client if client authentication is included and
///       ensure that the refresh token was issued to the authenticated
///       client, and
///
pub struct OAuth2AuthenticatedTokenRefreshRequest<'a> {

    /// The authenticated client. If the client is public and doesn't need
    /// authentication, then this value should should be set to None and
    /// the client_id attribute MUST exit on the [Self][request]
    authenticated_client_id: Option<&'a str>,

    /// The RefreshToken
    request: OAuth2TokenRefreshRequest<'a>
}

pub struct OAuth2ValidatedAuthenticatedTokenRefreshRequest<'a, C> {
    request: OAuth2AuthenticatedTokenRefreshRequest<'a>,
    context: C
}

pub trait OAuth2AuthorizationCodeFlowRequest<'a> :
    TryIntoOAuth2ServerRequest<rfc6749::OAuth2AuthorizationRequest<&'a str>> +
    TryIntoOAuth2ServerRequest<rfc6749::OAuth2AccessTokenRequest<&'a str>> +
    TryIntoOAuth2ServerRequest<rfc6749::OAuth2TokenRefreshRequest<&'a str>>
{}

pub struct OAuth2AuthorizationGrant<'a> {
    scope: Scope<Cow<'a, str>>,
    lifetime: i64,
}

pub struct OAuth2AccessGrant<'a> {
    lifetime: i64,
    refresh_lifetime: Option<i64>,
    scope: Option<Scope<Cow<'a, str>>>
}
pub type OAuth2RefreshGrant<'a> = OAuth2AccessGrant<'a>;

pub trait OAuth2Validate<'a, I, O, R, C1, C2> {
    fn validate(&self, raw: &'a I) -> Result<O, R>;
}

pub trait OAuth2ClientAuthenticate {
    type Request;
    fn authenticate_client<'a>(&self, req: &'a Self::Request) -> Result<Option<&'a str>, ()>;
}

pub trait FromOAuth2ServerResponse {
    fn from_server_response(res: &OAuth2ServerResponse<Cow<str>, i64>) -> Self;
}

pub trait TryIntoOAuth2ServerRequest<R> {
    type Error;
    fn try_into_server_request(&self) -> Result<R, Self::Error>;
}

pub trait OAuth2AuthorizationCodeFlow<R, C1, C2> where
    R: FromOAuth2ServerResponse
{
    type DateTime;

    fn authorize<G>(&self, req: OAuth2ValidatedAuthorizationRequest, grant: Option<OAuth2AuthorizationGrant>, generator: G) -> R where G: TokenGenerator<Self::DateTime>;
    fn token<G, G1>(&self, req: OAuth2ValidatedAuthenticatedAccessTokenRequest<C1>, grant: OAuth2AccessGrant, token_generator: G, refresh_token_generator: Option<G1>) -> R where G: TokenGenerator<Self::DateTime>, G1: TokenGenerator<Self::DateTime>;
    fn refresh<G, G1>(&self, req: OAuth2ValidatedAuthenticatedTokenRefreshRequest<C2>, grant: OAuth2RefreshGrant, generator: G, refresh_token_generator: Option<G1>) -> R where G: TokenGenerator<Self::DateTime>, G1: TokenGenerator<Self::DateTime>;
}

pub trait OAuth2State<C1, C2>: internal::OAuth2InternalState<C1, C2> + OAuth2ClientAuthenticate {

    type Response: FromOAuth2ServerResponse;
    type Grant;
    type DateTime;
}

impl <'a, R, S, C1, C2, D> OAuth2AuthorizationCodeFlow<R, C1, C2> for S where
    R: FromOAuth2ServerResponse,
    S: OAuth2State<C1, C2, Response=R, DateTime=D>,
    S: OAuth2InternalAuthorizationCodeFlow<C1, C2, DateTime=D>
{
    type DateTime = D;

    fn authorize<G>(&self, req: OAuth2ValidatedAuthorizationRequest, grant: Option<OAuth2AuthorizationGrant>, generator: G) -> R  where G: TokenGenerator<Self::DateTime> {

        let state = req.request.state.clone();
        //Validates correct redirect_uri, client_id, scope_tokens according to the registered client
        let code = match internal::OAuth2InternalAuthorizationCodeFlow::authorize::<G>(self, req, grant, generator) {
            Ok(code) => code,
            Err(err) => return R::from_server_response(
                &internal::OAuth2InternalAuthorizationErrorHandler::handle(self, err, state).into()
            )
        };

        //Debug validation
        debug_assert!(util::validate_code(&code).is_ok());

        //Returning a successful response because authorization completed successfully
        //code - The authorization code (g.e. JWS Token not specified here, but specified in a State implementation)
        //state - The exact value (if it is a valid state value) from the request
        R::from_server_response(&OAuth2ServerResponse::AuthorizationResponse(rfc6749::OAuth2AuthorizationResponse {
            code,
            state: state.map(|s| s.into())
        }))
    }

    fn token<G, G1>(&self, req: OAuth2ValidatedAuthenticatedAccessTokenRequest<C1>, grant: OAuth2AccessGrant, token_generator: G, refresh_token_generator: Option<G1>) -> R  where G: TokenGenerator<Self::DateTime>, G1: TokenGenerator<Self::DateTime> {

        //Grants access if the authorization code for given client id is valid and
        //ensures that the "redirect_uri" parameter is present if the "redirect_uri" parameter
        //was included in the initial authorization request as described in [RFC6749] Section 4.1.1,
        //and if included ensure that their values are identical.
        let token = match internal::OAuth2InternalAuthorizationCodeFlow::grant::<G, G1>(self, req, grant, token_generator, refresh_token_generator) {
            Ok(token) => token,
            Err(err) => return R::from_server_response(&internal::OAuth2InternalErrorHandler::handle(self, err, None).into())
        };
        //Serializing of the expires_in field
        let expires_in = token.expires_in;
        //Serializing the scope_tokens into the scope field format [RFC6749] Section 3.3.
        let scope = token.scope_tokens.map(|tokens| tokens.join(" "));

        //Debug validation
        debug_assert!(util::validate_access_token(&token.access_token).is_ok());
        debug_assert!(util::validate_token_type(&token.token_type).is_ok());
        match &token.refresh_token {
            Some(token) => debug_assert!(util::validate_refresh_token(token).is_ok()),
            None => {}
        }
        match &scope {
            Some(scope) => debug_assert!(util::validate_scope(scope).is_ok()),
            None => {}
        }

        R::from_server_response(&OAuth2ServerResponse::SuccessResponse(rfc6749::OAuth2SuccessResponse {
            access_token: token.access_token,
            token_type: token.token_type,
            expires_in,
            refresh_token: token.refresh_token,
            scope: scope.map(|s| s.into())
        }))
    }

    fn refresh<G, G1>(&self, req: OAuth2ValidatedAuthenticatedTokenRefreshRequest<C2>, grant: OAuth2RefreshGrant, token_generator: G, refresh_token_generator: Option<G1>) -> R where G: TokenGenerator<Self::DateTime>, G1: TokenGenerator<Self::DateTime> {

        //Refreshes the token
        //The scope can be a smaller scope than in the original granted authorization response or identical.
        //The client id is the client id of the authentication process or left empty when client is a
        //public client.
        //The refresh implementation requires some type of state (g.e Jwt tokens, database) management,
        //because information about previous authorization requests/responses are necessary to validate that
        //the refresh token was issued to the client and is valid.
        let token = match internal::OAuth2InternalAuthorizationCodeFlow::refresh::<G, G1>(self, req, grant, token_generator, refresh_token_generator) {
            Ok(token) => token,
            Err(err) => return R::from_server_response(&internal::OAuth2InternalErrorHandler::handle(self, err, None).into())
        };
        //Serializing of the expires_in field
        let expires_in = token.expires_in;
        //Serializing the scope_tokens into the scope field format [RFC6749] Section 3.3.
        let scope = token.scope_tokens.map(|tokens| tokens.join(" "));

        //Debug validation
        debug_assert!(util::validate_access_token(&token.access_token).is_ok());
        debug_assert!(util::validate_token_type(&token.token_type).is_ok());
        match &token.refresh_token {
            Some(token) => debug_assert!(util::validate_refresh_token(token).is_ok()),
            None => {}
        }
        match &scope {
            Some(scope) => debug_assert!(util::validate_scope(scope).is_ok()),
            None => {}
        }

        R::from_server_response(&OAuth2ServerResponse::SuccessResponse(rfc6749::OAuth2SuccessResponse {
            access_token: token.access_token,
            token_type: token.token_type,
            expires_in,
            refresh_token: token.refresh_token,
            scope: scope.map(|s| s.into())
        }))
    }
}


impl <C, D> TokenGenerator<D> for C where C: Fn() -> Result<Token<D>, ()> {
    fn generate(&self) -> Result<Token<D>, ()> {
        self()
    }
}
