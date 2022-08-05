use std::borrow::Cow;
use crate::{
    OAuth2ServerResponse,
    OAuth2AuthorizationError,
    OAuth2Error
};
use crate::rfc6749;
use crate::server::{OAuth2AccessToken, OAuth2AuthorizationRequest, OAuth2AuthenticatedAccessTokenRequest, OAuth2AuthenticatedTokenRefreshRequest, OAuth2ValidatedAuthenticatedAccessTokenRequest, OAuth2ValidatedAuthenticatedTokenRefreshRequest, OAuth2ValidatedAuthorizationRequest, TokenGenerator, OAuth2AuthorizationGrant, OAuth2AccessGrant, OAuth2RefreshGrant};

/// This abstract trait is used for all state relevant implementations of an oauth2 authorization server1.
/// It provides all methods which require some sort of state implementation,
/// because in oauth2 flows information about previous steps is often required
/// to validate next steps.
///
/// Please additionally implement [OAuth2InternalAuthorizationCodeFlowValidate] to enable validation.
/// (Can't be required here because )
pub trait OAuth2InternalState<C1, C2>: OAuth2InternalAuthorizationErrorHandler + OAuth2InternalErrorHandler + OAuth2InternalAuthorizationCodeFlow<C1, C2> {
}

//Validation for requests

pub trait OAuth2InternalAuthorizationRequestValidate {
    fn validate<'a>(&'a self, req: OAuth2AuthorizationRequest<'a>) -> Result<OAuth2ValidatedAuthorizationRequest<'a>, OAuth2AuthorizationError>;
}

pub trait OAuth2InternalAccessTokenRequestValidate<C1> {
    fn validate<'a>(&'a self, req: OAuth2AuthenticatedAccessTokenRequest<'a>) -> Result<OAuth2ValidatedAuthenticatedAccessTokenRequest<'a, C1>, OAuth2Error>;
}

pub trait OAuth2InternalTokenRefreshRequestValidate<C2> {
    fn validate<'a>(&'a self, req: OAuth2AuthenticatedTokenRefreshRequest<'a>) -> Result<OAuth2ValidatedAuthenticatedTokenRefreshRequest<'a, C2>, OAuth2Error>;
}

pub trait OAuth2InternalAuthorizationErrorHandler where {
    fn handle<'a>(&'a self, error: OAuth2AuthorizationError, state: Option<&'a str>) -> rfc6749::OAuth2AuthorizationErrorResponse<Cow<'a, str>>;
}

pub trait OAuth2InternalErrorHandler where {
    fn handle<'a>(&'a self, error: OAuth2Error, state: Option<&'a str>) -> rfc6749::OAuth2ErrorResponse<Cow<'a, str>>;
}

pub trait OAuth2InternalAuthorizationCodeFlow<C1, C2> : OAuth2InternalAuthorizationRequestValidate + OAuth2InternalAccessTokenRequestValidate<C1> + OAuth2InternalTokenRefreshRequestValidate<C2> {

    type DateTime;

    /// Returns a authorization code when a successful grant happens.
    /// Additionally lifetime, rate-limit and granted scope information is stored.
    /// Can return an authorization error, when rate-limit exceeded, redirect_uri invalid, scope invalid.
    ///
    /// # Arguments
    ///
    /// * client_id - A string representing the client id
    /// * scope_tokens - The desired scope that should be granted access or default or error
    /// * redirect_uri - The redirect_uri if multiple redirect_uris specified by the client,
    ///                 see [RFC6749] Section 3.1.2.3.
    ///
    fn authorize<G>(&self, req: super::OAuth2ValidatedAuthorizationRequest, grant: Option<OAuth2AuthorizationGrant>, generator: G) -> Result<Cow<str>, OAuth2AuthorizationError> where G: TokenGenerator<Self::DateTime>;

    /// Returns a valid access token when the authorization code, redirect uri and client id are valid.
    /// Ensures that the "redirect_uri" parameter is present if the "redirect_uri" parameter
    /// was included in the initial authorization request as described in [RFC6749] Section 4.1.1,
    /// and if included ensure that their values are identical.
    /// # Arguments
    ///
    /// * code - The authorization code which issued to the client
    /// * client_id - Client id of the authenticated client or the client id of the public client
    /// * redirect_uri - Gets checked if it was included in the original authorization
    ///     request and if the values are identical
    ///
    fn grant<'a, G, G1>(&self, req: super::OAuth2ValidatedAuthenticatedAccessTokenRequest<'a, C1>, grant: OAuth2AccessGrant<'a>, token_generator: G, refresh_token_generator: Option<G1>) -> Result<OAuth2AccessToken<'a>, OAuth2Error> where G: TokenGenerator<Self::DateTime>, G1: TokenGenerator<Self::DateTime>;

    /// Returns a new valid access token and optionally also a new refresh token.
    ///
    /// # Arguments
    ///
    /// * refresh_token - The refresh token that was previously issued to the client
    /// * scope_tokens - A new smaller scope or the identical old scope that was granted in the access token response.
    ///                 If omitted than it is treated as the same scope that was originally granted by the resource
    ///                 owner.
    /// * client_id - The client id of an authenticated client. If present the implementor has to make sure that the
    ///              refresh token was issued to the client id.
    /// * token_generator - A closure or value that impl TokenGenerator that generates a access token
    fn refresh<'a, G, G1>(&self, req: super::OAuth2ValidatedAuthenticatedTokenRefreshRequest<'a, C2>, grant: OAuth2RefreshGrant<'a>, token_generator: G, refresh_token_generator: Option<G1>) -> Result<OAuth2AccessToken<'a>, OAuth2Error> where G: TokenGenerator<Self::DateTime>, G1: TokenGenerator<Self::DateTime>;
}

impl <'a> Into<OAuth2ServerResponse<Cow<'a, str>, i64>> for rfc6749::OAuth2AuthorizationErrorResponse<Cow<'a, str>> {
    fn into(self) -> OAuth2ServerResponse<Cow<'a, str>, i64> {
        OAuth2ServerResponse::AuthorizationErrorResponse(self)
    }
}

impl <'a> Into<OAuth2ServerResponse<Cow<'a, str>, i64>> for rfc6749::OAuth2ErrorResponse<Cow<'a, str>> {
    fn into(self) -> OAuth2ServerResponse<Cow<'a, str>, i64> {
        OAuth2ServerResponse::ErrorResponse(self)
    }
}