use crate::server::{OAuth2Validate, OAuth2AuthorizationRequest, OAuth2AuthorizationCodeFlowRequest, FromOAuth2ServerResponse, OAuth2State, internal, TryIntoOAuth2ServerRequest, OAuth2AuthenticatedAccessTokenRequest, OAuth2ClientAuthenticate, OAuth2AuthenticatedTokenRefreshRequest, OAuth2AccessTokenRequest, OAuth2TokenRefreshRequest, OAuth2ValidatedAuthenticatedAccessTokenRequest, OAuth2ValidatedAuthorizationRequest, OAuth2ValidatedAuthenticatedTokenRefreshRequest};
use crate::{util, OAuth2AuthorizationError, OAuth2ServerResponse, rfc6749, OAuth2Error};
use std::borrow::Cow;
use crate::server::internal::{OAuth2InternalAuthorizationRequestValidate, OAuth2InternalAccessTokenRequestValidate, OAuth2InternalTokenRefreshRequestValidate};

fn validate_attribute<'a, 'b, S, H, E, R, F, V, I, C1, C2>(this: &'a S, val: Option<I>, err: E, handler: H, state: Option<&'a str>, predicate: F) -> Result<Option<V>, OAuth2ServerResponse<Cow<'a, str>, i64>> where
    S: internal::OAuth2InternalState<C1, C2>,
    R: Into<OAuth2ServerResponse<Cow<'a, str>, i64>>,
    H: Fn(&'a S, E, Option<&'a str>) -> R,
    F: Fn(I) -> Result<V, ()>
{
    match val {
        Some(v) => match predicate(v) {
            Ok(res) => Ok(Some(res)),
            Err(_) => Err(handler(this, err, state).into())
        },
        None => Ok(None)
    }
}

impl <'a, I, R, S, C1, C2> OAuth2Validate<'a, I, OAuth2ValidatedAuthorizationRequest<'a>, R, C1, C2> for S where
    I: OAuth2AuthorizationCodeFlowRequest<'a>,
    R: FromOAuth2ServerResponse,
    S: OAuth2State<C1, C2, Request=I, Response=R>,
    S: OAuth2InternalAuthorizationRequestValidate,
{

    /// Returns a Response which can be a successful [OAuth2AuthorizationResponse] or an
    /// non successful [OAuth2AuthorizationErrorResponse] serialized in a Response of the underlying
    /// request/response framework.
    /// Typically the response gets serialized in the query params of a http response.
    ///
    /// Additionally this function performs syntax validation of the individual attributes
    /// according to the [RFC6749] Appendix A. Section.
    ///
    /// It also validates the simple semantic validation of the [OAuth2AuthorizationRequest][response_type].
    /// (It ensures that this value is equal to "code").
    ///
    /// The underlying function [OAuth2State][grant_scope] must ensure that:
    ///
    ///     o client_id - is a valid registered client
    ///
    ///     o scope_tokens - are valid scopes and that the resource-owner granted access to these scopes
    ///
    ///     o redirect_uri - If multiple redirection URIs have been registered, if only part of
    ///         the redirection URI has been registered, or if no redirection URI has
    ///         been registered, the client MUST include the redirect_uri. See [RFC6749] 3.1.2.3.
    ///
    /// # Arguments
    ///
    /// *req - The incoming authorization request that is deserialized into a [OAuth2AuthorizationRequest].
    ///        BEFORE the call of this the request MUST be checked for:
    ///
    ///             o required and non required fields,
    ///
    ///             o fields MUST NOT be included more than once
    ///
    ///             o unrecognized request parameters MUST be ignored.
    ///
    ///         See [RFC6749] 3.1.
    ///         On the other side semantic- and syntax-validation will be performed by this function
    ///         and should not be performed BEFORE.
    ///
    /// # Notes
    ///
    /// o The authorization endpoint is used to interact with the resource
    ///     owner and obtain an authorization grant. The authorization server1
    ///     MUST first verify the identity of the resource owner. The way in
    ///     which the authorization server1 authenticates the resource owner
    ///     (e.g., username and password login, session cookies) is beyond the
    ///     scope of the oauth2 specification.
    ///
    /// o Since requests to the authorization endpoint result in user
    ///     authentication and the transmission of clear-text credentials (in the
    ///     HTTP response), the authorization server1 MUST require the use of TLS
    ///     as described in Section 1.6 when sending requests to the
    ///     authorization endpoint.
    ///
    /// o The authorization server1 MUST support the use of the HTTP "GET"
    ///     method [RFC2616] for the authorization endpoint and MAY support the
    ///     use of the "POST" method as well.
    ///
    fn validate(&self, raw: &'a I) -> Result<OAuth2ValidatedAuthorizationRequest<'a>, R> {
        let req: Result<rfc6749::OAuth2AuthorizationRequest<&str>, _> = TryIntoOAuth2ServerRequest::try_into_server_request(raw);
        let req: rfc6749::OAuth2AuthorizationRequest<&str> = match req {
            Ok(u) => u,
            Err(_) => return Err(R::from_server_response(
                //In this case we don't even have the req.state property because the deserialization of the
                //request failed.
                &internal::OAuth2InternalAuthorizationErrorHandler::handle(self, OAuth2AuthorizationError::InvalidRequest, None).into()
            ))
        };

        //Helper function that validates if the response_type is equals to code
        fn validate_response_type_code(str: &str) -> Result<(), ()> {
            match str == "code" {
                true => Ok(()),
                false => Err(())
            }
        }
        let validate = || {

            //Validate [OAuth2AuthorizationRequest][state] syntax
            validate_attribute::<S, _, _ , _, _, _, _, _, _>(
                self,
                req.state,
                OAuth2AuthorizationError::InvalidRequest,
                internal::OAuth2InternalAuthorizationErrorHandler::handle,
                req.state,
                util::validate_state
            )?;

            //Validate [OAuth2AuthorizationRequest][response_type] syntax
            validate_attribute::<S, _, _, _, _, _, _, _, _>(
                self,
                Some(req.response_type),
                OAuth2AuthorizationError::InvalidRequest,
                internal::OAuth2InternalAuthorizationErrorHandler::handle,
                req.state,
                util::validate_response_type
            )?;

            //Validate [OAuth2AuthorizationRequest][client_id] syntax
            validate_attribute::<S, _, _, _, _, _, _, _, _>(
                self,
                Some(req.client_id),
                OAuth2AuthorizationError::InvalidRequest,
                internal::OAuth2InternalAuthorizationErrorHandler::handle,
                req.state,
                util::validate_client_id
            )?;

            //Validate [OAuth2AuthorizationRequest][redirect_uri] syntax
            let redirect_uri = validate_attribute::<S, _, _, _, _, _, _, _, _>(
                self,
                req.redirect_uri,
                OAuth2AuthorizationError::InvalidRequest,
                internal::OAuth2InternalAuthorizationErrorHandler::handle,
                req.state,
                util::validate_uri
            )?;

            //Validate [OAuth2AuthorizationRequest][scope] syntax
            let scope_tokens = validate_attribute::<S, _, _, _, _, _, _, _, _>(
                self,
                req.scope,
                OAuth2AuthorizationError::InvalidRequest,
                internal::OAuth2InternalAuthorizationErrorHandler::handle,
                req.state,
                util::validate_scope
            )?;

            //Semantic

            //Validate [OAuth2AuthorizationRequest][response_type] value is "code"
            validate_attribute::<S, _, _, _, _, _, _, _, _>(
                self,
                Some(req.response_type),
                OAuth2AuthorizationError::UnsupportedResponseType,
                internal::OAuth2InternalAuthorizationErrorHandler::handle,
                req.state,
                validate_response_type_code
            )?;

            Ok(OAuth2AuthorizationRequest {
                client_id: req.client_id,
                redirect_uri,
                scope_tokens,
                state: req.state
            })
        };
        match validate() {
            //Do logical or semantic validation based on the state
            Ok(res) => match OAuth2InternalAuthorizationRequestValidate::validate(self, res) {
                Ok(res) => Ok(res),
                Err(err) => Err(R::from_server_response(&OAuth2ServerResponse::AuthorizationErrorResponse(internal::OAuth2InternalAuthorizationErrorHandler::handle(self, err, req.state))))
            },
            Err(res) => Err(R::from_server_response(&res))
        }
    }
}

impl <'a, I, R, S, C1, C2> OAuth2Validate<'a, I, OAuth2ValidatedAuthenticatedAccessTokenRequest<'a, C1>, R, C1, C2> for S where
    I: OAuth2AuthorizationCodeFlowRequest<'a>,
    R: FromOAuth2ServerResponse,
    S: OAuth2State<C1, C2, Request=I, Response=R>,
    S: OAuth2ClientAuthenticate<Request=I>,
    S: OAuth2InternalAccessTokenRequestValidate<C1>
{
    fn validate(&self, raw: &'a I) -> Result<OAuth2ValidatedAuthenticatedAccessTokenRequest<'a, C1>, R> {

        let req: Result<rfc6749::OAuth2AccessTokenRequest<&str>, _> = TryIntoOAuth2ServerRequest::try_into_server_request(raw);
        let req = match req {
            Ok(u) => u,
            Err(_) => return Err(R::from_server_response(
                &internal::OAuth2InternalErrorHandler::handle(self, OAuth2Error::InvalidRequest, None).into()
            ))
        };
        let authenticated_client_id = match OAuth2ClientAuthenticate::authenticate_client(self,raw) {
            Ok(id) => id,
            Err(_) => return Err(R::from_server_response(
                //I
                &internal::OAuth2InternalErrorHandler::handle(self, OAuth2Error::InvalidClient, None).into()
            ))
        };

        //Helper function that validates if the response_type is equals to code
        fn validate_grant_type_authorization_code(str: &str) -> Result<(), ()> {
            match str == "authorization_code" {
                true => Ok(()),
                false => Err(())
            }
        }

        fn validate_client_ids<'a>(client_ids: (Option<&'a str>, Option<&'a str>)) -> Result<&'a str, ()> {
            if client_ids.0.is_none() && client_ids.1.is_none() {
                return Err(());
            }
            if client_ids.0.is_some() && client_ids.1.is_some() {
                if client_ids.0.unwrap() != client_ids.1.unwrap() {
                    return Err(());
                }
            }
            if client_ids.0.is_some() {
                return Ok(client_ids.0.unwrap());
            }
            Ok(client_ids.1.unwrap())
        }

        let validate = move || {

            //Validate [OAuth2AccessTokenRequest][grant_type] syntax
            validate_attribute::<S, _, _, _, _, _, _, _, _>(
                self,
                Some(req.grant_type),
                OAuth2Error::InvalidRequest,
                internal::OAuth2InternalErrorHandler::handle,
                None,
                util::validate_grant_type
            )?.unwrap();

            //Validate [OAuth2AccessTokenRequest][code] syntax
            validate_attribute::<S, _, _, _, _, _, _, _, _>(
                self,
                Some(req.code),
                OAuth2Error::InvalidRequest,
                internal::OAuth2InternalErrorHandler::handle,
                None,
                util::validate_code
            )?;

            //Validate [OAuth2AccessTokenRequest][redirect_uri] syntax
            let redirect_uri = validate_attribute::<S, _, _, _, _, _, _, _, _>(
                self,
                req.redirect_uri,
                OAuth2Error::InvalidRequest,
                internal::OAuth2InternalErrorHandler::handle,
                None,
                util::validate_uri
            )?;

            //Validate [OAuth2AccessTokenRequest][client_id] syntax
            validate_attribute::<S, _, _, _, _, _, _, _, _>(
                self,
                req.client_id,
                OAuth2Error::InvalidRequest,
                internal::OAuth2InternalErrorHandler::handle,
                None,
                util::validate_client_id
            )?;

            //Semantic

            //Validate [OAuth2AccessTokenRequest][grant_type] value is "authorization_code"
            validate_attribute::<S, _, _, _, _, _, _, _, _>(
                self,
                Some(req.grant_type),
                OAuth2Error::InvalidGrant,
                internal::OAuth2InternalErrorHandler::handle,
                None,
                validate_grant_type_authorization_code
            )?;

            //Validate that not two different client_ids are present and that at least one client id is present
            let client_id = validate_attribute::<S, _, _, _, _, _, _, _, _>(
                self,
                Some((authenticated_client_id, req.client_id)),
                OAuth2Error::InvalidClient,
                internal::OAuth2InternalErrorHandler::handle,
                None,
                validate_client_ids
            )?.unwrap();

            Ok(OAuth2AccessTokenRequest {
                client_id,
                code: req.code,
                redirect_uri
            })
        };
        match validate() {
            Ok(res) => {
                let res = OAuth2AuthenticatedAccessTokenRequest {
                    authenticated_client_id,
                    request: res
                };
                //Do logical or semantic validation based on the state
                match OAuth2InternalAccessTokenRequestValidate::validate(self, res) {
                    Ok(res) => Ok(res),
                    Err(err) => Err(R::from_server_response(&OAuth2ServerResponse::ErrorResponse(internal::OAuth2InternalErrorHandler::handle(self, err, None))))
                }
            },
            Err(res) => Err(R::from_server_response(&res))
        }
    }
}

impl <'a, I, R, S, C1, C2> OAuth2Validate<'a, I, OAuth2ValidatedAuthenticatedTokenRefreshRequest<'a, C2>, R, C1, C2> for S where
    I: OAuth2AuthorizationCodeFlowRequest<'a>,
    R: FromOAuth2ServerResponse,
    S: OAuth2State<C1, C2, Request=I, Response=R>,
    S: OAuth2ClientAuthenticate<Request=I>,
    S: OAuth2InternalTokenRefreshRequestValidate<C2>
{
    fn validate(&self, raw: &'a I) -> Result<OAuth2ValidatedAuthenticatedTokenRefreshRequest<'a, C2>, R> {
        let req: Result<rfc6749::OAuth2TokenRefreshRequest<&str>, _> = TryIntoOAuth2ServerRequest::try_into_server_request(raw);
        let req = match req {
            Ok(u) => u,
            Err(_) => return Err(R::from_server_response(
                &internal::OAuth2InternalErrorHandler::handle(self, OAuth2Error::InvalidRequest, None).into()
            ))
        };
        let authenticated_client_id = match OAuth2ClientAuthenticate::authenticate_client(self,raw) {
            Ok(id) => id,
            Err(_) => return Err(R::from_server_response(
                //I
                &internal::OAuth2InternalErrorHandler::handle(self, OAuth2Error::InvalidClient, None).into()
            ))
        };
        //Helper function that validates if the response_type is equals to code
        fn validate_grant_type_refresh_token(str: &str) -> Result<(), ()> {
            match str == "refresh_token" {
                true => Ok(()),
                false => Err(())
            }
        }

        let validate = || {

            //Validate [OAuth2TokenRefreshRequest][grant_type] syntax
            validate_attribute::<S, _, _, _, _, _, _, _, _>(
                self,
                Some(req.grant_type),
                OAuth2Error::InvalidRequest,
                internal::OAuth2InternalErrorHandler::handle,
                None,
                util::validate_grant_type
            )?;

            //Validate [OAuth2TokenRefreshRequest][refresh_token] syntax
            validate_attribute::<S, _, _, _, _, _, _, _, _>(
                self,
                Some(req.refresh_token),
                OAuth2Error::InvalidRequest,
                internal::OAuth2InternalErrorHandler::handle,
                None,
                util::validate_refresh_token
            )?;

            //Validate [OAuth2TokenRefreshRequest][scope] syntax
            let scope_tokens = validate_attribute::<S, _, _, _, _, _, _, _, _>(
                self,
                req.scope,
                OAuth2Error::InvalidRequest,
                internal::OAuth2InternalErrorHandler::handle,
                None,
                util::validate_scope
            )?;

            //Semantic

            //Validate [OAuth2AccessTokenRequest][scope] value is "refresh_token"
            validate_attribute::<S, _, _, _, _, _, _, _, _>(
                self,
                Some(req.grant_type),
                OAuth2Error::InvalidGrant,
                internal::OAuth2InternalErrorHandler::handle,
                None,
                validate_grant_type_refresh_token
            )?;
            Ok(OAuth2TokenRefreshRequest {
                refresh_token: req.refresh_token,
                scope_tokens
            })
        };
        match validate() {
            Ok(res) => {
                let res = OAuth2AuthenticatedTokenRefreshRequest {
                    authenticated_client_id,
                    request: res
                };
                //Do logical or semantic validation based on the state
                match OAuth2InternalTokenRefreshRequestValidate::validate(self, res) {
                    Ok(res) => Ok(res),
                    Err(err) => Err(R::from_server_response(&OAuth2ServerResponse::ErrorResponse(internal::OAuth2InternalErrorHandler::handle(self, err, None))))
                }
            },
            Err(res) => Err(R::from_server_response(&res))
        }
    }
}