/* [RFC6749] 2.3.1.  Client Password

   Clients in possession of a client password MAY use the HTTP Basic
   authentication scheme as defined in [RFC2617] to authenticate with
   the authorization server.  The client identifier is encoded using the
   "application/x-www-form-urlencoded" encoding algorithm per
   Appendix B, and the encoded value is used as the username; the client
   password is encoded using the same algorithm and used as the
   password.  The authorization server MUST support the HTTP Basic
   authentication scheme for authenticating clients that were issued a
   client password.

   For example (with extra line breaks for display purposes only):

    Authorization: Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3

   Alternatively, the authorization server MAY support including the
   client credentials in the request-body using the following
   parameters:

   client_id
         REQUIRED.  The client identifier issued to the client during
         the registration process described by [RFC6749] Section 2.2.

   client_secret
         REQUIRED.  The client secret.  The client MAY omit the
         parameter if the client secret is an empty string.

   Including the client credentials in the request-body using the two
   parameters is NOT RECOMMENDED and SHOULD be limited to clients unable
   to directly utilize the HTTP Basic authentication scheme (or other
   password-based HTTP authentication schemes).  The parameters can only
   be transmitted in the request-body and MUST NOT be included in the
   request URI.

   For example, a request to refresh an access token (Section 6) using
   the body parameters (with extra line breaks for display purposes
   only):

        POST /token HTTP/1.1
        Host: server.example.com
        Content-Type: application/x-www-form-urlencoded

        grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
        &client_id=s6BhdRkqt3&client_secret=7Fjfp0ZBr1KtDRbnfVdmIw

   The authorization server MUST require the use of TLS as described in
   Section 1.6 when sending requests using password authentication.

   Since this client authentication method involves a password, the
   authorization server MUST protect any endpoint utilizing it against
   brute force attacks.

   See [OAuth2AccessTokenRequest][client_secret]
*/

/* [RFC6749] 3.2.1.  Client Authentication

   Confidential clients or other clients issued client credentials MUST
   authenticate with the authorization server as described in
   [RFC6749] Section 2.3 when making requests to the token endpoint.  Client
   authentication is used for:

   o  Enforcing the binding of refresh tokens and authorization codes to
      the client they were issued to.  Client authentication is critical
      when an authorization code is transmitted to the redirection
      endpoint over an insecure channel or when the redirection URI has
      not been registered in full.

   o  Recovering from a compromised client by disabling the client or
      changing its credentials, thus preventing an attacker from abusing
      stolen refresh tokens.  Changing a single set of client
      credentials is significantly faster than revoking an entire set of
      refresh tokens.

   o  Implementing authentication management best practices, which
      require periodic credential rotation.  Rotation of an entire set
      of refresh tokens can be challenging, while rotation of a single
      set of client credentials is significantly easier.

   A client MAY use the "client_id" request parameter to identify itself
   when sending requests to the token endpoint.  In the
   "authorization_code" "grant_type" request to the token endpoint, an
   unauthenticated client MUST send its "client_id" to prevent itself
   from inadvertently accepting a code intended for a client with a
   different "client_id".  This protects the client from substitution of
   the authentication code.  (It provides no additional security for the
   protected resource.)
*/

/* [RFC6749] 3.1.2.  Redirection Endpoint

   After completing its interaction with the resource owner, the
   authorization server directs the resource owner's user-agent back to
   the client.  The authorization server redirects the user-agent to the
   client's redirection endpoint previously established with the
   authorization server during the client registration process or when
   making the authorization request.

   The redirection endpoint URI MUST be an absolute URI as defined by
   [RFC3986] Section 4.3.  The endpoint URI MAY include an
   "application/x-www-form-urlencoded" formatted (per Appendix B) query
   component ([RFC3986] Section 3.4), which MUST be retained when adding
   additional query parameters.  The endpoint URI MUST NOT include a
   fragment component.
*/

/* [RFC6749] 3.1.2.1.  Endpoint Request Confidentiality

   The redirection endpoint SHOULD require the use of TLS as described
   in [RFC6749] Section 1.6 when the requested response type is "code" or "token",
   or when the redirection request will result in the transmission of
   sensitive credentials over an open network.  This specification does
   not mandate the use of TLS because at the time of this writing,
   requiring clients to deploy TLS is a significant hurdle for many
   client developers.  If TLS is not available, the authorization server
   SHOULD warn the resource owner about the insecure endpoint prior to
   redirection (e.g., display a message during the authorization
   request).

   Lack of transport-layer security can have a severe impact on the
   security of the client and the protected resources it is authorized
   to access.  The use of transport-layer security is particularly
   critical when the authorization process is used as a form of
   delegated end-user authentication by the client (e.g., third-party
   sign-in service).
*/

/* [RFC6749] 3.1.2.2.  Registration Requirements

   The authorization server MUST require the following clients to
   register their redirection endpoint:

   o  Public clients.

   o  Confidential clients utilizing the implicit grant type.

   The authorization server SHOULD require all clients to register their
   redirection endpoint prior to utilizing the authorization endpoint.

   The authorization server SHOULD require the client to provide the
   complete redirection URI (the client MAY use the "state" request
   parameter to achieve per-request customization).  If requiring the
   registration of the complete redirection URI is not possible, the
   authorization server SHOULD require the registration of the URI
   scheme, authority, and path (allowing the client to dynamically vary
   only the query component of the redirection URI when requesting
   authorization).

   The authorization server MAY allow the client to register multiple
   redirection endpoints.

   Lack of a redirection URI registration requirement can enable an
   attacker to use the authorization endpoint as an open redirector as
   described in Section 10.15.
*/

/* [RFC6749] 3.1.2.3.  Dynamic Configuration

   If multiple redirection URIs have been registered, if only part of
   the redirection URI has been registered, or if no redirection URI has
   been registered, the client MUST include a redirection URI with the
   authorization request using the "redirect_uri" request parameter.

   When a redirection URI is included in an authorization request, the
   authorization server MUST compare and match the value received
   against at least one of the registered redirection URIs (or URI
   components) as defined in [RFC3986] Section 6, if any redirection
   URIs were registered.  If the client registration included the full
   redirection URI, the authorization server MUST compare the two URIs
   using simple string comparison as defined in [RFC3986] Section 6.2.1.
*/

// [RFC6749] Section 4.1. Authorization Code Grant


/** [RFC6749] Section 4.1.1. Authorization Code Grant
   Adding the following
   parameters to the query component of the authorization endpoint URI
   using the "application/x-www-form-urlencoded" format

   Example:

        GET /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz
        &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
        Host: server.example.com
*/
pub struct OAuth2AuthorizationRequest<Str> {

    /// REQUIRED.  Value MUST be set to "code".
    pub response_type: Str,

    /// REQUIRED.  The client identifier as described in [RFC6749] Section 2.2.
    pub client_id: Str,

    /// OPTIONAL.  As described in Section [RFC6749] 3.1.2.
    pub redirect_uri: Option<Str>,

    /// OPTIONAL.  The scope of the access request as described by  [RFC6749] Section 3.3.
    pub scope: Option<Str>,

    /// RECOMMENDED.  An opaque value used by the client to maintain
    ///     state between the request and callback.  The authorization
    ///     server includes this value when redirecting the user-agent back
    ///     to the client.  The parameter SHOULD be used for preventing
    ///     cross-site request forgery as described in [RFC6749] Section 10.12.
    pub state: Option<Str>
}

/** [RFC6749] Section 4.1.2.  Authorization Response
   Adding the following parameters to the query component of the
   redirection URI using the "application/x-www-form-urlencoded" format.

   Example:

        HTTP/1.1 302 Found
        Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz
*/
pub struct OAuth2AuthorizationResponse<Str> {
    /** REQUIRED.  The authorization code generated by the
         authorization server.  The authorization code MUST expire
         shortly after it is issued to mitigate the risk of leaks.  A
         maximum authorization code lifetime of 10 minutes is
         RECOMMENDED.  The client MUST NOT use the authorization code
         more than once.  If an authorization code is used more than
         once, the authorization server MUST deny the request and SHOULD
         revoke (when possible) all tokens previously issued based on
         that authorization code.  The authorization code is bound to
         the client identifier and redirection URI.
    */
    pub code: Str,

    /** REQUIRED if the "state" parameter was present in the client
         authorization request.  The exact value received from the
         client.
    */
    pub state: Option<Str>
}

/** [RFC6749] 4.1.2.1.  Error Response
    If the request fails due to a missing, invalid, or mismatching
    redirection URI, or if the client identifier is missing or invalid,
    the authorization server SHOULD inform the resource owner of the
    error and MUST NOT automatically redirect the user-agent to the
    invalid redirection URI.

    If the resource owner denies the access request or if the request
    fails for reasons other than a missing or invalid redirection URI,
    the authorization server informs the client by adding the following
    parameters to the query component of the redirection URI using the
    "application/x-www-form-urlencoded" format.

    Example:

        HTTP/1.1 302 Found
        Location: https://client.example.com/cb?error=access_denied&state=xyz
*/
pub struct OAuth2AuthorizationErrorResponse<Str> {
    /** REQUIRED.  A single ASCII [USASCII] error code from the
         following:

         invalid_request
               The request is missing a required parameter, includes an
               invalid parameter value, includes a parameter more than
               once, or is otherwise malformed.

         unauthorized_client
               The client is not authorized to request an authorization
               code using this method.

         access_denied
               The resource owner or authorization server denied the
               request.

         unsupported_response_type
               The authorization server does not support obtaining an
               authorization code using this method.

         invalid_scope
               The requested scope is invalid, unknown, or malformed.

         server_error
               The authorization server encountered an unexpected
               condition that prevented it from fulfilling the request.
               (This error code is needed because a 500 Internal Server
               Error HTTP status code cannot be returned to the client
               via an HTTP redirect.)

         temporarily_unavailable
               The authorization server is currently unable to handle
               the request due to a temporary overloading or maintenance
               of the server.  (This error code is needed because a 503
               Service Unavailable HTTP status code cannot be returned
               to the client via an HTTP redirect.)

         Values for the "error" parameter MUST NOT include characters
         outside the set %x20-21 / %x23-5B / %x5D-7E.
    */
    pub error: Str,

    /** OPTIONAL.  Human-readable ASCII [USASCII] text providing
         additional information, used to assist the client developer in
         understanding the error that occurred.
         Values for the "error_description" parameter MUST NOT include
         characters outside the set %x20-21 / %x23-5B / %x5D-7E.
    */
    pub error_description: Option<Str>,

    /** OPTIONAL.  A URI identifying a human-readable web page with
         information about the error, used to provide the client
         developer with additional information about the error.
         Values for the "error_uri" parameter MUST conform to the
         URI-reference syntax and thus MUST NOT include characters
         outside the set %x21 / %x23-5B / %x5D-7E.
    */
    pub error_uri: Option<Str>,

    /** REQUIRED if a "state" parameter was present in the client
         authorization request.  The exact value received from the
         client.
    */
    pub state: Option<Str>
}

/// [RFC6749] 4.1.3.  Access Token Request
/// The client makes a request to the token endpoint by sending the
/// following parameters using the "application/x-www-form-urlencoded"
/// format per Appendix B with a character encoding of UTF-8 in the HTTP
/// request entity-body:
///
/// Example:
///
///     POST /token HTTP/1.1
///     Host: server.example.com
///     Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
///     Content-Type: application/x-www-form-urlencoded
///
///     grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
///     &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
///
/// The authorization server MUST:
///
///    o  require client authentication for confidential clients or for any
///       client that was issued client credentials (or with other
///       authentication requirements),
///
///    o  authenticate the client if client authentication is included,
///
///    o  ensure that the authorization code was issued to the authenticated
///       confidential client, or if the client is public, ensure that the
///       code was issued to "client_id" in the request,
///
///    o  verify that the authorization code is valid, and
///
///    o  ensure that the "redirect_uri" parameter is present if the
///       "redirect_uri" parameter was included in the initial authorization
///       request as described in [RFC6749] Section 4.1.1, and if included ensure that
///       their values are identical.
///
pub struct OAuth2AccessTokenRequest<Str> {

    /// REQUIRED.  Value MUST be set to "authorization_code".
    pub grant_type: Str,

    /// REQUIRED.  The authorization code received from the
    ///     authorization server.
    ///
    pub code: Str,

    /// REQUIRED, if the "redirect_uri" parameter was included in the
    ///  authorization request as described in Section [RFC6749] 4.1.1, and their
    ///  values MUST be identical.
    ///
    pub redirect_uri: Option<Str>,

    /// REQUIRED, if the client is not authenticating with the
    ///     authorization server as described in [RFC6749] Section 3.2.1.
    ///
    pub client_id: Option<Str>
}


/** [RFC6749] 4.1.4.  Access Token Response
    If the access token request is valid and authorized, the
    authorization server issues an access token and optional refresh
    token as described in [RFC6749] Section 5.1.  If the request client
    authentication failed or is invalid, the authorization server returns
    an error response as described in [RFC6749] Section 5.2.

    See struct [OAuth2SuccessResponse]
*/

//TODO [RFC6749] 4.2.  Implicit Grant
//TODO [RFC6749] 4.3.  Resource Owner Password Credentials Grant
//TODO [RFC6749] 4.4.  Client Credentials Grant
//TODO [RFC6749] 4.5.  Extension Grants

/// [RFC6749] 5.  Issuing an Access Token

/** [RFC6749] 5.1.  Successful Response
    The authorization server issues an access token and optional refresh
    token, and constructs the response by adding the following parameters
    to the entity-body of the HTTP response with a 200 (OK) status code.

    The parameters are included in the entity-body of the HTTP response
    using the "application/json" media type as defined by [RFC4627].  The
    parameters are serialized into a JavaScript Object Notation (JSON)
    structure by adding each parameter at the highest structure level.
    Parameter names and string values are included as JSON strings.
    Numerical values are included as JSON numbers.  The order of
    parameters does not matter and can vary.

    The authorization server MUST include the HTTP "Cache-Control"
    response header field [RFC2616] with a value of "no-store" in any
    response containing tokens, credentials, or other sensitive
    information, as well as the "Pragma" response header field [RFC2616]
    with a value of "no-cache".

    For example:

        HTTP/1.1 200 OK
        Content-Type: application/json;charset=UTF-8
        Cache-Control: no-store
        Pragma: no-cache

        {
            "access_token":"2YotnFZFEjr1zCsicMWpAA",
            "token_type":"example",
            "expires_in":3600,
            "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter":"example_value"
        }

    The client MUST ignore unrecognized value names in the response.  The
    sizes of tokens and other values received from the authorization
    server are left undefined.  The client should avoid making
    assumptions about value sizes.  The authorization server SHOULD
    document the size of any value it issues.
*/
pub struct OAuth2SuccessResponse<Str, Int> {
    /** REQUIRED.  The access token issued by the authorization server.
    */
    pub access_token: Str,

    /** REQUIRED.  The type of the token issued as described in
        [RFC6749] Section 7.1.  Value is case insensitive.
    */
    pub token_type: Str,

    /** RECOMMENDED.  The lifetime in seconds of the access token.  For
         example, the value "3600" denotes that the access token will
         expire in one hour from the time the response was generated.
         If omitted, the authorization server SHOULD provide the
         expiration time via other means or document the default value.
    */
    pub expires_in: Option<Int>,

    /** OPTIONAL.  The refresh token, which can be used to obtain new
         access tokens using the same authorization grant as described
         in [RFC6749] Section 6.
    */
    pub refresh_token: Option<Str>,

    /** OPTIONAL, if identical to the scope requested by the client;
         otherwise, REQUIRED.  The scope of the access token as
         described by [RFC6749] Section 3.3.
    */
    pub scope: Option<Str>
}

/** [RFC6749] 5.2.  Error Response
    The authorization server responds with an HTTP 400 (Bad Request)
    status code (unless specified otherwise) and includes the following
    parameters with the response:

    The parameters are included in the entity-body of the HTTP response
    using the "application/json" media type as defined by [RFC4627].  The
    parameters are serialized into a JSON structure by adding each
    parameter at the highest structure level.  Parameter names and string
    values are included as JSON strings.  Numerical values are included
    as JSON numbers.  The order of parameters does not matter and can
    vary.

    For example:

        HTTP/1.1 400 Bad Request
        Content-Type: application/json;charset=UTF-8
        Cache-Control: no-store
        Pragma: no-cache

        {
           "error":"invalid_request"
        }
*/
pub struct OAuth2ErrorResponse<Str> {
    /** REQUIRED.  A single ASCII [USASCII] error code from the
         following:

         invalid_request
               The request is missing a required parameter, includes an
               unsupported parameter value (other than grant type),
               repeats a parameter, includes multiple credentials,
               utilizes more than one mechanism for authenticating the
               client, or is otherwise malformed.

         invalid_client
               Client authentication failed (e.g., unknown client, no
               client authentication included, or unsupported
               authentication method).  The authorization server MAY
               return an HTTP 401 (Unauthorized) status code to indicate
               which HTTP authentication schemes are supported.  If the
               client attempted to authenticate via the "Authorization"
               request header field, the authorization server MUST
               respond with an HTTP 401 (Unauthorized) status code and
               include the "WWW-Authenticate" response header field
               matching the authentication scheme used by the client.

         invalid_grant
               The provided authorization grant (e.g., authorization
               code, resource owner credentials) or refresh token is
               invalid, expired, revoked, does not match the redirection
               URI used in the authorization request, or was issued to
               another client.

         unauthorized_client
               The authenticated client is not authorized to use this
               authorization grant type.

         unsupported_grant_type
               The authorization grant type is not supported by the
               authorization server.

         invalid_scope
               The requested scope is invalid, unknown, malformed, or
               exceeds the scope granted by the resource owner.

         Values for the "error" parameter MUST NOT include characters
         outside the set %x20-21 / %x23-5B / %x5D-7E.
    */
    pub error: Str,

    /** OPTIONAL.  Human-readable ASCII [USASCII] text providing
         additional information, used to assist the client developer in
         understanding the error that occurred.
         Values for the "error_description" parameter MUST NOT include
         characters outside the set %x20-21 / %x23-5B / %x5D-7E.
    */
    pub error_description: Option<Str>,

    /** OPTIONAL.  A URI identifying a human-readable web page with
         information about the error, used to provide the client
         developer with additional information about the error.
         Values for the "error_uri" parameter MUST conform to the
         URI-reference syntax and thus MUST NOT include characters
         outside the set %x21 / %x23-5B / %x5D-7E.
    */
    pub error_uri: Option<Str>
}

/// [RFC6749] 6.  Refreshing an Access Token

/// [RFC6749] 6.  Refreshing an Access Token
/// If the authorization server issued a refresh token to the client, the
/// client makes a refresh request to the token endpoint by adding the
/// following parameters using the "application/x-www-form-urlencoded"
/// format per Appendix B with a character encoding of UTF-8 in the HTTP
/// request entity-body:
///
/// Because refresh tokens are typically long-lasting credentials used to
/// request additional access tokens, the refresh token is bound to the
/// client to which it was issued.  If the client type is confidential or
/// the client was issued client credentials (or assigned other
/// authentication requirements), the client MUST authenticate with the
/// authorization server as described in [RFC6749] Section 3.2.1.
///
/// For example, the client makes the following HTTP request using
/// transport-layer security (with extra line breaks for display purposes
/// only):
///
///     POST /token HTTP/1.1
///     Host: server.example.com
///     Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
///     Content-Type: application/x-www-form-urlencoded
///
///     grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
///
/// The authorization server MUST:
///
///    o  require client authentication for confidential clients or for any
///       client that was issued client credentials (or with other
///       authentication requirements),
///
///    o  authenticate the client if client authentication is included and
///       ensure that the refresh token was issued to the authenticated
///       client, and
///
///    o  validate the refresh token.
///
/// If valid and authorized, the authorization server issues an access
/// token as described in [RFC6749] Section 5.1.  If the request failed
/// verification or is invalid, the authorization server returns an error
/// response as described in [RFC6749] Section 5.2.
///
/// The authorization server MAY issue a new refresh token, in which case
/// the client MUST discard the old refresh token and replace it with the
/// new refresh token.  The authorization server MAY revoke the old
/// refresh token after issuing a new refresh token to the client.  If a
/// new refresh token is issued, the refresh token scope MUST be
/// identical to that of the refresh token included by the client in the
/// request.
///
pub struct OAuth2TokenRefreshRequest<Str> {

    /// REQUIRED.  Value MUST be set to "refresh_token".
    pub grant_type: Str,

    /// REQUIRED.  The refresh token issued to the client.
    pub refresh_token: Str,

    /// OPTIONAL.  The scope of the access request as described by
    ///     [RFC6749] Section 3.3. The requested scope MUST NOT include any scope
    ///     not originally granted by the resource owner, and if omitted is
    ///     treated as equal to the scope originally granted by the
    ///     resource owner.
    pub scope: Option<Str>
}

/* [RFC6749] 7.  Accessing Protected Resources

   The client accesses protected resources by presenting the access
   token to the resource server.  The resource server MUST validate the
   access token and ensure that it has not expired and that its scope
   covers the requested resource.  The methods used by the resource
   server to validate the access token (as well as any error responses)
   are beyond the scope of this specification but generally involve an
   interaction or coordination between the resource server and the
   authorization server.

   The method in which the client utilizes the access token to
   authenticate with the resource server depends on the type of access
   token issued by the authorization server.  Typically, it involves
   using the HTTP "Authorization" request header field [RFC2617] with an
   authentication scheme defined by the specification of the access
   token type used, such as [RFC6750].
*/

/* [RFC6749] 7.1.  Access Token Types

   The access token type provides the client with the information
   required to successfully utilize the access token to make a protected
   resource request (along with type-specific attributes).  The client
   MUST NOT use an access token if it does not understand the token
   type.

   For example, the "bearer" token type defined in [RFC6750] is utilized
   by simply including the access token string in the request:

     GET /resource/1 HTTP/1.1
     Host: example.com
     Authorization: Bearer mF_9.B5f-4.1JqM

   while the "mac" token type defined in [OAuth-HTTP-MAC] is utilized by
   issuing a Message Authentication Code (MAC) key together with the
   access token that is used to sign certain components of the HTTP
   requests:

     GET /resource/1 HTTP/1.1
     Host: example.com
     Authorization: MAC id="h480djs93hd8",
                        nonce="274312:dj83hs9s",
                        mac="kDZvddkndxvhGRXZhvuDjEWhGeE="

   The above examples are provided for illustration purposes only.
   Developers are advised to consult the [RFC6750] and [OAuth-HTTP-MAC]
   specifications before use.

   Each access token type definition specifies the additional attributes
   (if any) sent to the client together with the "access_token" response
   parameter.  It also defines the HTTP authentication method used to
   include the access token when making a protected resource request.
*/

/* [RFC6749] 7.2.  Error Response

   If a resource access request fails, the resource server SHOULD inform
   the client of the error.  While the specifics of such error responses
   are beyond the scope of this specification, this document establishes
   a common registry in Section 11.4 for error values to be shared among
   OAuth token authentication schemes.

   New authentication schemes designed primarily for OAuth token
   authentication SHOULD define a mechanism for providing an error
   status code to the client, in which the error values allowed are
   registered in the error registry established by this specification.

   Such schemes MAY limit the set of valid error codes to a subset of
   the registered values.  If the error code is returned using a named
   parameter, the parameter name SHOULD be "error".

   Other schemes capable of being used for OAuth token authentication,
   but not primarily designed for that purpose, MAY bind their error
   values to the registry in the same manner.

   New authentication schemes MAY choose to also specify the use of the
   "error_description" and "error_uri" parameters to return error
   information in a manner parallel to their usage in this
   specification.
*/

impl <Str> OAuth2AuthorizationErrorResponse<Str> {
    pub fn new(error: Str, desc: Option<Str>, uri: Option<Str>, state: Option<Str>) -> Self {
        Self {
            error,
            error_description: desc,
            error_uri: uri,
            state
        }
    }
}

impl <Str> OAuth2ErrorResponse<Str> {
    pub fn new(error: Str, desc: Option<Str>, uri: Option<Str>) -> Self {
        Self {
            error,
            error_description: desc,
            error_uri: uri
        }
    }
}