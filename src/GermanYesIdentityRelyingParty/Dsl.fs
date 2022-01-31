namespace GermanYesIdentityRelyingParty

[<RequireQualifiedAccess>]
module Session =
    open Microsoft.AspNetCore.Http        
    open Newtonsoft.Json
    
    [<Literal>]
    let key = "yes"
    
    let save (session: ISession) (state: Configuration.IdentitySessionState) =
        session.SetString(key, JsonConvert.SerializeObject(state))        

    let load (session: ISession): Configuration.IdentitySessionState =
        JsonConvert.DeserializeObject<Configuration.IdentitySessionState>(session.GetString(key))

[<RequireQualifiedAccess>]
module Dsl =
    open System
    open System.Threading.Tasks
    open System.IdentityModel.Tokens.Jwt
    open System.Net
    open System.Net.Http
    open System.Net.Http.Headers
    open System.Security.Cryptography.X509Certificates
    open System.Text
    open System.Web
    open System.IO
    open System.Reflection
    open System.Runtime.InteropServices
    open Microsoft.IdentityModel.Protocols
    open Microsoft.IdentityModel.Protocols.OpenIdConnect
    open Microsoft.IdentityModel.Tokens
    open Newtonsoft.Json.Linq      
    
    let getAccountChooserUrl (sessionState: Configuration.IdentitySessionState) (accountSelection: Configuration.AccountSelection): Uri =
        // When calling the account chooser, the state parameter is required. Compare this to the authorization request
        // where the state parameter is optional. With the account chooser, the state parameter serves the purpose of
        // nonce with the authorization request.
        let accountChooserUrl = sessionState.Environment.Urls().AccountChooser.AbsoluteUri        
        let clientId = HttpUtility.UrlEncode sessionState.RelyingPartyConfiguration.ClientId
        let accountChooserState = HttpUtility.UrlEncode (sessionState.AccountChooserState.ToString())
        let accountChooserRedirectUrl = $"%s{accountChooserUrl}?client_id=%s{clientId}&state=%s{accountChooserState}"
        // While in case of NoPrompt we could pass "prompt=" but instead leave out the parameter entirely. 
        let accountChooserRedirectUrl' =
            match accountSelection with
            | Configuration.AccountSelection.Prompt -> $"%s{accountChooserRedirectUrl}&prompt=%s{accountSelection.String()}"
            | Configuration.AccountSelection.NoPrompt -> accountChooserRedirectUrl
        printfn $"Account chooser Url: %s{accountChooserRedirectUrl'}"
        Uri accountChooserRedirectUrl'
    
    /// Initial step when starting a yes identity flow is to construct the Url to call the account chooser and redirect
    /// the user to it.
    let startIdentityFlow (sessionState: Configuration.IdentitySessionState): Uri =
        getAccountChooserUrl sessionState Configuration.AccountSelection.NoPrompt
                
    [<Literal>]
    let WellKnownOpenIdConfiguration = "/.well-known/openid-configuration"
    
    /// As per the Relying Party Developer Guide, Section 2. Issuer URI Check.
    type IssuerState =
        | FoundAndActive
        | InvalidIssuerUrl
        | NotFound
        | FoundAndInactive
        | YesSpecificationError of HttpStatusCode * string option
    with
        static member OfHttpStatusCode code =
            match code with
            | HttpStatusCode.NoContent -> FoundAndActive
            | HttpStatusCode.BadRequest -> InvalidIssuerUrl
            | HttpStatusCode.NotFound -> NotFound
            | HttpStatusCode.Locked -> FoundAndInactive
            | _ -> YesSpecificationError(code, None)
    
    type AccountChooserCallbackError =
        | InvalidAccountChooserState of actual: Guid * expected: Guid
        | Canceled
        | UnknownIssuer
        | CheckIssuerUrlFailed of IssuerState 
        | RetrieveOidcConfigurationFailed of string
        | YesSpecificationError of string
    
    /// Checks that the issuer_url points to a valid issuer in the yes ecosystem.
    let checkIssuerUrl (sessionState: Configuration.IdentitySessionState) (issuer: Uri): Task<Result<unit, AccountChooserCallbackError>> =
        task {
            let issuerCheck = sessionState.Environment.Urls().IssuerCheckCallback
            let issuer' = HttpUtility.UrlEncode issuer.AbsoluteUri
            let checkUrl = Uri $"%s{issuerCheck.AbsoluteUri}?iss=%s{issuer'}"
            printfn $"Check issuer Url: %s{checkUrl.AbsoluteUri}"
            use client = new HttpClient()
            let! response = client.GetAsync(checkUrl)
            let! body = response.Content.ReadAsStringAsync()
            if not (String.IsNullOrEmpty body)
            then return Error (CheckIssuerUrlFailed (IssuerState.YesSpecificationError(response.StatusCode, Some "Expected empty body")))
            else
                match IssuerState.OfHttpStatusCode response.StatusCode with
                | FoundAndActive -> return Ok()
                | state -> return Error (CheckIssuerUrlFailed state)
        }
    
    /// Retrieves the ODIC/OAuth2 configuration from the discovered OIDC issuer.
    let retrieveOidcConfiguration (issuer: Uri): Task<Result<JObject, AccountChooserCallbackError>> =
        task {
            use client = new HttpClient()
            client.DefaultRequestHeaders.Accept.Add(MediaTypeWithQualityHeaderValue "application/json")
            // As an example, metadata endpoint for Test IdP 1 is
            // https://testidp.sandbox.yes.com/issuer/10000001/.well-known/openid-configuration
            let metadataUrl = $"%s{issuer.AbsoluteUri}{WellKnownOpenIdConfiguration}"
            printfn $"Metadata URL: %s{metadataUrl}"
            let! response = client.GetAsync(metadataUrl)
            let! body = response.Content.ReadAsStringAsync()
            let body' = JObject.Parse(body)
            let issuer' = Uri(body'["issuer"].Value<string>())
            if issuer <> issuer'
            then return Error (RetrieveOidcConfigurationFailed $"Issuer mismatch. Expected %s{issuer.AbsoluteUri}, got %s{issuer'.AbsoluteUri}")
            else return Ok body'
        }
                
    let assembleAuthorizationParameters (sessionState: Configuration.IdentitySessionState): string =
        // From the sequence diagram in the Relying Party Developer Guide, Steps 13, 19, and 20, one gets the impression
        // that the state parameter is required. However, Section 3.2 Authentication Request specifies the state
        // parameter is optional. When we don't have an actual use for passing state in relying party, nonce suffices. 
        let clientId = HttpUtility.UrlEncode sessionState.RelyingPartyConfiguration.ClientId
        let redirectUri = HttpUtility.UrlEncode sessionState.RelyingPartyConfiguration.RedirectUrl.AbsoluteUri
        let scope = "openid"
        let responseType = "code"
        let nonce = HttpUtility.UrlEncode (sessionState.OidcNonce.ToString())
        // Leave out claims and we get back only the "user id" which translates to the sub claim. 
        let claims = HttpUtility.UrlEncode sessionState.ClaimsRequested
        // Leave out ACR value and TwoFactor is the default.
        let acrValue = HttpUtility.UrlEncode(sessionState.AuthenticationContextClass.String())
        let queryString = $"client_id=%s{clientId}&redirect_uri=%s{redirectUri}&scope=%s{scope}&response_type=%s{responseType}&nonce=%s{nonce}&claims=%s{claims}&acr_values=%s{acrValue}"       
        printfn $"Authorization parameters query string: %s{queryString}"
        queryString
        
    let handleAccountChooserCallback (sessionState: Configuration.IdentitySessionState) (accountChooserState: Guid) (issuer: Uri option) (error: string option): Task<Result<Configuration.IdentitySessionState * Uri, AccountChooserCallbackError>> =
        task {
            if accountChooserState <> sessionState.AccountChooserState
            then return Error(InvalidAccountChooserState(accountChooserState, sessionState.AccountChooserState))
            else
                match error, issuer with
                | Some "canceled", None -> return Error Canceled
                | Some "unknown_issuer", None -> return Error UnknownIssuer
                | Some err, None -> return Error (YesSpecificationError err)
                | None, Some issuer ->
                    let! checkIssuerUrl = checkIssuerUrl sessionState issuer
                    return checkIssuerUrl
                    |> Result.bind (fun _ ->
                        // TODO: How to properly have task inside task?
                        (retrieveOidcConfiguration issuer).Result)
                    |> Result.bind (fun oidcConfiguration ->
                        let sessionState' = { sessionState with OidcConfiguration = Some oidcConfiguration; Issuer = Some issuer }
                        // authorization_endpoint may contain parameters that must be preserved when calling the endpoint.
                        // For instance, in testing the n parameter is present:
                        // https://testidpui.sandbox.yes.com/services/authz/10000001?n=true.
                        let endpoint = oidcConfiguration["authorization_endpoint"].Value<string>()
                        let parameters = assembleAuthorizationParameters sessionState'
                        Ok (sessionState', Uri $"%s{endpoint}&%s{parameters}"))
                | _ -> return Error (YesSpecificationError $"Error: %A{error}, Issuer: %A{issuer}")
            }            
            
    type OidcCallbackError =
        | InvalidIssuer of actual: string * expected: string
        | OAuthError of error: string * description: string option
        | YesSpecificationError of string
            
    let handleOidcCallback (sessionState: Configuration.IdentitySessionState) (iss: Uri) (code: string option) (error: string option) (errorDescription: string option): Result<Configuration.IdentitySessionState option * Uri option, OidcCallbackError> =
        match sessionState.Issuer with
        | Some issuer ->
            if issuer <> iss then
                // Possible mix-up attack detected. 
                Error (InvalidIssuer (iss.AbsoluteUri, issuer.AbsoluteUri))
            else
                match code, error, errorDescription with
                | None, Some "account_selection_requested", Some "User_requested_to_select_another_account" ->
                    // Non-standard OIDC response from the yes identity provider when the user clicks the "Select
                    // another bank" button during the login flow. In accordance with the Relying Party Developer Guide,
                    // Section 3.4 Authentication Error Response, this error must trigger a forced bank selection in the
                    // account chooser.
                    Ok (None, Some (getAccountChooserUrl sessionState Configuration.AccountSelection.Prompt))
                | None, Some error, _ ->
                    // In accordance with the OAuth 2.0 Authorization Error Response (https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1),
                    // OAuth 2.0 Error Response (https://datatracker.ietf.org/doc/html/rfc6749#section-5.2), and OIDC
                    // 1.0 Authentication Error Response (https://openid.net/specs/openid-connect-core-1_0.html#AuthError),
                    // the error_description parameter is optional.
                    Error (OAuthError (error, errorDescription))
                | Some code, None, None ->
                    let sessionState = { sessionState with AuthorizationCode = Some code }
                    Ok (Some sessionState, None)
                | e ->
                    Error (YesSpecificationError $"Callback parameters: %A{e}")
        | None ->
            failwith "Missing session state issuer"
        
    type ClaimsRequestError =
         | TokenRequestFailed of error: string * errorDescription: string option
         | IdTokenValidation of string
         | UserInfoRequestFailed of HttpStatusCode
         | YesSpecificationError of HttpStatusCode * body: string
            
    let decodeAndValidateIdToken (sessionState: Configuration.IdentitySessionState): Task<Result<Identity.IdToken, ClaimsRequestError>> =
        task {            
            match sessionState.Issuer with
            | Some issuer ->        
                let configurationManager =
                    // Decoding and validating can happen using either
                    // - ConfigurationManager: https://github.com/auth0-samples/auth0-dotnet-validate-jwt/blob/master/IdentityModel-RS256/Program.cs
                    // - Manual jwks parsing: https://github.com/IdentityServer/IdentityServer4/blob/main/samples/Clients/old/MvcManual/Controllers/HomeController.cs#L148
                    // The use of ConfigurationManager triggers a second download of .well-known/openid-configuration to get
                    // at the jwks_uri value within the metadata whose content is also downloaded. The first download may be
                    // avoided by "Manual jwks parsing" link". Downloading takes time so we should only download either once
                    // or periodically during the runtime of the RP or when an unknown token signing key is encountered.
                    ConfigurationManager<OpenIdConnectConfiguration>(
                        $"%s{issuer.AbsoluteUri}{WellKnownOpenIdConfiguration}",
                        OpenIdConnectConfigurationRetriever())
                let! openIdConfiguration = configurationManager.GetConfigurationAsync()
                // Checks in accordance with the Relying Party Developer Guide, Section 3.6.1. Handling Returned Data.
                // An actual relying party, one that doesn't print the claims verbatim, would additionally check that every
                // requested claim is present in the response. See the Relying Party Developer Guide, Section 1.3.
                // Availability of Data and Billing.
                let validationParameters =
                    TokenValidationParameters(
                        ValidIssuer = issuer.AbsoluteUri,
                        ValidAudience = sessionState.RelyingPartyConfiguration.ClientId,
                        IssuerSigningKeys = openIdConfiguration.SigningKeys,
                        RequireExpirationTime = true,
                        RequireSignedTokens = true,                    
                        ValidateLifetime = true,
                        TryAllIssuerSigningKeys = true)
                let handler = JwtSecurityTokenHandler()
                let idToken = sessionState.Jwt.Value["id_token"].Value<string>()          
                try
                    let claimsPrincipal, securityToken = handler.ValidateToken(idToken, validationParameters)                    
                    let securityToken' = securityToken :?> JwtSecurityToken
                    let claims =
                        claimsPrincipal.Claims
                        |> Seq.map (fun claim ->
                            let shortType =
                                if claim.Properties.Count > 0 then
                                    claim.Properties
                                    |> Seq.filter (fun p -> p.Key = "http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/ShortTypeName")
                                    |> Seq.exactlyOne
                                    |> fun p -> p.Value
                                else claim.Type                    
                            shortType, claim.Value) |> dict
                    let nonce = claims["nonce"]
                    let acr = claims["acr"]
                    if securityToken'.SignatureAlgorithm <> "RS256" then return Error (IdTokenValidation $"Wrong signature algorithm. Got %s{securityToken'.SignatureAlgorithm}, expected RS256")
                    // To prevent CSRF attacks, the Relying Party Developer Guide, Section 3.2.4. Implementation Notes
                    // requires nonce and state (if present as it's optional) be associated with the originating user agent.
                    // The binding between user agent and nonce/state must be checked after the relying party receives the
                    // authentication response (in this function) and after the relying party receives the token response
                    // (in the sendTokenRequest function). The association or binding to the user agent is through the
                    // .AspNetCore.Session cookie.
                    elif nonce <> sessionState.OidcNonce.ToString() then return Error (IdTokenValidation $"Wrong nonce in ID token. Got %s{nonce}, expected %s{sessionState.OidcNonce.ToString()}")
                    // The Relying Party Developer Guide, Section 3.2.3. Authentication Policy allows for an identity
                    // provider to respond with a lower acr value than the one requested by the relying party. Given that
                    // acr values represent one factor and two factor only, only with two factor authentication can the
                    // response be a lower acr value.
                    elif acr <> sessionState.AuthenticationContextClass.String() then return Error (IdTokenValidation $"Wrong acr value. Got %s{acr}, expected %s{sessionState.AuthenticationContextClass.String()}")
                    else
                        let idTokenJson = handler.ReadJwtToken idToken
                        let payload = idTokenJson.Payload.SerializeToJson()
                        return Ok (Identity.IdToken (JObject.Parse(payload)))                     
                with e ->
                    return Error (IdTokenValidation $"%s{e.GetType().ToString()}: %s{e.Message}")
            | None ->
                return failwith "Missing session state issuer"
        }

    let getClientCertificate (sessionState: Configuration.IdentitySessionState) =
        // Unexplained behavior: after sendTokenRequest has called this function for the first time, in sendUserInfoRequest
        // it's possible to follow the non-Windows path and the code still works on Windows. Either Windows internally
        // re-uses the underlying TCP connection or Windows recognizes and reuses the certificate, even though the
        // initial call was with a Pkcs12 certificate and the second was with a PEM certificate.
        let path = Assembly.GetExecutingAssembly().Location
        let path' = Path.GetDirectoryName path
        // Work around bug in Windows: https://github.com/dotnet/runtime/issues/23749#issuecomment-747407051
        if RuntimeInformation.IsOSPlatform OSPlatform.Windows then
            use certificate =
                X509Certificate2.CreateFromPemFile(
                    Path.Combine(path', sessionState.RelyingPartyConfiguration.PublicKeyFilePath),
                    Path.Combine(path', sessionState.RelyingPartyConfiguration.PrivateKeyFilePath))                        
            new X509Certificate2(certificate.Export X509ContentType.Pkcs12)
        else
            X509Certificate2.CreateFromPemFile(
                Path.Combine(path', sessionState.RelyingPartyConfiguration.PublicKeyFilePath),
                Path.Combine(path', sessionState.RelyingPartyConfiguration.PrivateKeyFilePath))
                                
    /// Send the token request to the discovered issuer's token endpoint.          
    let sendTokenRequest (sessionState: Configuration.IdentitySessionState): Task<Result<Configuration.IdentitySessionState * Identity.IdToken, ClaimsRequestError>> =
        task {
            match sessionState.OidcConfiguration with
            | Some oidcConfiguration ->
                match sessionState.AuthorizationCode with
                | Some code ->                    
                    let tokenEndpoint = oidcConfiguration["token_endpoint"].Value<string>()
                    let clientId = HttpUtility.UrlEncode sessionState.RelyingPartyConfiguration.ClientId
                    let redirectUri = HttpUtility.UrlEncode sessionState.RelyingPartyConfiguration.RedirectUrl.AbsoluteUri
                    let grantType = "authorization_code"
                    use handler = new HttpClientHandler()
                    use tlsCertificate = getClientCertificate sessionState
                    handler.ClientCertificates.Add(tlsCertificate) |> ignore
                    use client = new HttpClient(handler)
                    client.DefaultRequestHeaders.Accept.Add(MediaTypeWithQualityHeaderValue("application/json"))
                    use requestBody = new StringContent($"client_id=%s{clientId}&redirect_uri=%s{redirectUri}&grant_type=%s{grantType}&code=%s{code}", Encoding.UTF8, "application/x-www-form-urlencoded")
                    let! response = client.PostAsync(tokenEndpoint, requestBody)
                    let! responseBody = response.Content.ReadAsStringAsync()
                    match response.StatusCode with
                    | HttpStatusCode.BadRequest ->
                        // In accordance with the Relying Party Developer Guide, Section 3.7. Token Error Response.
                        let body' = JObject.Parse(responseBody)
                        let error = body'["error"].Value<string>()
                        let description =
                            if body'["error_description"] <> null
                            then Some (body'["error_description"].Value<string>())
                            else None 
                        return Error (TokenRequestFailed(error, description))
                    | HttpStatusCode.OK ->
                        let sessionState' = { sessionState with Jwt = Some (JObject.Parse(responseBody)) }
                        let! decodeAndValidateIdToken = decodeAndValidateIdToken sessionState'
                        return decodeAndValidateIdToken
                        |> Result.bind (fun claims -> Ok (sessionState', claims))
                    | _ -> return Error (YesSpecificationError(response.StatusCode, responseBody))                                 
                | None -> return failwith "Missing session state authorization code"
            | None -> return failwith "Missing session state Oidc configuration"
        }
    
    /// Send the token request to the discovered issuer's UserInfo endpoint.            
    let sendUserInfoRequest (sessionState: Configuration.IdentitySessionState): Task<Result<Identity.UserInfo, ClaimsRequestError>> =
        task {
            match sessionState.OidcConfiguration with
            | Some oidcConfiguration ->            
                match sessionState.Jwt with
                | Some jwt ->
                    let userinfoEndpoint = oidcConfiguration["userinfo_endpoint"].Value<string>()
                    let accessToken = jwt["access_token"].Value<string>()
                    use handler = new HttpClientHandler()
                    use certificate = getClientCertificate sessionState
                    handler.ClientCertificates.Add(certificate) |> ignore                        
                    use client = new HttpClient(handler) 
                    client.DefaultRequestHeaders.Authorization <- AuthenticationHeaderValue("Bearer", accessToken)
                    client.DefaultRequestHeaders.Accept.Add(MediaTypeWithQualityHeaderValue("application/json"))
                    let! response = client.GetAsync(userinfoEndpoint)
                    let! body = response.Content.ReadAsStringAsync()
                    match response.StatusCode with
                    | HttpStatusCode.BadRequest -> return Error (UserInfoRequestFailed(HttpStatusCode.BadRequest))
                    | HttpStatusCode.OK -> return Ok (Identity.UserInfo (JObject.Parse(body)))
                    | _ -> return Error (YesSpecificationError (response.StatusCode, body))
                | None -> return failwith "Missing session state tokens"
            | None -> return failwith "Missing session state Oidc configuration"
        }