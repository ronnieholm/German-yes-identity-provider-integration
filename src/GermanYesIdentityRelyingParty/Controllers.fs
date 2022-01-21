namespace GermanYesIdentityRelyingParty

[<RequireQualifiedAccess>]
module Domain =
    open System
    open Newtonsoft.Json.Linq    
    
    type EnvironmentUrls =
        { AccountChooser: Uri
          IssuerCheckCallback: Uri
          ServiceConfiguration: Uri }
        
    type Environment =
        | Sandbox
        | Production
    with
        member this.Urls() =
            // As per the Relying Party Developer Guide, Identity Service, sequence diagram.
            match this with
            | Sandbox ->
                { AccountChooser = Uri "https://accounts.sandbox.yes.com/"
                  IssuerCheckCallback = Uri "https://accounts.sandbox.yes.com/idp/"
                  ServiceConfiguration = Uri "https://api.sandbox.yes.com/service-configuration/v1/" }                   
            | Production ->
                { AccountChooser = Uri "https://accounts.yes.com/"
                  IssuerCheckCallback = Uri "https://accounts.yes.com/idp/"
                  ServiceConfiguration = Uri "https://api.yes.com/service-configuration/v1/" }             
    
    type RelyingPartyConfiguration =
        { ClientId: string
          PublicKeyFilePath: string
          PrivateKeyFilePath: string
          RedirectUrl: Uri }
    with
        static member Default() =
            // As per Relying Party Developer Guide, Testing and Onboarding, Sandbox Demo Client Data
            { ClientId = "sandbox.yes.com:e85ff3bc-96f8-4ae7-b6b1-894d8dde9ebe"
              PublicKeyFilePath = "cert.pem"
              PrivateKeyFilePath = "key.pem"
              // Account Chooser Url of http://localhost:3000/yes/oidccb from Demo Client Data left out from this
              // configuration as we'll never pass it to the identity provider but redirect to it directly as the first
              // step in the login flow.
              RedirectUrl = Uri "http://localhost:3000/yes/oidccb" }        
    
    type AccountSelection =
        | Prompt
        | NoPrompt
    with
        member this.String() =
            match this with
            | Prompt -> "select_account"
            | NoPrompt -> ""
    
    type AuthenticationContextClass =
        | OneFactor
        | TwoFactor
    with
        member this.String() =
            match this with
            | OneFactor -> "https://www.yes.com/acrs/online_banking"
            | TwoFactor -> "https://www.yes.com/acrs/online_banking_sca"
        
    [<CLIMutable>]
    type IdentitySessionState =
        { // These values are known prior to the start of login flow. We don't include AccountSelection as the relying
          // party must support changing its value dynamically: each IdP exposes a button which when clicked causes a
          // special OIDC error message to be returned to the relying party. Upon receiving this message, the relying
          // party must restart the login flow with AccountSelection = Prompt.
          Environment: Environment
          RelyingPartyConfiguration: RelyingPartyConfiguration
          AccountChooserState: Guid
          OidcNonce: Guid
          ClaimsRequested: string
          AuthenticationContextClass: AuthenticationContextClass
          // Remaining values are filled in during login flow.
          OidcConfiguration: JObject option
          Issuer: Uri option
          AuthorizationCode: string option
          Tokens: JObject option }
    with
        static member Default() =
            // As part of yes onboarding, the list of claims a relying party requires to fulfill its service must be
            // specified upfront. The claims requested below must be a subset of the ones specified prior. The format
            // of the claims requested follows from https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter.   
            let claims = """{
    "id_token": { 
        "txn": null,
        "email": null,
        "email_verified": null,
        "phone_number": null,
        "phone_number_verified": null,
        "given_name": null,
        "family_name": null,
        "birthdate": null,
        "address": null,
        "salutation": null,
        "title": null,
        "place_of_birth": null,
        "gender": null,
        "nationalities": null,
        "https://www.yes.com/claims/tax_id": null,
        "https://www.yes.com/claims/preferred_iban": null,
        "verified_claims": {
            "verification": {
                "trust_framework": null 
            },
            "claims": {
                "given_name": null,
                "family_name": null,
                "birthdate": null,             
                "place_of_birth": null,
                "nationalities": null,
                "address": null
            }
        }
    },
    "userinfo": { 
        "txn": null,
        "email": null,
        "email_verified": null,
        "phone_number": null,
        "phone_number_verified": null,
        "given_name": null,
        "family_name": null,
        "birthdate": null,
        "address": null,
        "salutation": null,
        "title": null,
        "place_of_birth": null,
        "gender": null,
        "nationalities": null,
        "https://www.yes.com/claims/tax_id": null,
        "https://www.yes.com/claims/preferred_iban": null,
        "verified_claims": {
            "verification": {
                "trust_framework": null 
            },
            "claims": {
                "given_name": null,
                "family_name": null,
                "birthdate": null,             
                "place_of_birth": null,
                "nationalities": null,
                "address": null
            }
        }
    }
}"""
            { Environment = Sandbox
              RelyingPartyConfiguration = RelyingPartyConfiguration.Default()
              AccountChooserState = Guid.NewGuid()
              OidcNonce = Guid.NewGuid()
              ClaimsRequested = claims
              AuthenticationContextClass = TwoFactor
              OidcConfiguration = None
              Issuer = None
              AuthorizationCode = None
              Tokens = None }

[<RequireQualifiedAccess>]
module Session =
    open Microsoft.AspNetCore.Http        
    open Newtonsoft.Json
    
    [<Literal>]
    let key = "yes"
    
    let save (session: ISession) (state: Domain.IdentitySessionState) =
        session.SetString(key, JsonConvert.SerializeObject(state))        

    let load (session: ISession): Domain.IdentitySessionState =
        JsonConvert.DeserializeObject<Domain.IdentitySessionState>(session.GetString(key))

[<RequireQualifiedAccess>]
module Dsl =
    open System
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
    
    let getAccountChooserUrl (sessionState: Domain.IdentitySessionState) (accountSelection: Domain.AccountSelection): Uri =
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
            | Domain.AccountSelection.Prompt -> $"%s{accountChooserRedirectUrl}&prompt=%s{accountSelection.String()}"
            | Domain.AccountSelection.NoPrompt -> accountChooserRedirectUrl
        printfn $"Account chooser Url: %s{accountChooserRedirectUrl'}"
        Uri accountChooserRedirectUrl'
    
    /// Initial step when starting a yes identity flow is to construct the Url to call the account chooser and redirect
    /// the user to it.
    let startIdentityFlow (sessionState: Domain.IdentitySessionState): Uri =
        getAccountChooserUrl sessionState Domain.AccountSelection.NoPrompt
                
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
    let checkIssuerUrl (sessionState: Domain.IdentitySessionState) (issuer: Uri): Result<unit, AccountChooserCallbackError> =
        let issuerCheck = sessionState.Environment.Urls().IssuerCheckCallback
        let issuer' = HttpUtility.UrlEncode issuer.AbsoluteUri
        let checkUrl = Uri $"%s{issuerCheck.AbsoluteUri}?iss=%s{issuer'}"
        printfn $"Check issuer Url: %s{checkUrl.AbsoluteUri}"
        use client = new HttpClient()
        let response = client.GetAsync(checkUrl).GetAwaiter().GetResult()
        let body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if not (String.IsNullOrEmpty body) then Error (CheckIssuerUrlFailed (IssuerState.YesSpecificationError(response.StatusCode, Some "Expected empty body")))
        else
            match IssuerState.OfHttpStatusCode response.StatusCode with
            | FoundAndActive -> Ok()
            | state -> Error (CheckIssuerUrlFailed state)

    /// Retrieves the ODIC/OAuth2 configuration from the discovered OIDC issuer.
    let retrieveOidcConfiguration (issuer: Uri): Result<JObject, AccountChooserCallbackError> =
        use client = new HttpClient()
        client.DefaultRequestHeaders.Accept.Add(MediaTypeWithQualityHeaderValue "application/json")
        // As an example, metadata endpoint for Test IdP 1 is
        // https://testidp.sandbox.yes.com/issuer/10000001/.well-known/openid-configuration
        let metadataUrl = $"%s{issuer.AbsoluteUri}{WellKnownOpenIdConfiguration}"
        printfn $"Metadata URL: %s{metadataUrl}"
        let response = client.GetAsync(metadataUrl).GetAwaiter().GetResult()
        let body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        let body' = JObject.Parse(body)
        let issuer' = Uri(body'.["issuer"].Value<string>())
        if issuer <> issuer' then Error (RetrieveOidcConfigurationFailed $"Issuer mismatch. Expected %s{issuer.AbsoluteUri}, got %s{issuer'.AbsoluteUri}")
        else Ok body'
                
    let assembleAuthorizationParameters (sessionState: Domain.IdentitySessionState): string =
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
        
    let handleAccountChooserCallback (sessionState: Domain.IdentitySessionState) (accountChooserState: Guid) (issuer: Uri option) (error: string option): Result<Domain.IdentitySessionState * Uri, AccountChooserCallbackError> =
        if accountChooserState <> sessionState.AccountChooserState then Error(InvalidAccountChooserState(accountChooserState, sessionState.AccountChooserState))
        else
            match error, issuer with
            | Some "canceled", None -> Error Canceled
            | Some "unknown_issuer", None -> Error UnknownIssuer
            | Some err, None -> Error (YesSpecificationError err)
            | None, Some issuer ->
                checkIssuerUrl sessionState issuer
                |> Result.bind (fun _ -> retrieveOidcConfiguration issuer)
                |> Result.bind (fun oidcConfiguration ->
                    let sessionState' = { sessionState with OidcConfiguration = Some oidcConfiguration; Issuer = Some issuer }
                    // authorization_endpoint may contain parameters that must be preserved when calling the endpoint.
                    // For instance, in testing the n parameter is present:
                    // https://testidpui.sandbox.yes.com/services/authz/10000001?n=true.
                    let endpoint = oidcConfiguration.["authorization_endpoint"].Value<string>()
                    let parameters = assembleAuthorizationParameters sessionState'
                    Ok (sessionState', Uri $"%s{endpoint}&%s{parameters}"))
            | _ -> Error (YesSpecificationError $"Error: %A{error}, Issuer: %A{issuer}")
            
    type OidcCallbackError =
        | InvalidIssuer of actual: string * expected: string
        | OAuthError of error: string * description: string option
        | YesSpecificationError of string
            
    let handleOidcCallback (sessionState: Domain.IdentitySessionState) (iss: Uri) (code: string option) (error: string option) (errorDescription: string option): Result<Domain.IdentitySessionState option * Uri option, OidcCallbackError> =
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
                    Ok (None, Some (getAccountChooserUrl sessionState Domain.AccountSelection.Prompt))
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
            
    let decodeAndValidateIdToken (sessionState: Domain.IdentitySessionState): Result<JObject, ClaimsRequestError> =
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
            let openIdConfiguration = configurationManager.GetConfigurationAsync().GetAwaiter().GetResult()
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
            let idToken = sessionState.Tokens.Value.["id_token"].Value<string>()          
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
                let nonce = claims.["nonce"]
                let acr = claims.["acr"]
                if securityToken'.SignatureAlgorithm <> "RS256" then Error (IdTokenValidation $"Wrong signature algorithm. Got %s{securityToken'.SignatureAlgorithm}, expected RS256")
                // To prevent CSRF attacks, the Relying Party Developer Guide, Section 3.2.4. Implementation Notes
                // requires nonce and state (if present as it's optional) be associated with the originating user agent.
                // The binding between user agent and nonce/state must be checked after the relying party receives the
                // authentication response (in this function) and after the relying party receives the token response
                // (in the sendTokenRequest function). The association or binding to the user agent is through the
                // .AspNetCore.Session cookie.
                elif nonce <> sessionState.OidcNonce.ToString() then Error (IdTokenValidation $"Wrong nonce in ID token. Got %s{nonce}, expected %s{sessionState.OidcNonce.ToString()}")
                // The Relying Party Developer Guide, Section 3.2.3. Authentication Policy allows for an identity
                // provider to respond with a lower acr value than the one requested by the relying party. Given that
                // acr values represent one factor and two factor only, only with two factor authentication can the
                // response be a lower acr value.
                elif acr <> sessionState.AuthenticationContextClass.String() then Error (IdTokenValidation $"Wrong acr value. Got %s{acr}, expected %s{sessionState.AuthenticationContextClass.String()}")
                else
                    let idTokenJson = handler.ReadJwtToken idToken
                    let payload = idTokenJson.Payload.SerializeToJson()
                    Ok (JObject.Parse(payload))                    
            with e ->
                Error (IdTokenValidation $"%s{e.GetType().ToString()}: %s{e.Message}")
        | None ->
            failwith "Missing session state issuer"

    let getClientCertificate (sessionState: Domain.IdentitySessionState) =
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
    let sendTokenRequest (sessionState: Domain.IdentitySessionState): Result<Domain.IdentitySessionState * JObject, ClaimsRequestError> =
        match sessionState.OidcConfiguration with
        | Some oidcConfiguration ->
            match sessionState.AuthorizationCode with
            | Some code ->                    
                let tokenEndpoint = oidcConfiguration.["token_endpoint"].Value<string>()
                let clientId = HttpUtility.UrlEncode sessionState.RelyingPartyConfiguration.ClientId
                let redirectUri = HttpUtility.UrlEncode sessionState.RelyingPartyConfiguration.RedirectUrl.AbsoluteUri
                let grantType = "authorization_code"
                use handler = new HttpClientHandler()
                use tlsCertificate = getClientCertificate sessionState
                handler.ClientCertificates.Add(tlsCertificate) |> ignore
                use client = new HttpClient(handler)
                client.DefaultRequestHeaders.Accept.Add(MediaTypeWithQualityHeaderValue("application/json"))
                // TODO(rh): Rename to requestBody and responseBody instead of shadowing.
                use body = new StringContent($"client_id=%s{clientId}&redirect_uri=%s{redirectUri}&grant_type=%s{grantType}&code=%s{code}", Encoding.UTF8, "application/x-www-form-urlencoded")
                let response = client.PostAsync(tokenEndpoint, body).GetAwaiter().GetResult()
                let body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                match response.StatusCode with
                | HttpStatusCode.BadRequest ->
                    // In accordance with the Relying Party Developer Guide, Section 3.7. Token Error Response.
                    let body' = JObject.Parse(body)
                    let error = body'.["error"].Value<string>()
                    let description =
                        if body'.["error_description"] <> null
                        then Some (body'.["error_description"].Value<string>())
                        else None 
                    Error (TokenRequestFailed(error, description))
                | HttpStatusCode.OK ->
                    let sessionState' = { sessionState with Tokens = Some (JObject.Parse(body)) }
                    decodeAndValidateIdToken sessionState'
                    |> Result.bind (fun claims -> Ok (sessionState', claims))
                | _ -> Error (YesSpecificationError(response.StatusCode, body))                                 
            | None -> failwith "Missing session state authorization code"
        | None -> failwith "Missing session state Oidc configuration"        
        
    /// Send the token request to the discovered issuer's UserInfo endpoint.            
    let sendUserInfoRequest (sessionState: Domain.IdentitySessionState): Result<JObject, ClaimsRequestError> =
        match sessionState.OidcConfiguration with
        | Some oidcConfiguration ->            
            match sessionState.Tokens with
            | Some tokens ->
                let userinfoEndpoint = oidcConfiguration.["userinfo_endpoint"].Value<string>()
                let accessToken = tokens.["access_token"].Value<string>()
                use handler = new HttpClientHandler()
                use certificate = getClientCertificate sessionState
                handler.ClientCertificates.Add(certificate) |> ignore                        
                use client = new HttpClient(handler) 
                client.DefaultRequestHeaders.Authorization <- AuthenticationHeaderValue("Bearer", accessToken)
                client.DefaultRequestHeaders.Accept.Add(MediaTypeWithQualityHeaderValue("application/json"))
                let response = client.GetAsync(userinfoEndpoint).GetAwaiter().GetResult()
                let body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                match response.StatusCode with
                | HttpStatusCode.BadRequest -> Error (UserInfoRequestFailed(HttpStatusCode.BadRequest))
                | HttpStatusCode.OK -> Ok (JObject.Parse(body))
                | _ -> Error (YesSpecificationError (response.StatusCode, body))
            | None -> failwith "Missing session state tokens"
        | None -> failwith "Missing session state Oidc configuration"

[<RequireQualifiedAccess>]                
module Helpers =
    open System.Net
    open Microsoft.AspNetCore.Mvc
       
    let respond (statusCode: HttpStatusCode) (content: string): IActionResult =
        ContentResult(
            ContentType = "text/html",
            StatusCode = int statusCode,
            Content = content) :> _  
                
open System
open System.Net
open System.Text
open Microsoft.AspNetCore.Mvc
                
type HomeController () =
    inherit Controller()

    [<HttpGet>]
    member this.Index () =
         ContentResult(
             ContentType = "text/html",
             StatusCode = int HttpStatusCode.OK,
             Content = """<html>
    <head>
      <meta charset="UTF-8">
    </head>
    <p>Please identify with your bank</p>
    <form action="/yes/start">
        <button type="submit">yes®</button>
    </form>
</html>""")
             
type YesController () =
    inherit Controller()
            
    /// Starts the yes identity flow after the user clicked the yes button.
    [<HttpGet>]
    member this.Start () =
        let sessionState = Domain.IdentitySessionState.Default()
        Session.save base.HttpContext.Session sessionState
        let accountChooserRedirectUrl = Dsl.startIdentityFlow sessionState
        base.Redirect(accountChooserRedirectUrl.ToString())

    /// The user arrives at the Account chooser callback Url after selecting a bank. This Url must be registered with
    /// the yes platform for the client_id. accb is part of the Sandbox Demo Client metadata.
    [<HttpGet>]
    member this.Accb (issuer_url: string) (selected_bic: string) (state: Guid) (error: string): IActionResult =
        let issuer_url' = (Option.ofObj issuer_url) |> Option.map Uri
        let _ = Option.ofObj selected_bic
        let error' = Option.ofObj error        
        let sessionState = Session.load base.HttpContext.Session
        match Dsl.handleAccountChooserCallback sessionState state issuer_url' error' with
        | Ok (sessionState', url) ->
            Session.save base.HttpContext.Session sessionState'
            base.Redirect(url.AbsoluteUri) :> _
        | Error s ->
            Helpers.respond HttpStatusCode.BadRequest $"%A{s}"  
         
    /// The user arrives at the OpenID Connect callback endpoint after going through the authentication/authorization
    /// steps at the bank. This Url must be registered with the yes platform for the client_id. oidccb is part of the
    /// Sandbox Demo Client metadata.
    [<HttpGet>]
    member this.Oidccb (iss: string) (code: string) (error: string) (error_description: string): IActionResult =
        let iss' = Uri iss
        let code' = Option.ofObj code
        let error' = Option.ofObj error
        let error_description' = Option.ofObj error_description        
        let sessionState = Session.load base.HttpContext.Session        
        let responseBuilder = StringBuilder()
        
        // The yes platform supports associating any number of client-side TLS certificates with a client_id; a common
        // case when onboarding by providing a jwks Url. In case of multiple certificates, the client must ensure that
        // the certificate used when calling token_endpoint (to exchange the authorization code for the ID token and the
        // access token) is identical to that used when calling userinfo_endpoint or other APIs to which the access
        // token is passed.
        //
        // The access token contains the cnf (confirmation) claim with the hash of the client-side TLS certificate used
        // when calling the token_endpoint (see https://datatracker.ietf.org/doc/html/rfc7800#section-3):
        //
        // "cnf": { "x5t#S256": "JX50qAD0Za84F2UW91nHnoV561-P4B-4ob6bagFeq6Y" }
        //
        // As specified in the IDP Core Specification, Section 2.1.5. Token & Scope Handling, APIs are required to
        // check for possession of the key, i.e., the baked-in hash must match the hash of the certificate used to call
        // the API.
        match Dsl.handleOidcCallback sessionState iss' code' error' error_description' with
        | Ok (Some sessionState', None) ->
            Session.save base.HttpContext.Session sessionState'
            let issuer = sessionState.Issuer.Value.AbsoluteUri
            responseBuilder.Append("<h3>Configuration</h3>") |> ignore
            responseBuilder.Append($"<a href='%s{issuer + Dsl.WellKnownOpenIdConfiguration}'><pre>%s{issuer + Dsl.WellKnownOpenIdConfiguration}</pre></a>") |> ignore                       

            responseBuilder.Append("<h3>ID token</h3>") |> ignore
            match Dsl.sendTokenRequest sessionState' with
            | Ok (sessionState', oidcToken) ->                
                Session.save base.HttpContext.Session sessionState'
                responseBuilder.Append($"<pre>%s{oidcToken.ToString()}</pre>") |> ignore                
            | Error e ->
                responseBuilder.Append($"%A{e}") |> ignore

            let sessionState = Session.load base.HttpContext.Session                
            responseBuilder.Append("<h3>UserInfo</h3>") |> ignore
            match Dsl.sendUserInfoRequest sessionState with
            | Ok userInfo ->
                responseBuilder.Append($"<pre>%s{userInfo.ToString()}</pre>") |> ignore                                
            | Error e ->
                responseBuilder.Append($"%A{e}") |> ignore
            
            Helpers.respond HttpStatusCode.OK (responseBuilder.ToString())
        | Ok (None, Some accountSelectionRequested) ->
            base.Redirect(accountSelectionRequested.AbsoluteUri) :> _
        | Error s ->
            Helpers.respond HttpStatusCode.BadRequest $"%A{s}"
        | _ ->
            Helpers.respond HttpStatusCode.BadRequest "Should never happen"