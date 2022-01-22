namespace GermanYesIdentityRelyingParty

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