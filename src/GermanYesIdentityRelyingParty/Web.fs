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
open System.Threading.Tasks
open Microsoft.AspNetCore.Mvc
                
type HomeController () =
    inherit Controller()

    [<HttpGet>]
    member this.Index (): ContentResult =
         ContentResult(
             ContentType = "text/html",
             StatusCode = int HttpStatusCode.OK,
             Content = """<html>
    <head>
      <meta charset="UTF-8">
    </head>
    <p>Please identify with your bank</p>
    <form action="/yes/start">
        <button id="login" type="submit">yes®</button>
    </form>
</html>""")
             
type YesController () =
    inherit Controller()
            
    /// Starts the yes identity flow after the user clicked the yes button.
    [<HttpGet>]
    member this.Start (): RedirectResult =
        let sessionState = Configuration.IdentitySessionState.Default()
        Session.save base.HttpContext.Session sessionState
        let accountChooserRedirectUrl = Dsl.startIdentityFlow sessionState
        base.Redirect(string accountChooserRedirectUrl)

    // Workaround to bug in task computation expression. Calling through base results in a compilation error:
    // "A protected member is called or 'base' is being used"
    // See https://github.com/dotnet/fsharp/issues/12448
    member this.Redirect(url: Uri): IActionResult = base.Redirect(url.AbsoluteUri)        
    member this.Session = base.HttpContext.Session                
    
    /// The user arrives at the Account chooser callback Url after selecting a bank. This Url must be registered with
    /// the yes platform for the client_id. accb is part of the Sandbox Demo Client metadata.
    [<HttpGet>]
    member this.Accb (issuer_url: string) (selected_bic: string) (state: Guid) (error: string): Task<IActionResult> =
        task {                
            let issuer_url' = (Option.ofObj issuer_url) |> Option.map Uri
            let _ = Option.ofObj selected_bic
            let error' = Option.ofObj error        
            let sessionState = Session.load this.HttpContext.Session
            let! handleAccountChooserCallback = Dsl.handleAccountChooserCallback sessionState state issuer_url' error'  
            match handleAccountChooserCallback with
            | Ok (sessionState', url) ->
                Session.save this.HttpContext.Session sessionState'
                this.Response.Redirect(url.AbsoluteUri)
                return RedirectResult(url.AbsoluteUri) :> IActionResult
            | Error s ->
                return Helpers.respond HttpStatusCode.BadRequest $"%A{s}"
        }
         
    /// The user arrives at the OpenID Connect callback endpoint after going through the authentication/authorization
    /// steps at the bank. This Url must be registered with the yes platform for the client_id. oidccb is part of the
    /// Sandbox Demo Client metadata.
    [<HttpGet>]
    member this.Oidccb (iss: string) (code: string) (error: string) (error_description: string): Task<IActionResult> =
        task {
            let iss' = Uri iss
            let code' = Option.ofObj code
            let error' = Option.ofObj error
            let error_description' = Option.ofObj error_description        
            let sessionState = Session.load this.HttpContext.Session        
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
                Session.save this.HttpContext.Session sessionState'
                let issuer = sessionState.Issuer.Value.AbsoluteUri
                responseBuilder.Append("<h3>Configuration</h3>") |> ignore
                responseBuilder.Append($"<a href='%s{issuer + Dsl.WellKnownOpenIdConfiguration}'><pre id='wellKnownOpenIdConfiguration'>%s{issuer + Dsl.WellKnownOpenIdConfiguration}</pre></a>") |> ignore                       

                responseBuilder.Append("<h3>ID token</h3>") |> ignore
                let! sendTokenRequest = Dsl.sendTokenRequest sessionState' 
                match sendTokenRequest with
                | Ok (sessionState', Identity.IdToken idToken) ->                
                    Session.save this.HttpContext.Session sessionState'
                    responseBuilder.Append($"<pre id='idToken'>%s{string idToken}</pre>") |> ignore  
                | Error e ->
                    responseBuilder.Append($"%A{e}") |> ignore

                let sessionState = Session.load this.HttpContext.Session                
                responseBuilder.Append("<h3>UserInfo</h3>") |> ignore
                let! sendUserInfoRequest = Dsl.sendUserInfoRequest sessionState
                match sendUserInfoRequest with
                | Ok (Identity.UserInfo userInfo) ->
                    responseBuilder.Append($"<pre id='userInfo'>%s{string userInfo}</pre>") |> ignore                                
                | Error e ->
                    responseBuilder.Append($"%A{e}") |> ignore
                
                return Helpers.respond HttpStatusCode.OK (string responseBuilder)
            | Ok (None, Some accountSelectionRequested) ->
                return this.Redirect(accountSelectionRequested.AbsoluteUri) :> _
            | Error s ->
                return Helpers.respond HttpStatusCode.BadRequest $"%A{s}"
            | _ ->
                return Helpers.respond HttpStatusCode.BadRequest "Should never happen"
        }