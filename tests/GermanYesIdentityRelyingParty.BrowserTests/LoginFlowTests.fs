module GermanYesIdentityRelyingParty.BrowserTests

// These browser tests focus on testing the interactions between the relying party and the identity provider.
// They don't aim to test features of the test identity provider itself.

// In the Chrome DevTools Console, to locate an element:
// $$('button#c-p-bn');
       
module BrowserTests =
    open System.Web
    open Xunit
    open Newtonsoft.Json.Linq
    open PuppeteerSharp        

    [<AutoOpen>]
    module Steps =
        let timeout = 10000
        
        type Context =
            { Browser: Browser
              Page: Page
              WellKnownOpenIdConfiguration: string option
              IdToken: JObject option
              UserInfo: JObject option }
        with
            static member Default browser page =
                { Browser = browser; Page = page; WellKnownOpenIdConfiguration = None; IdToken = None; UserInfo = None }
        
        let setup launchUrl =
             task {
                 use browserFetcher = new BrowserFetcher()
                 let! _ = browserFetcher.DownloadAsync()
                 let! browser = Puppeteer.LaunchAsync(LaunchOptions(Headless = false))
                 let! pages = browser.PagesAsync()
                 let page = pages |> Array.exactlyOne
                 let ctx = Context.Default browser page
                 let! _ = page.GoToAsync(launchUrl); 
                 return ctx }

        let teardown ctx =
            task {
                let! ctx = ctx
                ctx.Browser.CloseAsync().GetAwaiter().GetResult()
                return ctx }

        let initiateLogin ctx =
            task {
                let! ctx = ctx
                let! login = ctx.Page.QuerySelectorAsync("button#login")
                let! _ = login.ClickAsync()
                return ctx }
            
        let cookieConsent ctx =
            task {
                let! ctx = ctx
                // Click "Accept all" cookie consent button
                let! acceptAll = ctx.Page.WaitForSelectorAsync("button#c-p-bn", WaitForSelectorOptions(Timeout = timeout, Visible = true))
                let! _ = acceptAll.ClickAsync()
                return ctx }
            
        let selectIdP idP ctx =
            task {
                let! ctx = ctx
                let! _ = ctx.Page.QuerySelectorAsync("input#input-bank-query")
                let! _ = ctx.Page.TypeAsync("input#input-bank-query", idP)
                // Wait until JavaScript populates the result list.
                let! _ = ctx.Page.WaitForSelectorAsync(".ac-result-list-item", WaitForSelectorOptions(Timeout = timeout))
                let! _ = ctx.Page.Keyboard.PressAsync("Enter")
                let! _ = ctx.Page.WaitForSelectorAsync("button#button_submit_query:not([disabled])")
                let! nextButton = ctx.Page.WaitForSelectorAsync("button#button_submit_query")
                let! _ = nextButton.ClickAsync()
                let! _ = ctx.Page.WaitForNavigationAsync()            
                return ctx }

        let loginAs username ctx =
            task {
                let! ctx = ctx
                assert (ctx.Page.Url.StartsWith("https://testidpui.sandbox.yes.com/services/authz/10000001"))
                let! _ = ctx.Page.TypeAsync("input#ui-login-username-input", username)
                let! loginButton = ctx.Page.QuerySelectorAsync("input#ui-login-submit-button")
                let! _ = loginButton.ClickAsync()
                let! _ = ctx.Page.WaitForNavigationAsync()  
                return ctx }

        let selectOtherBank ctx =
            task {
                let! ctx = ctx
                assert (ctx.Page.Url.StartsWith("https://testidpui.sandbox.yes.com/services/authz/10000001"))
                let! selectOtherBankButton = ctx.Page.QuerySelectorAsync("input#ui-login-select-another-bank-button")
                // Causes post-back to relying party
                // http://localhost:3000/yes/oidccb?iss=https://testidp.sandbox.yes.com/issuer/10000001&error=account_selection_requested&error_description=User_requested_to_select_another_account
                // which then redirects to the account chooser, including the prompt parameter:
                // https://accounts.sandbox.yes.com/?client_id=sandbox.yes.com:e85ff3bc-96f8-4ae7-b6b1-894d8dde9ebe&state=60f9f8b7-9eb3-480f-a1e2-7346720ade32&prompt=select_account
                let! _ = selectOtherBankButton.ClickAsync()
                let! _ = ctx.Page.WaitForNavigationAsync()            
                return ctx }                
                
        let confirmTwoFactorAuth ctx =
            task {
                let! ctx = ctx
                let! twoFactorLoginButton = ctx.Page.WaitForSelectorAsync("input#ui-second-factor-login-button", WaitForSelectorOptions(Timeout = timeout))
                let! _ = twoFactorLoginButton.ClickAsync()
                let! _ = ctx.Page.WaitForNavigationAsync()  
                return ctx }
        
        let declineSecondFactorAuth ctx =
            task {
                let! ctx = ctx
                assert (ctx.Page.Url.StartsWith("https://testidpui.sandbox.yes.com/services/login"))
                let! declineSecondFactorButton = ctx.Page.QuerySelectorAsync("input#ui-second-factor-decline-button")
                // Causes post-back to relying party
                // http://localhost:3000/yes/oidccb?error=access_denied&error_description=Access+denied+by+resource+owner+or+authorization+server&iss=https://testidp.sandbox.yes.com/issuer/10000001
                // with a specific error and error_description and login flow terminates.
                let! _ = declineSecondFactorButton.ClickAsync()
                let! _ = ctx.Page.WaitForNavigationAsync()
                return ctx }
        
        let consentSharing ctx =
            task {
                let! ctx = ctx
                // Labelled "yes" in the UI.
                let! consentButton = ctx.Page.WaitForSelectorAsync("input#ui-consent-submit-button", WaitForSelectorOptions(Timeout = timeout))
                let! _ = consentButton.ClickAsync()
                let! _ = ctx.Page.WaitForNavigationAsync()
                return ctx }
            
        let declineSharing ctx =
            task {
                let! ctx = ctx
                // Labelled "No" in the UI.
                let! declineButton = ctx.Page.WaitForSelectorAsync("input#ui-consent-cancel-button", WaitForSelectorOptions(Timeout = timeout))
                let! _ = declineButton.ClickAsync()
                let! _ = ctx.Page.WaitForNavigationAsync()
                return ctx }        
            
        let parseResult ctx =                  
            task {
                let! ctx = ctx
                let! wellKnownOpenIdConfiguration = ctx.Page.WaitForSelectorAsync("pre#wellKnownOpenIdConfiguration")
                let! idToken = ctx.Page.WaitForSelectorAsync("pre#idToken")
                let! userInfo = ctx.Page.WaitForSelectorAsync("pre#userInfo")
                let! wellKnownOpenIdConfigurationValue = ctx.Page.EvaluateFunctionAsync("e => e.textContent", wellKnownOpenIdConfiguration)
                let! idTokenValue = ctx.Page.EvaluateFunctionAsync("e => e.textContent", idToken)
                let! userInfoValue = ctx.Page.EvaluateFunctionAsync("e => e.textContent", userInfo)                                                                                                        
                return { ctx with
                             WellKnownOpenIdConfiguration = Some (wellKnownOpenIdConfigurationValue.ToString())
                             IdToken = Some (JObject.Parse (idTokenValue.ToString()))
                             UserInfo = Some (JObject.Parse (userInfoValue.ToString())) } }
        
    let wellKnownOpenIdConfigurationExpected = "https://testidp.sandbox.yes.com/issuer/10000001/.well-known/openid-configuration"
    let idTokenExpected = """{
  "sub": "f647f683-e46d-43bd-bc76-526d93429b86",
  "verified_claims": {
    "claims": {
      "place_of_birth": {
        "locality": "Berlin",
        "country": "DE"
      },
      "birthdate": "1950-01-01",
      "address": {
        "street_address": "Street1 1",
        "country": "DE",
        "formatted": "Street1 1\nBerlin\n10243\nDE",
        "locality": "Berlin",
        "region": "Berlin",
        "postal_code": "10243"
      },
      "nationalities": [
        "DE"
      ],
      "given_name": "Given001",
      "family_name": "Family001"
    },
    "verification": {
      "trust_framework": "de_aml"
    }
  },
  "https://www.yes.com/claims/preferred_iban": "DE72100500000000000019",
  "email_verified": true,
  "birthdate": "1950-01-01",
  "address": {
    "street_address": "Street1 1",
    "country": "DE",
    "formatted": "Street1 1\nBerlin\n10243\nDE",
    "locality": "Berlin",
    "region": "Berlin",
    "postal_code": "10243"
  },
  "gender": "male",
  "iss": "https://testidp.sandbox.yes.com/issuer/10000001",
  "phone_number_verified": true,
  "nationalities": [
    "DE"
  ],
  "given_name": "Given001",
  "title": "Dr.",
  "https://www.yes.com/claims/tax_id": "1121081508150",
  "place_of_birth": {
    "locality": "Berlin",
    "country": "DE"
  },
  "aud": "sandbox.yes.com:e85ff3bc-96f8-4ae7-b6b1-894d8dde9ebe",
  "acr": "https://www.yes.com/acrs/online_banking_sca",
  "phone_number": "+49301111001",
  "salutation": "Herr",
  "family_name": "Family001",
  "email": "test001@platform.yes.com"
}"""
    let userInfoExpected = """{
  "sub": "f647f683-e46d-43bd-bc76-526d93429b86",
  "verified_claims": {
    "claims": {
      "place_of_birth": {
        "locality": "Berlin",
        "country": "DE"
      },
      "birthdate": "1950-01-01",
      "address": {
        "street_address": "Street1 1",
        "country": "DE",
        "formatted": "Street1 1\nBerlin\n10243\nDE",
        "locality": "Berlin",
        "region": "Berlin",
        "postal_code": "10243"
      },
      "nationalities": [
        "DE"
      ],
      "given_name": "Given001",
      "family_name": "Family001"
    },
    "verification": {
      "trust_framework": "de_aml"
    }
  },
  "https://www.yes.com/claims/preferred_iban": "DE72100500000000000019",
  "email_verified": true,
  "birthdate": "1950-01-01",
  "address": {
    "street_address": "Street1 1",
    "country": "DE",
    "formatted": "Street1 1\nBerlin\n10243\nDE",
    "locality": "Berlin",
    "region": "Berlin",
    "postal_code": "10243"
  },
  "gender": "male",
  "phone_number_verified": true,
  "nationalities": [
    "DE"
  ],
  "given_name": "Given001",
  "title": "Dr.",
  "https://www.yes.com/claims/tax_id": "1121081508150",
  "place_of_birth": {
    "locality": "Berlin",
    "country": "DE"
  },
  "phone_number": "+49301111001",
  "salutation": "Herr",
  "family_name": "Family001",
  "email": "test001@platform.yes.com"
}"""    
    
    [<Fact>]
    let ``First time successful login`` () =
        task {
            let! ctx =
                setup "http://localhost:3000"
                |> initiateLogin
                |> cookieConsent
                |> selectIdP "testidp1"
                |> loginAs "test001"
                |> confirmTwoFactorAuth
                |> consentSharing
                |> parseResult
                |> teardown       
            
            Assert.Equal(Some wellKnownOpenIdConfigurationExpected, ctx.WellKnownOpenIdConfiguration)       
            let idToken = ctx.IdToken.Value
            let userInfo = ctx.UserInfo.Value
            
            // Remove parts of response that vary with each login.
            ["exp"; "iat"; "txn"; "nonce"]
            |> List.iter (fun propertyName -> idToken.Remove(propertyName) |> ignore)        
            Assert.Equal(JObject.Parse(idTokenExpected).ToString(), idToken.ToString())        

            ["txn"] |> List.iter (fun propertyName -> userInfo.Remove(propertyName) |> ignore)
            Assert.Equal(JObject.Parse(userInfoExpected).ToString(), userInfo.ToString()) }

    [<Fact>]
    let ``Select other bank`` () =
        task {
            let! ctx =
                setup "http://localhost:3000"
                |> initiateLogin
                |> cookieConsent
                |> selectIdP "testidp1"
                |> selectOtherBank
                |> teardown
                
            let url = ctx.Page.Url |> HttpUtility.UrlDecode
            Assert.True(url.StartsWith("https://accounts.sandbox.yes.com/?client_id=sandbox.yes.com:e85ff3bc-96f8-4ae7-b6b1-894d8dde9ebe"))
            Assert.True(url.EndsWith("prompt=select_account")) }
        
    [<Fact>]
    let ``Decline second factor auth`` () =
        task {
            let! ctx =
                setup "http://localhost:3000"
                |> initiateLogin
                |> cookieConsent
                |> selectIdP "testidp1"
                |> loginAs "test001"
                |> declineSecondFactorAuth
                |> teardown
                
            let actualUrl = ctx.Page.Url
            let expectedUrl = "http://localhost:3000/yes/oidccb?error=access_denied&error_description=Access+denied+by+resource+owner+or+authorization+server&iss=https://testidp.sandbox.yes.com/issuer/10000001"
            Assert.Equal(expectedUrl, actualUrl) }
        
    [<Fact>]
    let ``Decline sharing`` () =
        task {
            let! ctx =
                setup "http://localhost:3000"
                |> initiateLogin
                |> cookieConsent
                |> selectIdP "testidp1"
                |> loginAs "test001"
                |> confirmTwoFactorAuth
                |> declineSharing
                |> teardown    
            
            let actualUrl = ctx.Page.Url
            let expectedUrl = "http://localhost:3000/yes/oidccb?error=access_denied&error_description=Access+denied+by+resource+owner+or+authorization+server&iss=https://testidp.sandbox.yes.com/issuer/10000001"
            Assert.Equal(expectedUrl, actualUrl) }
