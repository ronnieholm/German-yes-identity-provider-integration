module GermanYesIdentityRelyingParty.BrowserTests

// In Chrome DevTools, locate an element like so:
// $$('button#c-p-bn');

// TODO: Browse through documentation: https://puppeteersharp.com/api/

open Xunit
open PuppeteerSharp
open Newtonsoft.Json.Linq

module BrowserSteps =
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
         (task {
             use browserFetcher = new BrowserFetcher()
             let! _ = browserFetcher.DownloadAsync()
             let! browser = Puppeteer.LaunchAsync(LaunchOptions(Headless = false))
             let! pages = browser.PagesAsync()
             let page = pages |> Array.exactlyOne
             let ctx = Context.Default browser page
             let! _ = page.GoToAsync(launchUrl); 
             return ctx
        }).Result

    let teardown ctx =
        //System.Threading.Tasks.Task.Delay(5000).GetAwaiter().GetResult()
        ctx.Browser.CloseAsync().GetAwaiter().GetResult()
        ctx

    let initiateLogin ctx =
        (task {
            let! login = ctx.Page.QuerySelectorAsync("button#login")
            let! _ = login.ClickAsync()
            return ctx
        }).Result
        
    let cookieConsent ctx =
        (task {
            // Click "Accept all" cookie consent button
            // 1000ms appear to be too little for the button to appear
            // Click will often fail because while the accept button is present in the DOM, it's invisible.
            // WaitForSelectorAsync doesn't take into account visibility unless query for an additional param similar to
            // "button#button_submit_query:not([disabled])"
            // ClickAsync() will check if the style attribute `visibility` is not `hidden`and if the element has a
            // visible bounding box (https://stackoverflow.com/questions/47014724/click-visible-elements-using-puppeteer)
            let! acceptAll = ctx.Page.WaitForSelectorAsync("button#c-p-bn", WaitForSelectorOptions(Timeout=3000, Visible = true))
            let! _ = acceptAll.ClickAsync()
            return ctx
        }).Result
        
    let selectIdP idP ctx =
        (task {
            let! _ = ctx.Page.QuerySelectorAsync("input#input-bank-query")
            let! _ = ctx.Page.TypeAsync("input#input-bank-query", idP)
            // Wait a little until JavaScript fires and populates the result list
            let! _ = ctx.Page.WaitForSelectorAsync(".ac-result-list-item", WaitForSelectorOptions(Timeout=1000))
            let! _ = ctx.Page.Keyboard.PressAsync("Enter")
            let! _ = ctx.Page.WaitForSelectorAsync("button#button_submit_query:not([disabled])")
            let! nextButton = ctx.Page.WaitForSelectorAsync("button#button_submit_query")
            let! _ = nextButton.ClickAsync()
            let! _ = ctx.Page.WaitForNavigationAsync()            
            return ctx
        }).Result

    let loginAs username ctx =
        (task {
            assert (ctx.Page.Url.StartsWith("https://testidpui.sandbox.yes.com/services/authz/10000001"))
            let! _ = ctx.Page.TypeAsync("input#ui-login-username-input", username)
            let! loginButton = ctx.Page.QuerySelectorAsync("input#ui-login-submit-button")
            let! _ = loginButton.ClickAsync()
            return ctx
        }).Result

    let confirmTwoFactorAuth ctx =
        (task {
            let! twoFactorLoginButton = ctx.Page.WaitForSelectorAsync("input#ui-second-factor-login-button", WaitForSelectorOptions(Timeout=5000))
            let! _ = twoFactorLoginButton.ClickAsync()
            return ctx
        }).Result
    
    let consentSharingWithRelyingParty ctx =
        (task {
            // Labelled "yes" in the UI
            let! consentButton = ctx.Page.WaitForSelectorAsync("input#ui-consent-submit-button", WaitForSelectorOptions(Timeout=5000))
            let! _ = consentButton.ClickAsync()
            // We're redirected back to http://localhost:3000/yes/oidccb?code=AXEIutTa6nVsE7C3LGX4-g.dSjpqUr5V5mTNlaVB5vmKA&iss=https://testidp.sandbox.yes.com/issuer/10000001
            let! _ = ctx.Page.WaitForNavigationAsync()
            return ctx
        }).Result
        
    let parseResult ctx =                  
        (task {            
            let! wellKnownOpenIdConfiguration = ctx.Page.WaitForSelectorAsync("pre#wellKnownOpenIdConfiguration")
            let! idToken = ctx.Page.WaitForSelectorAsync("pre#idToken")
            let! userInfo = ctx.Page.WaitForSelectorAsync("pre#userInfo")
            let! wellKnownOpenIdConfigurationValue = ctx.Page.EvaluateFunctionAsync("e => e.textContent", wellKnownOpenIdConfiguration)
            let! idTokenValue = ctx.Page.EvaluateFunctionAsync("e => e.textContent", idToken)
            let! userInfoValue = ctx.Page.EvaluateFunctionAsync("e => e.textContent", userInfo)
                                  
            let x = JObject.Parse (idTokenValue.ToString())
                                                                      
            return { ctx with
                         WellKnownOpenIdConfiguration = Some (wellKnownOpenIdConfigurationValue.ToString())
                         IdToken = Some (JObject.Parse (idTokenValue.ToString()))
                         UserInfo = Some (JObject.Parse (userInfoValue.ToString())) }
        }).Result

module BrowserTests =
    open BrowserSteps
    
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
    let ``First time login`` () =
        let ctx =
            setup "http://localhost:3000"
            |> initiateLogin
            |> cookieConsent
            |> selectIdP "testidp1"
            |> loginAs "test001"
            |> confirmTwoFactorAuth
            |> consentSharingWithRelyingParty
            |> parseResult
            |> teardown       
        
        Assert.Equal(Some wellKnownOpenIdConfigurationExpected, ctx.WellKnownOpenIdConfiguration)
        Assert.True(ctx.IdToken.IsSome)
        Assert.True(ctx.UserInfo.IsSome)
        
        let idToken = ctx.IdToken.Value
        let userInfo = ctx.UserInfo.Value
        
        // Remove parts of response that vary with each login.
        ["exp"; "iat"; "txn"; "nonce"]
        |> List.iter (fun propertyName -> idToken.Remove(propertyName) |> ignore)        
        Assert.Equal(JObject.Parse(idTokenExpected).ToString(), idToken.ToString())        

        ["txn"] |> List.iter (fun propertyName -> userInfo.Remove(propertyName) |> ignore)
        Assert.Equal(JObject.Parse(userInfoExpected).ToString(), userInfo.ToString())

        
        
        
