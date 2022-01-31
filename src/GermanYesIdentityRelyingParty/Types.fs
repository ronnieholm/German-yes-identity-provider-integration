namespace GermanYesIdentityRelyingParty

module Identity =
    open Newtonsoft.Json.Linq    

    type IdToken = IdToken of JObject
    type UserInfo = UserInfo of JObject

module Configuration = 
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
          Jwt: JObject option }
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
              Jwt = None }