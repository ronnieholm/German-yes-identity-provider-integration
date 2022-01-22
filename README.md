# German yes identity provider integration

Sample identity relying party conforming to the [integration
documentation](https://www.yes.com/docs/rp-devguide/latest/IDENTITY) and
inspired by the [yes Python sample](https://github.com/yescom/pyyes).

## Getting started

Download the mutual TLS client certificate to enable calls to the
`token_endpoint` and the `userinfo_endpoint` as defined in
`.well-known/openid-configuration`:

1. Go to the Relying Party Developer Guide, [Section 1. Sandbox Demo
   Client](https://yes.com/docs/rp-devguide/latest/ONBOARDING/#_sandbox_demo_client).
2. Click the `yes®, show the sandbox demo client data` button to unfold the
   client data.
3. Into the `src\YesIdentityRelyingParty` directory, copy the public certificate to a
   file named `cert.pem` and private key to a file named `key.pem`. These locations 
   are hardcoded into the GermanYesIdentityRelyingParty source code.

   The _Sandbox Demo Client Data_, consisting of Client ID, Account Chooser
   Redirect URL, and OpenID Connect Redirect URL are similarly hardcoded into
   the GermanYesIdentityRelyingParty source code.  

With `cert.pem` and `key.pem` in place:

    $ cd src/GermanYesIdentityRelyingParty
    $ dotnet build
    $ dotnet run

Go to the GermanYesIdentityRelyingParty login page at
[http://localhost:3000](http://localhost:3000) and click the yes button to
initiate a identity flow using one of the [test banks and test
users](https://yes.com/docs/rp-devguide/latest/ONBOARDING/#sandbox). For
instance, bank `testidp1` and username `test001`.

The yes account chooser remembers the previously selected bank through the
`preselect` cookie for the `https://accounts.sandbox.yes.com` domain. To reset
the account chooser for testing and development, go to
[https://accounts.sandbox.yes.com/cookie](https://accounts.sandbox.yes.com/cookie).

## Example of a successful identity response 

```
Configuration

https://testidp.sandbox.yes.com/issuer/10000002/.well-known/openid-configuration

ID token

{
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
  "iss": "https://testidp.sandbox.yes.com/issuer/10000002",
  "phone_number_verified": true,
  "nationalities": [
    "DE"
  ],
  "txn": "fa49c2d0-8229-4072-9f6c-ba0fc6af1f99",
  "given_name": "Given001",
  "title": "Dr.",
  "nonce": "157d7f93-4c4c-4379-932c-4d563ee0baf2",
  "https://www.yes.com/claims/tax_id": "1121081508150",
  "place_of_birth": {
    "locality": "Berlin",
    "country": "DE"
  },
  "aud": "sandbox.yes.com:e85ff3bc-96f8-4ae7-b6b1-894d8dde9ebe",
  "acr": "https://www.yes.com/acrs/online_banking_sca",
  "phone_number": "+49301111001",
  "salutation": "Herr",
  "exp": 1642801847,
  "iat": 1642800947,
  "family_name": "Family001",
  "email": "test001@platform.yes.com"
}

UserInfo

{
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
  "txn": "e5575148-ab0d-44fc-b1df-4615fbee3d59",
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
}
```

## Integration notes

### Maintaining client registration metadata

Yes doesn't provide a portal to view and update client metadata. For a non-demo
client registration, we have to manually track the state metadata, provided
during onboarding based on the [Testing and
Onboarding](https://www.yes.com/docs/rp-devguide/latest/ONBOARDING/index.html#_client_id_set_up).

### Client metadata

The set of claims are described in [Verified and Unverified
Data](https://www.yes.com/docs/rp-devguide/latest/IDENTITY/index.html#_verified_and_unverified_data). Also note that

- While unclear from yes documentation and identity provider metadata, actual
  use shows that every verified claim is also an unverified claim.
- Relying party implementation doesn't support the legacy yes version 1.x claims
  request format. Only yes version 2.x claims request format is supported.
- Requested claims in `Domain.fs` are based on `claims_supported` identity
  provider metadata from
  [testidp1](https://testidp.sandbox.yes.com/issuer/10000001/.well-known/openid-configuration).
  We assume claims from this identity provider represent real-world claims.
- The `sub` and `iss` claims in combination make up a pseudonymous user
  identifier. They're always present in the claims response (as part of the OIDC
  standard set of claims). Therefore, these claims are left out of requested
  claims. The `(sub, iss)` tuple is unique in the yes ecosystem and is what
  relying parties must use as a userid.
- Claims `email_verified`, `phone_number_verified`, `birth_family_name`,
  `birth_middle_name`, `birth_given_name` are missing from [Verified and
  Unverified
  Data](https://www.yes.com/docs/rp-devguide/latest/IDENTITY/index.html#_verified_and_unverified_data),
  but listed as part of identity provider metadata. That's because
  `email_verified` and `phone_number_verified` are OpenID standard claims as per
  [OpenID Connect Core 1.0, Section 5.1 Standard
  Claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims )
  and `birth_family_name`, `birth_middle_name`, and `birth_given` are part of
  [OpenID Connect for Identity Assurance 1.0, Section 4.1 Additional Claims
  about
  End-Users](https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html#section-4.1).
  (partially authored by yes.com).
- For the Account Chooser Redirect URI, https://localhost is allowed, but only
  one URI per client ID is allowed.
- For OpenID Connect Redirect URI, multiple URLs are allowed, but
  https://localhost is disallowed. For localhost, only the http protocol is
  currently (January 22, 2022) supported, possibly due to a too strict
  interpretation of [OAuth 2.0 for Native Apps, Loopback Redirect
  Considerations](https://datatracker.ietf.org/doc/html/rfc8252#section-8.3).
  yes is working on fix to allow the https protocol with localhost which would
  simplify relying party development.
- *Undocumented*: by default actual client registrations (but not the sandbox
  client) has branding for bank test identity providers disabled. Yes partner
  support can enable branding per client ID basis. Branding affects automated
  tests as HTML elements and the inclusion of JavaScript differs.
- *Undocumented*: according to yes partner support, for both regular and
  verified claims, `birth_family_name`, `birth_middle_name`, and
  `birth_given_name` are advertised in documentation and identity provider
  metadata, but are not currently (January 22, 2022) supported by bank identity
  provider. If customers include these claims as part of an actual client
  registration, Yes partner support will remove those from the client's allowed
  claims. This also means that the sandbox client doesn't support these claims,
  and that test identity providers will respond with an error if these claims
  requested. From the error message, you'd never guess this to be the cause:

The following claims request, which must be provided to yes partner support as
part of an actual client registration, returns every supported 2.x claims from
both the the ID token and through the userinfo endpoint.

```json
{
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
}
```

### Debugging

Out of the box, Fiddler only supports the authentication flow up until code
exchange for tokens. Code exchange and any subsequent use of the access token
requires [mutual TLS
configuration](https://docs.telerik.com/fiddler/configure-fiddler/tasks/respondwithclientcert).

## Resources

- [Demo client certificates, client_id, test IdPs, and test users](https://yes.com/docs/rp-devguide/latest/ONBOARDING).
- [Identity Relying Party Developer Guide](https://www.yes.com/docs/rp-devguide/latest/IDENTITY).
