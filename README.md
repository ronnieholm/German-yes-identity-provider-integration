# German Yes IdentityProvider Integration

Example identity relying party conforming to the [integration
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

## Resources

- [Demo client certificates, client_id, test IdPs, and test users](https://yes.com/docs/rp-devguide/latest/ONBOARDING).
- [Identity Relying Party Developer Guide](https://www.yes.com/docs/rp-devguide/latest/IDENTITY).