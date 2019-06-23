# cfjwt

Command line utility for parsing JWTs and getting claims

Can verify a token by adding `-verify` or `-v`.

```
$ echo 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjY1OTNkOWFjZjkyY ...' | cfjwt
{
  "alg": "RS256",
  "kid": "6593d9acf92b87faca750a78f7b308a844a57ae51c25ed7322fe06d6d8a6b9b0",
  "typ": "JWT"
}

{
  "aud": [
    "32eafc7626e974616deaf0dc3ce63d7bcbed58a2731e84d06bc3cdf1b53c4551"
  ],
  "email": "test@example.com",
  "exp": 1551854755,
  "iat": 1549226755,
  "iss": "https://james.cloudflareaccess.com",
  "nonce": "6c464bf601793547fcc456f50f5257b51c9b245401413f97d724a06ed86df77D",
  "sub": "b2790424-651e-439b-998e-ef9f27b0ddee"
}
```
