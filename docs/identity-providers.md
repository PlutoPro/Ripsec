# Identity providers

[← README](../README.md)

The portal signs users in with the OpenID Connect **authorization code flow with PKCE**. Any compliant provider
should work. **Only Keycloak is tested**; the other sections are guidance to start from, and corrections are
welcome.

- [What Ripsec needs from a provider](#what-ripsec-needs-from-a-provider)
- [Roles](#roles)
- [Keycloak](#keycloak)
- [Authentik](#authentik)
- [Okta](#okta)
- [Microsoft Entra ID](#microsoft-entra-id)
- [Auth0](#auth0)
- [Google](#google)
- [Checking your setup](#checking-your-setup)

## What Ripsec needs from a provider

| Requirement | Detail |
|---|---|
| Discovery | `<issuer>/.well-known/openid-configuration` |
| Flow | Authorization code, PKCE with `S256` |
| Redirect URI | `<web.public_url>/auth/callback`, exactly |
| Client type | Public (PKCE only), or confidential with a secret |
| Client authentication | If confidential, the secret is sent **in the request body** (`client_secret_post`). Basic authentication is not used |
| ID token | Signed with an asymmetric algorithm (RS, PS or ES). `HS*` is refused |
| ID token claims | `sub`, `iss`, `aud` (your client ID), `exp`, `nonce` |
| Name shown | The first of `preferred_username`, `email`, `name`, otherwise `sub` |

## Roles

Roles are read from the **ID token** (not the access token or userinfo) at the claim named by `roles_claim`.
The claim may be a list of strings or a single string. The name is first looked up literally, so URL-shaped
names such as `https://example.com/roles` work, and then as a dotted path such as `realm_access.roles`.

```toml
[oidc]
roles_claim = "roles"
admin_role  = "vpn-admin"   # manage all devices, add site gateways
user_role   = "vpn-user"    # required to use the portal at all
```

> **Set `user_role`** unless every account at your provider should be able to get VPN access. Administrators do
> not need `user_role` as well.

## Keycloak

Tested with Keycloak 26. Commands and menu names are for its admin console.

**1. Realm.** Create one for VPN users, for example `ripsec`. Turn on brute force detection
(*Realm settings → Security defenses*).

**2. Client.** *Clients → Create client*:

| Setting | Value |
|---|---|
| Client type | OpenID Connect |
| Client ID | `ripsec-portal` |
| Client authentication | Off for a public client, or On and note the secret |
| Authentication flow | Standard flow only |
| Valid redirect URIs | `https://vpn.example.com/auth/callback` |
| Proof Key for Code Exchange (*Advanced*) | `S256` |

**3. Roles.** *Realm roles → Create role*: `vpn-admin` and `vpn-user`. Assign them to users or, better, to
groups.

**4. Put roles in the ID token.** Keycloak does not do this by default. *Clients → ripsec-portal → Client
scopes → ripsec-portal-dedicated → Add mapper → By configuration → User Realm Role*:

| Setting | Value |
|---|---|
| Name | `roles in id token` |
| Token Claim Name | `roles` |
| Multivalued | On |
| Add to ID token | **On** |

**5. Ripsec.**

```toml
[oidc]
issuer      = "https://sso.example.com/realms/ripsec"
client_id   = "ripsec-portal"
roles_claim = "roles"
admin_role  = "vpn-admin"
user_role   = "vpn-user"
```

For a confidential client also set `RIPSEC_OIDC_CLIENT_SECRET`.

[`deploy/keycloak/ripsec-realm.json`](../deploy/keycloak/ripsec-realm.json) is the realm used by the
evaluation stack. You can import it as a starting point, but **delete its demo users** and change the redirect
URI first.

**Reaching Keycloak under two names** (as in Docker): keep `issuer` as the URL browsers use, and point
`discovery_url` at the internal one. Keycloak needs `KC_HOSTNAME` set to the public URL and
`KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true`.

## Authentik

*Not tested.*

1. Create an **OAuth2/OpenID Provider** and an **Application** that uses it. Authorization code flow; strict
   redirect URI `https://vpn.example.com/auth/callback`. Choose a signing key, so ID tokens are signed with
   RS256 and not HS256.
2. Create groups `vpn-admin` and `vpn-user`. Group names usually arrive in the `groups` claim with the
   `profile` scope.

```toml
[oidc]
issuer      = "https://auth.example.com/application/o/ripsec/"   # trailing slash
client_id   = "..."
roles_claim = "groups"
user_role   = "vpn-user"
```

## Okta

*Not tested.*

1. Create an OIDC application using the authorization code flow with PKCE. Because Ripsec sends any client
   secret in the request body, a public client with PKCE only is the simplest choice.
2. Add a **groups claim** to the ID token, filtered to the VPN groups.

```toml
[oidc]
issuer      = "https://example.okta.com"   # or https://example.okta.com/oauth2/default
client_id   = "..."
scopes      = "openid profile email groups"
roles_claim = "groups"
user_role   = "vpn-user"
```

## Microsoft Entra ID

*Not tested.*

1. *App registrations → New registration*, redirect URI of type **Web**:
   `https://vpn.example.com/auth/callback`.
2. Create a client secret.
3. *App roles*: create roles with the values `vpn-admin` and `vpn-user`, then assign users or groups to them
   under *Enterprise applications*. App roles appear in the ID token's `roles` claim.

```toml
[oidc]
issuer      = "https://login.microsoftonline.com/<tenant-id>/v2.0"
client_id   = "<application (client) id>"
roles_claim = "roles"
user_role   = "vpn-user"
```

Use your tenant ID, not `common`: the issuer must match exactly.

## Auth0

*Not tested.*

1. Create a **Regular Web Application**, add the callback URL, and use the `Post` token endpoint
   authentication method.
2. Add roles to the ID token with a post-login Action, under a namespaced claim:

```js
exports.onExecutePostLogin = async (event, api) => {
  api.idToken.setCustomClaim("https://vpn.example.com/roles", event.authorization?.roles ?? []);
};
```

```toml
[oidc]
issuer      = "https://YOUR_TENANT.us.auth0.com/"   # trailing slash
client_id   = "..."
roles_claim = "https://vpn.example.com/roles"
user_role   = "vpn-user"
```

## Google

*Not tested.* Google's ID tokens carry no roles. Without `user_role`, **every account the OAuth client allows
can enrol**, so restrict the client to your own organisation ("Internal" audience) at Google. Nobody will be a
portal administrator, so there can be no site gateways.

```toml
[oidc]
issuer    = "https://accounts.google.com"
client_id = "....apps.googleusercontent.com"
# client secret in RIPSEC_OIDC_CLIENT_SECRET
```

## Checking your setup

1. `curl <issuer>/.well-known/openid-configuration` and compare its `issuer` with yours, character for
   character.
2. Open the portal at exactly `public_url` and sign in.
3. If it fails, read the server log: `sign in rejected: ...` gives the reason.
4. "Your account is not allowed to use this VPN" means the sign-in worked but the roles did not arrive. Decode
   an ID token for that client and check the claim named by `roles_claim` is in it.
5. An administrator sees "(administrator)" next to their name.
