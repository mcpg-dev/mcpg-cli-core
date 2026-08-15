# mcpg-cli-core

> Client-side plumbing shared by the MCPG command-line tools: OIDC PKCE login, stored credentials, Bearer HTTP, SSE phase rendering, and state-dir conventions.

Everything an MCPG CLI needs to sign a user in and talk to a control plane, and
nothing else. It owns the browser-driven OIDC authorization-code flow with PKCE,
the `credentials.json` file that flow maintains, the JWKS-verifying OIDC client
underneath it, the Bearer-authenticated HTTP client control-plane commands use,
the Server-Sent-Events phase renderer for long-running provisioning streams, and
the `~/.mcpg` state-directory conventions. It deliberately does not depend on the
control-plane server or its database and gRPC dependency tree: a tenant CLI
should not link a server in order to sign someone in. Each module sits behind its
own Cargo feature, so a consumer that wants one of them does not pay for the
rest.

## What's here
- `paths` (feature `paths`) — `default_state_dir()` resolves `MCPG_STATE_DIR`
  when set, else `.mcpg` under the user's home directory, else `./mcpg-state`;
  plus `default_db_path()`, `db_url()` and `ensure_dir()`.
- `oidc` (feature `oidc`) — `OidcClient` with cached discovery and JWKS:
  `discovery()`, `authorize_url()`, `exchange_code()`, `verify_signed_claims()`,
  `verify_id_token()`. Also `PkcePair::generate()` (32 random bytes, S256
  challenge), `random_state()`, `DiscoveryDoc`, `TokenResponse` and
  `IdTokenClaims` (with `resolved_email()` and `string_claim()` for reading a
  deployment-configured tenant claim by name). Works against any provider that
  serves `/.well-known/openid-configuration`.
- `login` (feature `login`, implies `oidc` + `paths`) — `run()` drives the whole
  flow: bind `127.0.0.1:0`, open the browser, receive the callback, compare
  `state`, exchange the code, verify the `id_token` under the issuer's JWKS, and
  persist `StoredCredentials`. `logout()` removes the file; `ensure_fresh()`
  redeems a stored refresh token when the `id_token` is inside its 60-second
  expiry skew.
- `client` (feature `client`, implies `login`) — `bearer_client()` builds a
  `reqwest::Client` that refreshes first and then attaches `Authorization:
  Bearer` on every request, plus the `x-mcpg-license` header (`LICENSE_HEADER`)
  when a licence is stored. A loopback control plane needs no token, and with no
  credentials on disk no header is attached and commands still work. Also
  `bearer_token()`, `cred_field()`, `program_invocation()` (renders `mcpg-cloud`
  as `mcpg cloud` in hint strings) and `cp_error()` (appends a re-login hint on
  a 401).
- `stream` (feature `stream`) — `stream_phases()` drains an SSE response,
  printing one line per phase event and surfacing `instance_uid` and endpoint
  URLs as soon as an event carries them.
- `context` (feature `context`) — the sticky `Context { org, workspace, env }`
  stored at `<state_dir>/context.json`, with `load()` and `save()`. A missing or
  corrupt file degrades to an empty context rather than an error, so flag and
  environment fallbacks still apply.

Credential handling is the security-load-bearing part of this crate:
`credentials.json` is written to a sibling temporary file created `0600` from
the start and then renamed over the target, so neither a umask race nor a crash
mid-write can leave a readable or truncated file after the issuer has already
rotated the refresh token. `ensure_fresh()` refuses to POST a refresh token to a
token endpoint that is neither HTTPS nor loopback. Both the bearer and licence
header values are marked sensitive so they stay out of logs. A `kid` the cached
JWKS does not know triggers at most one refetch per 30 seconds, so a flood of
forged tokens cannot be amplified into a request storm against the identity
provider. Verification pins issuer and audience and allows 60 seconds of clock
skew.

## Used by
- `apps/cloud/cli` (`mcpg-cloud`) and `apps/cloud/admin` (`mcpg-admin`) — the
  full default feature set.
- `apps/control-plane/server` — the `oidc` module for its browser login and
  Bearer verification, plus `paths` and `client` for its own state dir and its
  calls back into a CP.
- `apps/gateway` — `default-features = false, features = ["paths"]`, so the
  gateway gets the state-dir helpers without the login stack.

## Build / test
```bash
cargo build -p mcpg-cli-core
cargo test  -p mcpg-cli-core
cargo build -p mcpg-cli-core --no-default-features --features paths   # the light path
```

## Licence
Apache-2.0.

## See also
- [The `mcpg` CLI](https://mcpg.dev/docs/reference/cli)
- [`mcpg cloud` reference](https://mcpg.dev/docs/reference/cli/cloud)
- [`mcpg admin` reference](https://mcpg.dev/docs/reference/cli/admin)
- `apps/cloud/cli` — the CLI that exercises every module in this crate.
