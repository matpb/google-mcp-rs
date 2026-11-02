# MCP tokens in HTTP mode

This page covers the tokens `google-mcp` issues to MCP clients when it runs as an HTTP server (`google-mcp http`). It explains how clients authenticate, how access and refresh tokens live and die, and which attacks each rule is there for.

**Stdio mode is not affected.** `google-mcp stdio` is a single-user child process. It never issues MCP tokens, and it refreshes Google access on its own from the stored Google refresh token. Nothing on this page applies to it.

Two different "refresh tokens" exist, and they should not be confused:

| Token | Issued by | Held by | Stored on the server as |
|---|---|---|---|
| Google refresh token | Google | this server only | AES-256-GCM ciphertext, bound to the Google `sub` |
| MCP refresh token (`mcpr_...`) | this server | the MCP client | SHA-256 hash only |

The rest of this page is about the MCP tokens.

## At a glance

| Rule | Value | Configurable |
|---|---|---|
| Access token (JWT) lifetime | 1 hour | `ACCESS_TOKEN_LIFETIME_SECS`, clamped to 60 s .. 30 days |
| Refresh token idle lifetime | 30 days, reset on every refresh | no |
| Refresh token absolute lifetime | 90 days from the original sign-in | no |
| Reuse grace for a retired refresh token | 10 s, re-serves the same successor | `REFRESH_REUSE_GRACE_SECS`, clamped to 0 .. 60 s, `0` disables |
| Retired tokens kept per family for replay detection | newest 1000 | no |
| Refresh token entropy | 256 bits from the OS RNG | no |
| Client secret entropy | 122 bits (random UUIDv4) | no |
| Authorization code lifetime | 5 minutes, single use | no |
| Client authentication methods | `client_secret_basic`, `client_secret_post`, `none` | chosen by the client at registration |

## Client registration and authentication

Clients register themselves at `/oauth/register` (RFC 7591). The server records the `token_endpoint_auth_method` the client asks for and enforces it on every later token request.

| Requested method | What the client gets | What `/oauth/token` requires |
|---|---|---|
| omitted | treated as `client_secret_basic` (RFC 7591 default) | the secret, in an `Authorization: Basic` header or the form |
| `client_secret_basic` | `client_secret`, `client_secret_expires_at: 0` | the secret, in an `Authorization: Basic` header or the form |
| `client_secret_post` | `client_secret`, `client_secret_expires_at: 0` | the secret, in an `Authorization: Basic` header or the form |
| `none` (public client) | no secret | `client_id` only; PKCE and refresh-token rotation protect it |
| anything else | `400 invalid_client_metadata`, nothing stored | |

The server enforces that a secret-holding client presents a valid secret. It does not insist on the transport the client named at registration, because that adds breakage without adding protection.

Rules at the token endpoint:

- **The client is authenticated before anything is consumed.** A wrong or missing secret returns `401 invalid_client` and leaves the authorization code or refresh token untouched. So whoever knows a `client_id`, which is visible in authorization URLs, cannot burn a legitimate user's code or log them out by sending bad credentials.
- An unknown client and a wrong secret get the same answer, so the endpoint does not reveal which clients exist.
- A `401` carries `WWW-Authenticate: Basic realm="google-mcp"` when the request used Basic.
- Basic credentials are decoded per RFC 6749 section 2.3.1: `+` becomes a space, then percent-decoding.
- Sending both a Basic header and a form `client_secret` is `400 invalid_request`, as is a form `client_id` that differs from the Basic one. Several Basic headers are `401`.
- Secrets are stored as SHA-256 hashes and compared in constant time.

### Clients registered before 1.3.0

Earlier versions issued a secret to every client but recorded no method, and accepted token requests without the secret. Those registrations have no recorded method, and are treated as **public clients**:
- A request without a secret is accepted, as before.
- A request that does send a secret must send the right one.

Forcing them to present a secret would break every existing HTTP-mode user on their next refresh, with no automatic recovery. To get full enforcement for a client, delete its row from `mcp_clients` and let the client register again. Registrations that were never used are pruned after 24 hours anyway.

## Authorization code grant

1. Authenticate the client (see above).
2. Consume the code. Codes are single use and live 5 minutes.
3. The code must belong to the authenticated client. A code presented by another client is refused with `invalid_grant` and stays consumed (RFC 6749 section 4.1.2).
4. `redirect_uri` must match the authorization request when sent. The PKCE `S256` verifier is required and must match.
5. If both the authorization request and the token request name a `resource` (RFC 8707), they must be equal, else `invalid_target`.
6. The response carries an access token, its `expires_in` and the first refresh token of a new **family**.

## Refresh token grant and rotation

Every successful refresh returns a new access token and a **new refresh token**, and retires the one presented. All the refresh tokens descended from one sign-in form a family.

Each refresh runs as a single SQLite transaction. Every check happens before anything is written; then the server either rotates or refuses. A database error rolls everything back, so a token is never consumed without its successor being stored.

| Situation | Response | Effect on the family |
|---|---|---|
| Live token, right client | `200`, new pair | presented token retired, successor stored |
| Retired token, within the grace window, its successor not used yet | `200`, a new access token and the **same** successor as before | nothing written |
| Retired token, outside the grace window, or after its successor was used | `400 invalid_grant` | **whole family deleted** (RFC 9700 section 4.14.2) |
| Token presented by another registered client | `400 invalid_grant` | **whole family deleted** |
| Different `resource` than the original grant | `400 invalid_target` | nothing changes, the token stays usable |
| Unknown, expired (30 days idle) or past 90 days since sign-in | `400 invalid_grant` | nothing to change |
| Account revoked after the family began, or disconnected | `400 invalid_grant` | whole family deleted |
| Client authentication failed | `401 invalid_client` | nothing changes |

### Why a reuse grace exists

Without one, two ordinary events look exactly like theft:
- a client that sends a refresh, loses the response to a network error, and retries;
- two processes sharing one stored credential that refresh at the same moment.

Both present a retired token, and a strict server would delete the family and force the user to sign in again.

For `REFRESH_REUSE_GRACE_SECS` (10 s by default) after a token is retired, presenting it again returns the successor it was already rotated into, as long as nobody has used that successor yet.
- The family never forks: there is still exactly one live refresh token.
- To make that possible, the successor is kept on the retired row encrypted with AES-256-GCM under `STORAGE_ENCRYPTION_KEY`, bound to the retired token's hash. The ciphertext is wiped once the window has passed (60 s at most).
- Any use after the window, or after the successor has been used, is treated as theft.

The cost is small. An attacker who replays a copied token within those seconds receives the same successor the legitimate client holds. The next time one of them uses it, the other's use is a replay, and the family is deleted. Operators who prefer zero tolerance can set `REFRESH_REUSE_GRACE_SECS=0`, so no successor is ever stored and any reuse deletes the family.

Retired tokens stay in the database until they expire, so that a replay weeks later is still detected. At most the newest 1000 retired tokens are kept per family, which bounds what a client rotating in a loop can make the server store.

## Revocation

- `google-mcp accounts revoke <email-or-sub>` does three things:
  - writes a per-account tombstone, which invalidates every access token issued before it at the next `/mcp` call;
  - deletes the account's MCP refresh tokens and its stored Google credentials;
  - best-effort revokes the grant at Google.
- A family that began before the tombstone is refused even if a row survived.
- When Google answers `invalid_grant` for the stored Google refresh token (the user removed access in their Google account), the server writes the same tombstone and deletes the MCP refresh tokens.
- There is no RFC 7009 revocation endpoint for clients. Access tokens are short-lived, and the operator command above cuts an account off immediately.

## Responses are never cached

Every response from `/oauth/token` and `/oauth/register` carries `Cache-Control: no-store` and `Pragma: no-cache`, success or error (RFC 6749 section 5.1). The consent page sends `Referrer-Policy: same-origin`, so its URL never reaches Google or the client as a referrer. It is not `no-referrer`, because that makes browsers send `Origin: null` on the consent form and the origin check would refuse it.

## Threats and what stops them

| Threat | Mitigation |
|---|---|
| A leaked access token | Valid for at most `ACCESS_TOKEN_LIFETIME_SECS` (1 hour by default); `accounts revoke` cuts it off at once. `/mcp` also refuses any token whose lifetime is longer than the configured one (plus 60 s), so lowering the setting retires longer tokens that are still outstanding. |
| A leaked refresh token of a confidential client | Useless without that client's secret. |
| A leaked refresh token of a public client | Rotation: the first time both the thief and the real client use the family, it is deleted. The 90-day cap bounds a family nobody notices. |
| A thief replays a token through their own registered client | Detected as wrong-client use; the family is deleted. |
| Someone who knows a `client_id` sends bad credentials to lock a user out | Authentication runs first and a failure consumes nothing. |
| A stolen authorization code | Needs the PKCE verifier, and the client secret for confidential clients; single use, 5 minutes. |
| Tokens or secrets read from the database | Only SHA-256 hashes of MCP refresh tokens and client secrets are stored; Google refresh tokens are encrypted. |
| Tokens in logs | The server never logs tokens, secrets, codes or `Authorization` headers; replay and wrong-client events log the `client_id` only. |
| Responses kept by a cache or proxy | `no-store` on every token and registration response. |

### Not covered

- **Rate limiting.** The application has none; put a reverse proxy with request limits in front of a public instance (see the README's deployment posture). Secrets and tokens have too much entropy to guess, but open registration can be flooded up to its 10,000-row cap.
- **Sender-constrained tokens.** DPoP and mutual TLS are not implemented; for public clients, rotation is the protection RFC 9700 accepts instead.
- **`JWT_SECRET` compromise.** Access tokens are HS256-signed with one server secret. Whoever holds it can mint tokens; rotate it to log everyone out.

## Upgrading

- Database migrations `003` and `004` run on start. Before migrating an existing database, the server copies it to `<DATABASE_URL>.pre-00N.bak`. `004` recreates the refresh-token table, so a database that ran an unreleased development build of this feature starts clean.
- Access tokens issued by earlier versions lived 30 days. `/mcp` now refuses them because their lifetime exceeds the configured one, so every HTTP-mode client signs in once more after the upgrade, then refreshes silently.
- Clients registered before 1.3.0 keep working as public clients (see above).
