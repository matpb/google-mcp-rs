-- Per-user Google account state. Refresh token is encrypted at rest with
-- AES-256-GCM; AAD is bound to `google_sub` so ciphertexts cannot be
-- swapped across rows. Keyed by Google's stable `sub` (never by email).
CREATE TABLE oauth_accounts (
    google_sub             TEXT PRIMARY KEY,
    email                  TEXT NOT NULL,
    refresh_token_ct       BLOB NOT NULL,
    refresh_token_nonce    BLOB NOT NULL,
    scopes                 TEXT NOT NULL,        -- space-separated
    created_at             INTEGER NOT NULL,     -- unix seconds
    updated_at             INTEGER NOT NULL,
    last_refresh_at        INTEGER
);
CREATE INDEX idx_oauth_accounts_email ON oauth_accounts(email);

-- MCP clients self-registered via RFC 7591 dynamic client registration.
-- These are OUR clients, completely separate from Google's OAuth client.
-- Secret is stored as an Argon2id PHC string (salt + params embedded).
CREATE TABLE mcp_clients (
    client_id              TEXT PRIMARY KEY,
    client_secret_hash     TEXT NOT NULL,
    redirect_uris          TEXT NOT NULL,        -- JSON array
    client_name            TEXT,
    created_at             INTEGER NOT NULL
);

-- Single-use authorization codes minted by /authorize, redeemed at /oauth/token.
CREATE TABLE oauth_codes (
    code                   TEXT PRIMARY KEY,
    mcp_client_id          TEXT NOT NULL,
    mcp_redirect_uri       TEXT NOT NULL,
    code_challenge         TEXT NOT NULL,        -- PKCE S256 challenge
    google_sub             TEXT NOT NULL,
    resource               TEXT,                 -- RFC 8707 audience
    expires_at             INTEGER NOT NULL,     -- unix seconds (+300)
    FOREIGN KEY (mcp_client_id) REFERENCES mcp_clients(client_id) ON DELETE CASCADE,
    FOREIGN KEY (google_sub) REFERENCES oauth_accounts(google_sub) ON DELETE CASCADE
);

-- Opaque state tokens minted by /authorize and threaded through Google's
-- consent screen back to /oauth/google/callback. Single-use, 5-minute TTL.
CREATE TABLE oauth_states (
    state_id               TEXT PRIMARY KEY,
    mcp_client_id          TEXT NOT NULL,
    mcp_redirect_uri       TEXT NOT NULL,
    mcp_state              TEXT,                 -- echoed back to MCP client
    code_challenge         TEXT NOT NULL,
    code_challenge_method  TEXT NOT NULL,
    resource               TEXT,
    expires_at             INTEGER NOT NULL,
    FOREIGN KEY (mcp_client_id) REFERENCES mcp_clients(client_id) ON DELETE CASCADE
);
