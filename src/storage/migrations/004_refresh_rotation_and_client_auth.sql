-- Rebuild mcp_refresh_tokens (the unreleased 003 schema lacks the rotation columns); tokens issued so far are dropped.
DROP TABLE IF EXISTS mcp_refresh_tokens;
CREATE TABLE mcp_refresh_tokens (
    token_hash       TEXT PRIMARY KEY,
    family_id        TEXT NOT NULL,
    mcp_client_id    TEXT NOT NULL,
    google_sub       TEXT NOT NULL,
    resource         TEXT,
    issued_at        INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL,
    used_at          INTEGER,
    family_issued_at INTEGER NOT NULL,  -- absolute cap and revocation reference
    successor_nonce  BLOB,              -- sealed successor token, kept only for the reuse grace
    successor_ct     BLOB
);
CREATE INDEX mcp_refresh_tokens_family ON mcp_refresh_tokens (family_id);
CREATE INDEX mcp_refresh_tokens_sub ON mcp_refresh_tokens (google_sub);
CREATE INDEX mcp_refresh_tokens_expires ON mcp_refresh_tokens (expires_at);

-- NULL: registered before this column existed; treated as a public client whose secret is optional.
ALTER TABLE mcp_clients ADD COLUMN token_endpoint_auth_method TEXT;
