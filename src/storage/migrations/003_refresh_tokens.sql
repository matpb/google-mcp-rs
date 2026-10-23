-- Rotating MCP refresh tokens. Only the SHA-256 of a token is stored. A used
-- row is kept until it expires so that a replayed token revokes its family.
CREATE TABLE mcp_refresh_tokens (
    token_hash     TEXT PRIMARY KEY,
    family_id      TEXT NOT NULL,
    mcp_client_id  TEXT NOT NULL,
    google_sub     TEXT NOT NULL,
    resource       TEXT,
    issued_at      INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    used_at        INTEGER
);
CREATE INDEX mcp_refresh_tokens_family ON mcp_refresh_tokens (family_id);
CREATE INDEX mcp_refresh_tokens_sub ON mcp_refresh_tokens (google_sub);
