-- Confused-deputy consent interstitial + client hygiene + revocation.

ALTER TABLE mcp_clients ADD COLUMN last_used_at INTEGER;
UPDATE mcp_clients SET last_used_at = CAST(strftime('%s','now') AS INTEGER)
    WHERE last_used_at IS NULL;

-- browser_binding: SHA-256 hex of the per-state cookie secret.
-- approved: flips to 1 only via /authorize/consent.
ALTER TABLE oauth_states ADD COLUMN browser_binding TEXT;
ALTER TABLE oauth_states ADD COLUMN approved INTEGER NOT NULL DEFAULT 0;
ALTER TABLE oauth_states ADD COLUMN login_hint TEXT;

-- No foreign key: must survive deletion of the oauth_accounts row.
CREATE TABLE revoked_subs (
    google_sub  TEXT PRIMARY KEY,
    not_before  INTEGER NOT NULL
);
