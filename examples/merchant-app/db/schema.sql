-- NAP store schema for the merchant app.
--
-- Every column here is required by a query in
-- `packages/nap-store-postgres/src/index.ts`. NAP ships no migration file, so
-- this is yours to own; §5.5 of the integration guide derives it column by
-- column with the statement that needs each one.
--
-- Two constraints are load-bearing rather than tidy, and getting them wrong
-- fails at runtime rather than at CREATE TABLE:
--   * nap_sessions.challenge_id UNIQUE  — the store's ON CONFLICT target, and
--     the "one session per challenge" guarantee.
--   * nap_acl PRIMARY KEY (app_id, pubkey) — same, for the ACL upsert.

CREATE TABLE nap_challenges (
  challenge_id        TEXT PRIMARY KEY,
  challenge           TEXT NOT NULL,
  npub                TEXT NOT NULL,
  pubkey              TEXT NOT NULL,
  auth_url            TEXT NOT NULL,
  auth_method         TEXT NOT NULL,
  state               TEXT NOT NULL,              -- issued | redeemed | expired | failed_terminal
  issued_at           BIGINT NOT NULL,            -- unix seconds, compared numerically
  expires_at          BIGINT NOT NULL,
  redeemed_event_id   TEXT,
  redeemed_session_id TEXT,
  result_cache_until  BIGINT,
  client_ip           TEXT,
  failure_count       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE nap_sessions (
  session_id             TEXT PRIMARY KEY,
  challenge_id           TEXT NOT NULL UNIQUE,
  access_token           TEXT NOT NULL UNIQUE,
  principal_npub         TEXT NOT NULL,
  principal_pubkey       TEXT NOT NULL,
  roles                  JSONB NOT NULL,
  permissions            JSONB NOT NULL,
  issued_at              BIGINT NOT NULL,
  expires_at             BIGINT NOT NULL,
  step_up_token          TEXT,
  step_up_expires_at     BIGINT,
  refresh_token          TEXT UNIQUE,
  refresh_expires_at     BIGINT,
  previous_refresh_token TEXT,
  revoked_at             BIGINT                   -- NULL = live
);

CREATE TABLE nap_acl (
  app_id               TEXT NOT NULL,
  pubkey               TEXT NOT NULL,             -- maps to AclRecord.principal_pubkey
  role                 TEXT NOT NULL,
  permission_overrides JSONB NOT NULL,
  suspended            BOOLEAN NOT NULL DEFAULT FALSE,
  suspended_at         TIMESTAMPTZ,               -- NOW(), read back as a string
  suspended_reason     TEXT,
  created_at           TIMESTAMPTZ DEFAULT NOW(),
  updated_at           TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (app_id, pubkey)
);

CREATE INDEX idx_nap_sessions_principal ON nap_sessions (principal_pubkey);

-- getByRefreshToken() matches either column, so both need one or every refresh
-- is a sequential scan of the session table.
CREATE INDEX idx_nap_sessions_refresh_token      ON nap_sessions (refresh_token);
CREATE INDEX idx_nap_sessions_prev_refresh_token ON nap_sessions (previous_refresh_token);

-- countOutstanding() runs on every /auth/init — the hottest unauthenticated
-- path there is.
CREATE INDEX idx_nap_challenges_expiry ON nap_challenges (expires_at) WHERE state = 'issued';
CREATE INDEX idx_nap_challenges_npub   ON nap_challenges (npub)       WHERE state = 'issued';
CREATE INDEX idx_nap_challenges_ip     ON nap_challenges (client_ip)  WHERE state = 'issued';
