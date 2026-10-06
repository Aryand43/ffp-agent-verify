-- ffp-agent-verify schema. Idempotent: safe to run on every startup.

CREATE TABLE IF NOT EXISTS airlines (
    airline_id      TEXT PRIMARY KEY,                -- IATA-style code, e.g. 'AC', 'SQ'
    name            TEXT NOT NULL,
    issuer          TEXT NOT NULL UNIQUE,            -- `iss` of the airline's authorization server
    jwks            JSONB,                           -- inline JWKS for the AS signing keys ...
    jwks_uri        TEXT,                            -- ... or where to fetch them
    api_key_hash    TEXT NOT NULL UNIQUE,            -- sha256 of the key the airline uses to call /verify
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (jwks IS NOT NULL OR jwks_uri IS NOT NULL)
);

-- One row per airline; history kept in airline_policy_versions for audit / rollback.
CREATE TABLE IF NOT EXISTS airline_policies (
    airline_id      TEXT PRIMARY KEY REFERENCES airlines(airline_id) ON DELETE CASCADE,
    version         INTEGER NOT NULL,
    policy          JSONB NOT NULL,                  -- validated AirlinePolicy (limits, vpn_tolerance, weights, thresholds)
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS airline_policy_versions (
    airline_id      TEXT NOT NULL REFERENCES airlines(airline_id) ON DELETE CASCADE,
    version         INTEGER NOT NULL,
    policy          JSONB NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by      TEXT NOT NULL,
    PRIMARY KEY (airline_id, version)
);

-- A monitoring tool (the software product), identified by its signing key.
CREATE TABLE IF NOT EXISTS authorized_tools (
    tool_id             TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    developer_contact   TEXT NOT NULL,
    public_jwk          JSONB NOT NULL,
    jkt                 TEXT NOT NULL UNIQUE,         -- RFC 7638 thumbprint = signature keyid = JWT cnf.jkt
    redirect_uris       TEXT[] NOT NULL DEFAULT '{}',
    management_token_hash TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked')),
    status_reason       TEXT,
    risk_score          REAL NOT NULL DEFAULT 0,      -- max grant score across airlines, refreshed by the worker
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen           TIMESTAMPTZ
);

-- A user's authorization of a tool at one airline (the long-lived thing behind the
-- short-lived access tokens). member_ref = sha256(airline_id || ':' || sub), never the raw FFP number.
CREATE TABLE IF NOT EXISTS grants (
    grant_id        TEXT PRIMARY KEY,                -- sha256(airline:tool:member_ref)[:32]
    tool_id         TEXT NOT NULL REFERENCES authorized_tools(tool_id) ON DELETE CASCADE,
    airline_id      TEXT NOT NULL REFERENCES airlines(airline_id) ON DELETE CASCADE,
    member_ref      TEXT NOT NULL,
    auth_time       TIMESTAMPTZ,                     -- when the member consented (JWT auth_time)
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    status_reason   TEXT,
    risk_score      REAL NOT NULL DEFAULT 0,
    UNIQUE (tool_id, airline_id, member_ref)
);
CREATE INDEX IF NOT EXISTS grants_member_idx ON grants (airline_id, member_ref);

-- Each airline-issued access token we've seen (5-15 min lifetime).
CREATE TABLE IF NOT EXISTS credentials (
    cred_id         TEXT PRIMARY KEY,                -- JWT jti
    grant_id        TEXT NOT NULL REFERENCES grants(grant_id) ON DELETE CASCADE,
    tool_id         TEXT NOT NULL,
    airline_id      TEXT NOT NULL,
    issued_at       TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    route_scope     TEXT[],                          -- ffp_routes claim, NULL = any route
    first_seen      TIMESTAMPTZ NOT NULL,
    last_seen       TIMESTAMPTZ NOT NULL,
    usage_count     INTEGER NOT NULL DEFAULT 0,
    ip_history      INET[] NOT NULL DEFAULT '{}'     -- distinct IPs, capped at 32
);
CREATE INDEX IF NOT EXISTS credentials_grant_idx ON credentials (grant_id, last_seen DESC);

-- Every verified search (time-series; a hypertable when TimescaleDB is present).
CREATE TABLE IF NOT EXISTS search_requests (
    ts              TIMESTAMPTZ NOT NULL,
    request_id      TEXT NOT NULL,
    airline_id      TEXT NOT NULL,
    lane            TEXT NOT NULL,                   -- authenticated | unauthenticated
    tool_id         TEXT,
    grant_id        TEXT,
    cred_id         TEXT,
    client_ip       INET,
    device_ref      TEXT,
    origin          TEXT,
    destination     TEXT,
    travel_date     DATE,
    cabin           TEXT,
    decision        TEXT NOT NULL,
    score           REAL NOT NULL,
    reason_codes    TEXT[] NOT NULL DEFAULT '{}',
    verify_latency_us INTEGER NOT NULL,
    risk_signals    JSONB
);
CREATE INDEX IF NOT EXISTS search_requests_tool_idx ON search_requests (tool_id, ts DESC);
CREATE INDEX IF NOT EXISTS search_requests_airline_idx ON search_requests (airline_id, ts DESC);
CREATE INDEX IF NOT EXISTS search_requests_req_idx ON search_requests (request_id);

-- Scoring outcomes worth keeping: anything that wasn't a clean allow, plus revocations.
CREATE TABLE IF NOT EXISTS risk_events (
    event_id        BIGSERIAL PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT now(),
    request_id      TEXT,
    airline_id      TEXT NOT NULL,
    lane            TEXT NOT NULL,
    subject_type    TEXT NOT NULL,                   -- grant | tool | ip | device
    subject_id      TEXT NOT NULL,
    risk_score      REAL NOT NULL,
    flags           JSONB NOT NULL,                  -- per-signal contributions + human-readable reasons
    action_taken    TEXT NOT NULL                    -- allow | flag | challenge | throttle | block | revoke
);
CREATE INDEX IF NOT EXISTS risk_events_subject_idx ON risk_events (subject_type, subject_id, ts DESC);

-- Airline labels on our decisions; ground truth for tuning weights and thresholds.
CREATE TABLE IF NOT EXISTS feedback (
    feedback_id     BIGSERIAL PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT now(),
    airline_id      TEXT NOT NULL REFERENCES airlines(airline_id) ON DELETE CASCADE,
    request_id      TEXT,
    tool_id         TEXT,
    label           TEXT NOT NULL CHECK (label IN ('false_positive', 'false_negative', 'confirmed_abuse', 'confirmed_legitimate')),
    notes           TEXT
);

-- Redemption (award) inventory: one row per flight x date x award class, latest known state.
-- airline_id is the FFP program the seat is bookable through; operating_carrier differs for partner /
-- alliance space (e.g. an SQ-operated flight bookable with Aeroplan miles).
CREATE TABLE IF NOT EXISTS award_inventory (
    airline_id        TEXT NOT NULL REFERENCES airlines(airline_id) ON DELETE CASCADE,
    operating_carrier TEXT NOT NULL,
    flight_number     TEXT NOT NULL,                 -- e.g. 'SQ322'
    origin            TEXT NOT NULL,                 -- IATA airport codes
    destination       TEXT NOT NULL,
    travel_date       DATE NOT NULL,
    departs_at        TEXT,                          -- local 'HH:MM', informational
    cabin             TEXT NOT NULL CHECK (cabin IN ('economy', 'premium_economy', 'business', 'first')),
    award_class       TEXT NOT NULL CHECK (award_class ~ '^[A-Z]$'),  -- X / I / O by default
    seats_available   INTEGER NOT NULL CHECK (seats_available >= 0),
    seats_total       INTEGER CHECK (seats_total IS NULL OR seats_total >= seats_available),
    source            TEXT NOT NULL,                 -- 'airline_feed' | 'tool:<tool_id>'
    observed_at       TIMESTAMPTZ NOT NULL,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (airline_id, operating_carrier, flight_number, travel_date, award_class)
);
CREATE INDEX IF NOT EXISTS award_inventory_route_idx ON award_inventory (airline_id, origin, destination, travel_date);

-- Every change in seat counts, so we can see when seats open up or get taken.
CREATE TABLE IF NOT EXISTS award_inventory_history (
    observed_at       TIMESTAMPTZ NOT NULL,
    airline_id        TEXT NOT NULL,
    operating_carrier TEXT NOT NULL,
    flight_number     TEXT NOT NULL,
    travel_date       DATE NOT NULL,
    award_class       TEXT NOT NULL,
    seats_available   INTEGER NOT NULL,
    seats_total       INTEGER,
    source            TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS award_inventory_history_idx
    ON award_inventory_history (airline_id, flight_number, travel_date, award_class, observed_at DESC);
