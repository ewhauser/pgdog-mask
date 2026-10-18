-- Must exist before PgDog starts: the plugin only sees relations in its catalog.
DROP SCHEMA IF EXISTS masking_e2e CASCADE;
CREATE SCHEMA masking_e2e;
CREATE TABLE masking_e2e.users (
    id BIGINT PRIMARY KEY,
    name TEXT NOT NULL CHECK (name <> 'forbidden'),
    ssn TEXT,
    email TEXT,
    phone TEXT,
    secret_note TEXT,
    -- Masked by proxy masks.
    tax_id TEXT,
    card VARCHAR(19),
    balance BIGINT,
    -- Tags that fail closed, and a column tests tag while PgDog runs.
    nickname TEXT,
    codename TEXT,
    alias TEXT
);
-- Tagged in the database (tag_source = "comment").
COMMENT ON COLUMN masking_e2e.users.phone IS 'Phone number. pgdog:tag=pii.phone';
-- No [[tags]] entry.
COMMENT ON COLUMN masking_e2e.users.nickname IS 'pgdog:tag=pii.nickname';
-- Tags for two policies.
COMMENT ON COLUMN masking_e2e.users.codename IS 'pgdog:tag=pii.phone,secret';
INSERT INTO masking_e2e.users VALUES
    (1, 'alice', 'CANARYSSN-1111', 'canaryemail-alice@example.com', 'CANARYPHONE-11', 'CANARYNOTE-1',
     'TAX-1111', '4111-1111-1111-1111', 1000, 'ally', 'red', 'al'),
    (2, 'bob', 'CANARYSSN-2222', 'canaryemail-bob@example.com', 'CANARYPHONE-22', 'CANARYNOTE-2',
     'TAX-2222', '5500-0000-0000-0004', 2000, 'bobby', 'blue', 'bo');

-- Inlined with masks applied.
CREATE VIEW masking_e2e.user_ssns AS SELECT id, ssn FROM masking_e2e.users;
CREATE FUNCTION masking_e2e.get_ssn(uid BIGINT) RETURNS TEXT LANGUAGE sql STABLE
    AS $$ SELECT ssn FROM masking_e2e.users WHERE id = uid $$;
-- Queried like a table: its condition casts real values, whatever the
-- user's masks.
CREATE VIEW masking_e2e.err_sb WITH (security_barrier) AS
    SELECT id FROM masking_e2e.users WHERE ssn::int > 0;
