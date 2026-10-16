-- Must exist before PgDog starts: the plugin only sees relations in the schema snapshot.
DROP SCHEMA IF EXISTS masking_e2e CASCADE;
CREATE SCHEMA masking_e2e;
CREATE TABLE masking_e2e.users (
    id BIGINT PRIMARY KEY,
    name TEXT NOT NULL CHECK (name <> 'forbidden'),
    ssn TEXT,
    email TEXT,
    phone TEXT,
    secret_note TEXT
);
-- Tagged in the database (tag_source = "comment").
COMMENT ON COLUMN masking_e2e.users.phone IS 'Phone number. pgdog:tag=pii.phone';
INSERT INTO masking_e2e.users VALUES
    (1, 'alice', 'CANARYSSN-1111', 'canaryemail-alice@example.com', 'CANARYPHONE-11', 'CANARYNOTE-1'),
    (2, 'bob', 'CANARYSSN-2222', 'canaryemail-bob@example.com', 'CANARYPHONE-22', 'CANARYNOTE-2');

-- Inlined with masks applied.
CREATE VIEW masking_e2e.user_ssns AS SELECT id, ssn FROM masking_e2e.users;
CREATE FUNCTION masking_e2e.get_ssn(uid BIGINT) RETURNS TEXT LANGUAGE sql STABLE
    AS $$ SELECT ssn FROM masking_e2e.users WHERE id = uid $$;
