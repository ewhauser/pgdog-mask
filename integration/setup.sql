-- Must exist before PgDog starts: the plugin only sees relations in the schema snapshot.
DROP SCHEMA IF EXISTS masking_e2e CASCADE;
CREATE SCHEMA masking_e2e;
CREATE TABLE masking_e2e.users (id BIGINT PRIMARY KEY, name TEXT, ssn TEXT, email TEXT);
INSERT INTO masking_e2e.users VALUES
    (1, 'alice', 'CANARYSSN-1111', 'canaryemail-alice@example.com'),
    (2, 'bob', 'CANARYSSN-2222', 'canaryemail-bob@example.com');
