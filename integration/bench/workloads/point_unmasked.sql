-- An unmasked column of a table with a masked column: analysis only, the
-- statement isn't changed.
\set aid random(1, 100000 * :scale)
SELECT bid FROM pgbench_accounts WHERE aid = :aid;
