-- A lookup by a masked, indexed column. Masked users compare masked values,
-- so the index can't be used; raw search (bench_support) keeps using it.
\set id random(1, 100000)
SELECT id FROM customers WHERE login = :id::text;
