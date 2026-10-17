-- Benchmark data, on top of `pgbench -i`. bench.sh runs this when the data is
-- missing or out of date; bump the version in bench_meta when you change it.
DROP TABLE IF EXISTS orders, customers, bench_meta;
CREATE TABLE customers (id bigint PRIMARY KEY, email text, ssn text, tax_id text, login text, created_at timestamptz , attr_0 text, attr_1 text, attr_2 text, attr_3 text, attr_4 text, attr_5 text, attr_6 text, attr_7 text, attr_8 text, attr_9 text, attr_10 text, attr_11 text, attr_12 text, attr_13 text, attr_14 text, attr_15 text, attr_16 text, attr_17 text, attr_18 text, attr_19 text, attr_20 text, attr_21 text, attr_22 text, attr_23 text, attr_24 text, attr_25 text, attr_26 text, attr_27 text, attr_28 text, attr_29 text);
INSERT INTO customers
    SELECT g, 'user' || g || '@example.com', lpad(g::text, 9, '0'), 'TAX-' || lpad(g::text, 8, '0'), g::text, now() - (g || ' minutes')::interval , md5(g::text || '0'), md5(g::text || '1'), md5(g::text || '2'), md5(g::text || '3'), md5(g::text || '4'), md5(g::text || '5'), md5(g::text || '6'), md5(g::text || '7'), md5(g::text || '8'), md5(g::text || '9'), md5(g::text || '10'), md5(g::text || '11'), md5(g::text || '12'), md5(g::text || '13'), md5(g::text || '14'), md5(g::text || '15'), md5(g::text || '16'), md5(g::text || '17'), md5(g::text || '18'), md5(g::text || '19'), md5(g::text || '20'), md5(g::text || '21'), md5(g::text || '22'), md5(g::text || '23'), md5(g::text || '24'), md5(g::text || '25'), md5(g::text || '26'), md5(g::text || '27'), md5(g::text || '28'), md5(g::text || '29')
    FROM generate_series(1, 100000) g;
CREATE INDEX ON customers (login);
CREATE TABLE orders (id bigint PRIMARY KEY, customer_id bigint, total numeric, created_at timestamptz);
INSERT INTO orders
    SELECT g, (g % 100000) + 1, g % 1000, now() - (g || ' seconds')::interval
    FROM generate_series(1, 200000) g;
CREATE INDEX ON orders (customer_id);
VACUUM ANALYZE customers, orders;

CREATE TABLE bench_meta (version int NOT NULL);
INSERT INTO bench_meta VALUES (3);
