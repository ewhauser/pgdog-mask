-- 500 rows with a proxy-masked column: the plugin's per-row cost.
\set id random(1, 99500)
SELECT id, tax_id FROM customers WHERE id BETWEEN :id AND :id + 499;
