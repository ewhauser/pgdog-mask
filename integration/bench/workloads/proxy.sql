-- 20 rows with a proxy-masked column (hmac_sha256), masked by the plugin.
\set id random(1, 99980)
SELECT id, tax_id FROM customers WHERE id BETWEEN :id AND :id + 19;
