\set aid random(1, 100000 * :scale)
SELECT a.aid, a.bid, a.abalance, b.bbalance
FROM pgbench_accounts a
JOIN pgbench_branches b ON b.bid = a.bid
WHERE a.aid = :aid
ORDER BY a.aid
LIMIT 10;
