-- An ORM-style SELECT "customers".* over 34 columns, two of them masked.
\set id random(1, 99990)
\set id2 :id + 1
\set id3 :id + 2
SELECT "customers".* FROM "customers" INNER JOIN "orders" ON "orders"."customer_id" = "customers"."id" WHERE "customers"."id" IN (:id, :id2, :id3) AND "orders"."created_at" > '2020-01-01' ORDER BY "customers"."created_at" DESC LIMIT 20;
