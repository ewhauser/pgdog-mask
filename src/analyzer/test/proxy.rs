//! Results-only proxy masks: the regression corpus.
//!
//! Users: `engineer` sees `users.ssn` (proxy 0) and `patients.mrn` (proxy 1)
//! through proxy masks and `users.email` through a SQL mask; `analyst` gets
//! SQL masks only; `admin` is exempt.
use super::*;
use crate::proxy::{Datum, MaskError, Options, ProxyMask, Registry};

/// Proxy masks for `engineer`, SQL masks for everyone else.
pub(crate) const PROXY_CONFIG: &str = r#"
[general]
udf_allowlist = ["public.safe_fn"]
extension_allowlist = ["pgcrypto"]

[[users]]
name = "engineer"
roles = ["engineer"]

[[users]]
name = "admin"
roles = ["pii_admin"]

[[policies]]
name = "ssn"
data_type = "character varying"
mask = "null"

[[policies.rules]]
roles = ["pii_admin"]
mask = "none"

[[policies.rules]]
roles = ["engineer"]
mask = "proxy"
proxy = "test.hmac"

[[policies]]
name = "mrn"
data_type = "text"
mask = "null"

[[policies.rules]]
roles = ["pii_admin"]
mask = "none"

[[policies.rules]]
roles = ["engineer"]
mask = "proxy"
proxy = "test.ff1"

[[policies]]
name = "email"
data_type = "text"
mask = "partial"
keep_suffix = 4

[[policies.rules]]
roles = ["pii_admin"]
mask = "none"

[[masked_columns]]
name = "users"
column = "ssn"
policy = "ssn"

[[masked_columns]]
name = "users"
column = "email"
policy = "email"

[[masked_columns]]
name = "patients"
column = "mrn"
policy = "mrn"
"#;

/// A proxy mask that returns values unchanged.
struct Identity;

impl ProxyMask for Identity {
    fn accepts(&self, _data_type: &str) -> bool {
        true
    }

    fn mask(&self, value: Datum) -> Result<Datum, MaskError> {
        Ok(value)
    }
}

/// The proxy masks `PROXY_CONFIG` uses.
pub(crate) fn proxy_registry() -> Registry {
    let mut registry = Registry::default();
    registry.register("test.hmac", |_: &Options| Ok(Identity));
    registry.register("test.ff1", |_: &Options| Ok(Identity));
    registry
}

/// A result mask: `P(proxy, type_oid)` or NULL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum M {
    P(usize, u32),
    N,
}

/// `(result, column, mask)`.
type Mask = (u16, u16, M);

/// What the analysis decided.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Got {
    Blocked(String),
    /// `sql` is `None` when the statement is sent unchanged.
    Ran {
        sql: Option<String>,
        masks: Vec<Mask>,
        redact: bool,
    },
}

impl Got {
    fn new(outcome: Outcome) -> Self {
        let (sql, results) = match outcome {
            Outcome::Blocked { reason } => return Self::Blocked(reason),
            Outcome::Unchanged { results, .. } => (None, results),
            Outcome::Rewritten { sql, results, .. } => (Some(sql), results),
        };
        let masks = results
            .columns
            .iter()
            .map(|column| {
                let mask = match column.mask {
                    ResultMask::Proxy { proxy, type_oid } => M::P(proxy, type_oid),
                    ResultMask::Null => M::N,
                };
                (column.result, column.column, mask)
            })
            .collect();
        Self::Ran {
            sql,
            masks,
            redact: results.redact_errors,
        }
    }

    /// Comparable across the full and shape paths.
    fn canonical(self) -> Self {
        match self {
            Self::Ran { sql, masks, redact } => Self::Ran {
                sql: sql.map(|sql| canonical(&sql)),
                masks,
                redact,
            },
            // Reasons may name a placeholder instead of a literal.
            Self::Blocked(_) => Self::Blocked(String::new()),
        }
    }
}

/// Expected outcome of a corpus row.
#[derive(Debug, Clone)]
enum Expect {
    /// Sent unchanged, with these masks and redaction.
    Same(Vec<Mask>, bool),
    /// Rewritten (containing these fragments), with these masks and redaction.
    Rewritten(Vec<&'static str>, Vec<Mask>, bool),
    /// Blocked, with a reason containing this.
    Block(&'static str),
}

/// Sent unchanged, nothing to mask.
fn allow() -> Expect {
    Expect::Same(vec![], false)
}

/// Proxy 0 (`ssn`, varchar) at column `c` of the first result.
fn p(c: u16) -> Mask {
    (0, c, M::P(0, 1043))
}

/// Proxy 0 on a text column (table-like views).
fn pt(c: u16) -> Mask {
    (0, c, M::P(0, 25))
}

/// Proxy 1 (`mrn`, text).
fn m(c: u16) -> Mask {
    (0, c, M::P(1, 25))
}

/// NULL.
fn n(c: u16) -> Mask {
    (0, c, M::N)
}

/// The same mask in result `r`.
fn at(r: u16, (_, column, mask): Mask) -> Mask {
    (r, column, mask)
}

/// A corpus row.
#[derive(Clone)]
struct Case {
    id: &'static str,
    user: &'static str,
    sql: &'static str,
    expect: Expect,
    config: Option<String>,
    catalog: fn() -> Catalog,
}

fn case(id: &'static str, sql: &'static str, expect: Expect) -> Case {
    Case {
        id,
        user: "engineer",
        sql,
        expect,
        config: None,
        catalog,
    }
}

impl Case {
    fn user(mut self, user: &'static str) -> Self {
        self.user = user;
        self
    }

    fn config(mut self, config: String) -> Self {
        self.config = Some(config);
        self
    }

    fn catalog(mut self, catalog: fn() -> Catalog) -> Self {
        self.catalog = catalog;
        self
    }

    /// Analyze the row, through its shape with `shape`. `None` if it has no
    /// shape.
    fn run(&self, shape: bool) -> Option<Got> {
        let config = self.config.as_deref().unwrap_or(PROXY_CONFIG);
        let policies =
            Policies::with_registry(Config::from_toml(config).unwrap(), &proxy_registry()).unwrap();
        let catalog = (self.catalog)();
        let assignments = Assignments::new(&policies, "db", &catalog);
        let profile = policies.profile(self.user, "db");
        let ctx = Context {
            catalog: &catalog,
            assignments: &assignments,
            policies: &policies,
            profile: &profile,
            search_path: vec!["public".into()],
        };
        let outcome = if shape {
            analyze_shape(self.sql, &ctx)?
        } else {
            analyze(self.sql, &ctx)
        };
        Some(Got::new(outcome))
    }

    /// Why the outcome isn't the expected one.
    fn mismatch(&self, got: &Got) -> Option<String> {
        match (&self.expect, got) {
            (Expect::Block(reason), Got::Blocked(got)) if got.contains(reason) => None,
            (
                Expect::Same(masks, redact),
                Got::Ran {
                    sql: None,
                    masks: got_masks,
                    redact: got_redact,
                },
            ) if masks == got_masks && redact == got_redact => None,
            (
                Expect::Rewritten(fragments, masks, redact),
                Got::Ran {
                    sql: Some(sql),
                    masks: got_masks,
                    redact: got_redact,
                },
            ) if masks == got_masks && redact == got_redact => fragments
                .iter()
                .find(|fragment| !sql.contains(**fragment))
                .map(|fragment| format!("missing {fragment:?}")),
            (expect, _) => Some(format!("expected {expect:?}")),
        }
    }
}

/// Check every row, and report every mismatch.
fn check(cases: Vec<Case>) {
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|case| {
            let got = case.run(false).expect("full analysis");
            case.mismatch(&got).map(|why| {
                format!(
                    "{} ({}) {:?}: {why}\n    got {got:?}",
                    case.id, case.user, case.sql
                )
            })
        })
        .collect();
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

fn plain_outputs() -> Vec<Case> {
    use Expect::*;
    vec![
        case("A1", "SELECT ssn FROM users", Same(vec![p(0)], false)),
        case(
            "A2",
            "SELECT id, ssn FROM users WHERE id = $1",
            Same(vec![p(1)], false),
        ),
        case("A3", "SELECT ssn AS s FROM users", Same(vec![p(0)], false)),
        case("A4", "SELECT u.ssn FROM users u", Same(vec![p(0)], false)),
        case(
            "A5",
            "SELECT public.users.ssn FROM public.users",
            Same(vec![p(0)], false),
        ),
        // Aliases map by position, which a stale catalog can get wrong.
        case(
            "A6",
            "SELECT c FROM users AS x(a, b, c)",
            Block("alias columns in the select list"),
        ),
        case(
            "A7",
            "SELECT ssn, ssn AS again FROM users",
            Same(vec![p(0), p(1)], false),
        ),
        case(
            "A8",
            "SELECT ssn AS email FROM users",
            Same(vec![p(0)], false),
        ),
        // ORDER BY ssn sorts by the output (email), and the input ssn is read.
        case(
            "A9",
            "SELECT email AS ssn FROM users ORDER BY ssn",
            Rewritten(vec!["repeat("], vec![], true),
        ),
        case("A10", "SELECT ssn FROM users_2024", Same(vec![p(0)], false)),
        case(
            "A11",
            "SELECT ssn FROM ONLY users FOR UPDATE",
            Same(vec![p(0)], false),
        ),
        // A cast is a computation.
        case("A12", "SELECT ssn::text FROM users", Same(vec![n(0)], true)),
        case(
            "A13",
            "SELECT ssn::varchar FROM users",
            Same(vec![n(0)], true),
        ),
    ]
}

fn stars() -> Vec<Case> {
    use Expect::*;
    vec![
        case(
            "B1",
            "SELECT * FROM users",
            Rewritten(
                vec!["users.id AS id", "users.ssn AS ssn", "repeat("],
                vec![p(2)],
                false,
            ),
        ),
        case(
            "B2",
            "SELECT u.* FROM users u JOIN orders o ON o.user_id = u.id",
            Rewritten(vec!["u.ssn AS ssn"], vec![p(2)], false),
        ),
        case(
            "B3",
            "SELECT o.*, u.ssn FROM orders o JOIN users u ON o.user_id = u.id",
            Rewritten(
                vec!["SELECT o.id, o.user_id, o.total, u.ssn AS ssn FROM"],
                vec![p(3)],
                false,
            ),
        ),
        case("B4", "TABLE users", Rewritten(vec![], vec![p(2)], false)),
        case(
            "B5",
            "SELECT * FROM patients",
            Rewritten(
                vec!["patients.id AS id, patients.user_id AS user_id, patients.mrn AS mrn"],
                vec![m(2)],
                false,
            ),
        ),
        case(
            "B6",
            "SELECT ssn, *, upper(ssn) FROM users",
            Rewritten(vec![], vec![p(0), p(3), n(7)], true),
        ),
        case(
            "B7",
            "SELECT * FROM users u JOIN patients p ON p.user_id = u.id",
            Rewritten(vec![], vec![p(2), m(8)], false),
        ),
        case(
            "B8",
            "SELECT x.* FROM (SELECT id, ssn FROM users) x",
            Same(vec![p(1)], false),
        ),
        case(
            "B9",
            "SELECT f.*, u.ssn FROM users u, generate_series(1, 2) f",
            Block("can't place masks"),
        ),
        case(
            "B10",
            "SELECT * FROM users u, generate_series(1, 2) g",
            Rewritten(vec!["u.salary AS salary, g.*"], vec![p(2)], false),
        ),
        case(
            "B11",
            "SELECT * FROM users JOIN orders USING (id)",
            Block("USING or NATURAL"),
        ),
        case(
            "B12",
            "SELECT ssn, total FROM users JOIN orders USING (id)",
            Same(vec![p(0)], false),
        ),
        case(
            "B13",
            "SELECT (u).*, u.ssn FROM users u",
            Rewritten(vec!["u.id AS id"], vec![p(2), p(6)], false),
        ),
        case(
            "B14",
            "SELECT (o).*, u.ssn FROM orders o JOIN users u ON o.user_id = u.id",
            Rewritten(
                vec!["SELECT o.id, o.user_id, o.total, u.ssn"],
                vec![p(3)],
                false,
            ),
        ),
        case(
            "B15",
            "SELECT * FROM pg_class c, users u",
            Block("can't place masks"),
        ),
        case(
            "B16",
            "SELECT * FROM (SELECT ssn, id FROM users) s JOIN orders o USING (id)",
            Block("can't place masks"),
        ),
        case(
            "B17",
            "SELECT (ROW(1, 2)).*, ssn FROM users",
            Block("can't place masks"),
        ),
        case(
            "B18",
            "SELECT * FROM users, XMLTABLE('/r' PASSING ('<r/>'::xml) COLUMNS a text) x",
            Rewritten(vec!["users.salary AS salary, x.*"], vec![p(2)], false),
        ),
        case(
            "B19",
            "SELECT s.*, u.ssn FROM (SELECT * FROM pg_class) s, users u",
            Block("can't place masks"),
        ),
        // Merged columns: a bare * has unknown width even over clean inputs.
        case(
            "B20",
            "SELECT *, (SELECT upper(ssn) FROM users LIMIT 1) FROM orders a JOIN orders b USING (id)",
            Block("can't place masks"),
        ),
        case(
            "B21",
            "SELECT s.*, upper(u.ssn) FROM (SELECT * FROM orders a JOIN orders b USING (id)) s, users u",
            Block("can't place masks"),
        ),
        case(
            "B22",
            "SELECT s.*, upper(u.ssn) FROM (SELECT * FROM orders) s, users u",
            Rewritten(
                vec![
                    "(SELECT orders.id AS id, orders.user_id AS user_id, orders.total AS total FROM orders) s",
                ],
                vec![n(3)],
                true,
            ),
        ),
        case(
            "B23",
            "SELECT l.* FROM users u, LATERAL (SELECT u.*) l",
            Rewritten(vec!["u.ssn AS ssn"], vec![p(2)], false),
        ),
        case(
            "B24",
            "SELECT * FROM (SELECT * FROM orders) s",
            Rewritten(vec!["orders.id AS id"], vec![], false),
        ),
    ]
}

fn subqueries_ctes() -> Vec<Case> {
    use Expect::*;
    vec![
        case(
            "C1",
            "SELECT s.ssn FROM (SELECT ssn FROM users) s",
            Same(vec![p(0)], false),
        ),
        case(
            "C2",
            "SELECT s.x FROM (SELECT ssn AS x, id FROM users WHERE id > 5) s",
            Same(vec![p(0)], false),
        ),
        case(
            "C3",
            "SELECT * FROM (SELECT * FROM users) s",
            Rewritten(vec!["users.ssn AS ssn"], vec![p(2)], false),
        ),
        case(
            "C4",
            "SELECT s.u FROM (SELECT upper(ssn) AS u FROM users) s",
            Same(vec![n(0)], true),
        ),
        case(
            "C5",
            "SELECT count(*) FROM (SELECT DISTINCT ssn FROM users) s",
            allow(),
        ),
        case(
            "C6",
            "SELECT count(s.ssn) FROM (SELECT ssn FROM users) s",
            Same(vec![n(0)], true),
        ),
        case(
            "C7",
            "WITH s AS (SELECT id, ssn FROM users) SELECT ssn FROM s",
            Same(vec![p(0)], false),
        ),
        case(
            "C8",
            "WITH s(a, b) AS (SELECT id, ssn FROM users) SELECT b, a FROM s",
            Same(vec![p(0)], false),
        ),
        case(
            "C9",
            "WITH s AS MATERIALIZED (SELECT * FROM users) SELECT ssn, email FROM s",
            Rewritten(vec!["users.ssn AS ssn"], vec![p(0)], false),
        ),
        case(
            "C10",
            "WITH s AS (SELECT ssn || '' AS x FROM users) SELECT x FROM s",
            Same(vec![n(0)], true),
        ),
        // The pending self-reference r.id is a computing use.
        case(
            "C11",
            "WITH RECURSIVE r AS (SELECT id, ssn FROM users WHERE id = 1 UNION ALL SELECT u.id, u.ssn FROM users u JOIN r ON u.id = r.id + 1) SELECT ssn FROM r",
            Same(vec![p(0)], true),
        ),
        // No fixpoint: what passes through the recursion is NULL.
        case(
            "C12",
            "WITH RECURSIVE r(n, s) AS (SELECT 1, ssn FROM users WHERE id = 1 UNION ALL SELECT n + 1, s FROM r WHERE n < 3) SELECT s FROM r",
            Same(vec![n(0)], true),
        ),
        case(
            "C13",
            "WITH RECURSIVE r(n, s) AS (SELECT 1, ssn FROM users WHERE id = 1 UNION ALL SELECT n + 1, s || '!' FROM r WHERE n < 3) SELECT n, s FROM r",
            Same(vec![n(0), n(1)], true),
        ),
        // A CTE that only reads itself is rolled back to clean.
        case(
            "C14",
            "WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM t WHERE n < 5) SELECT t.n, u.ssn FROM t, users u",
            Same(vec![p(1)], false),
        ),
        case(
            "C15",
            "SELECT (SELECT s.v FROM archive a, (SELECT ssn AS v) s LIMIT 1) FROM users u",
            Same(vec![n(0)], true),
        ),
        case(
            "C16",
            "SELECT (SELECT l.v FROM archive a, LATERAL (SELECT ssn AS v) l LIMIT 1) FROM users u",
            allow(),
        ),
        case(
            "C17",
            "SELECT (WITH c AS (SELECT u.ssn AS x) SELECT x FROM c) FROM users u",
            Same(vec![n(0)], true),
        ),
        // A forward reference to another recursive CTE is a source.
        case(
            "C18",
            "WITH RECURSIVE a AS (SELECT x FROM b), b AS (SELECT ssn AS x FROM users) SELECT * FROM a",
            Same(vec![n(0)], false),
        ),
        // A sink deferred inside the CTE survives.
        case(
            "C19",
            "WITH RECURSIVE d AS (INSERT INTO audit (note) SELECT x FROM t RETURNING 1), t AS (SELECT ssn AS x FROM users) SELECT count(*) FROM d",
            Block("INSERT"),
        ),
        // SEARCH and CYCLE columns hold the listed values.
        case(
            "C20",
            "WITH RECURSIVE t(n, s) AS (SELECT 1, ssn FROM users WHERE id = 1 UNION ALL SELECT n + 1, s FROM t WHERE n < 3) SEARCH DEPTH FIRST BY s SET ord SELECT * FROM t",
            Same(vec![n(0), n(1), n(2)], true),
        ),
        // CTEs stay visible inside non-LATERAL subqueries.
        case(
            "C21",
            "WITH archive AS (SELECT ssn FROM users) SELECT x.ssn FROM orders o, (SELECT * FROM archive) x",
            Same(vec![p(0)], false),
        ),
    ]
}

fn set_operations() -> Vec<Case> {
    use Expect::*;
    vec![
        case(
            "D1",
            "SELECT ssn FROM users UNION ALL SELECT ssn FROM users_2024",
            Same(vec![p(0)], false),
        ),
        case(
            "D2",
            "SELECT ssn FROM users UNION SELECT ssn FROM users",
            Same(vec![p(0)], false),
        ),
        case(
            "D3",
            "SELECT ssn FROM users UNION ALL SELECT name FROM users",
            Same(vec![n(0)], false),
        ),
        case(
            "D4",
            "SELECT ssn FROM users UNION ALL SELECT mrn FROM patients",
            Same(vec![n(0)], false),
        ),
        case(
            "D5",
            "SELECT id, ssn FROM users INTERSECT SELECT id, ssn FROM users_2024",
            Same(vec![p(1)], false),
        ),
        case(
            "D6",
            "SELECT ssn FROM users EXCEPT SELECT name FROM users",
            Same(vec![n(0)], false),
        ),
        case(
            "D7",
            "SELECT ssn FROM users UNION ALL SELECT upper(ssn) FROM users",
            Same(vec![n(0)], true),
        ),
        case(
            "D8",
            "SELECT ssn FROM users UNION SELECT ssn FROM users_2024 ORDER BY 1 LIMIT 3",
            Same(vec![p(0)], false),
        ),
        case(
            "D9",
            "SELECT ssn FROM users UNION ALL SELECT email FROM users",
            Rewritten(vec!["repeat("], vec![n(0)], false),
        ),
        case(
            "D10",
            "SELECT ssn FROM users UNION ALL SELECT ssn FROM users ORDER BY ssn",
            Same(vec![p(0)], true),
        ),
        case(
            "D11",
            "SELECT ssn FROM users UNION SELECT 'x'",
            Same(vec![n(0)], false),
        ),
        case(
            "D12",
            "SELECT ssn AS s FROM users UNION ALL SELECT ssn FROM users_2024 ORDER BY s",
            Same(vec![p(0)], true),
        ),
    ]
}

fn values_lateral_joins() -> Vec<Case> {
    use Expect::*;
    let unresolved = PROXY_CONFIG.replacen("[general]", "[general]\non_unresolved = \"allow\"", 1);
    vec![
        case("E1", "VALUES (1, 'a')", allow()),
        case(
            "E2",
            "SELECT * FROM (VALUES ((SELECT ssn FROM users LIMIT 1))) v(s)",
            Same(vec![n(0)], true),
        ),
        case(
            "E3",
            "SELECT l.x FROM users u, LATERAL (SELECT u.ssn AS x) l",
            Same(vec![p(0)], false),
        ),
        case(
            "E4",
            "SELECT l.x FROM users u CROSS JOIN LATERAL (SELECT upper(u.ssn) AS x) l",
            Same(vec![n(0)], true),
        ),
        case(
            "E5",
            "SELECT o.id, l.ssn FROM orders o LEFT JOIN LATERAL (SELECT u.ssn FROM users u WHERE u.id = o.user_id LIMIT 1) l ON true",
            Same(vec![p(1)], false),
        ),
        case(
            "E6",
            "SELECT u.ssn, o.total FROM users u JOIN orders o ON o.user_id = u.id",
            Same(vec![p(0)], false),
        ),
        case(
            "E7",
            "SELECT u.ssn FROM orders o LEFT JOIN users u ON u.id = o.user_id",
            Same(vec![p(0)], false),
        ),
        case(
            "E8",
            "SELECT a.id, b.id FROM users a JOIN users_2024 b ON a.ssn = b.ssn",
            Same(vec![], true),
        ),
        case(
            "E9",
            "SELECT j.ssn FROM (users u JOIN orders o ON true) AS j",
            Block("aliased joins"),
        ),
        case(
            "E10",
            "SELECT * FROM users NATURAL JOIN orders",
            Block("USING or NATURAL"),
        ),
        case(
            "E11",
            "SELECT (SELECT count(*) FROM archive a, orders b JOIN orders c ON c.id = length(ssn)) FROM users u",
            Same(vec![], true),
        ),
        case(
            "E12",
            "SELECT ssn FROM users u JOIN users_2024 p USING (ssn)",
            Same(vec![p(0)], true),
        ),
        case(
            "E13",
            "SELECT x.a FROM users u, XMLTABLE('/r' PASSING (u.ssn::xml) COLUMNS a text PATH '.') x",
            Same(vec![n(0)], true),
        ),
        case(
            "E14",
            "SELECT j.a FROM users u, JSON_TABLE(to_jsonb(u.ssn), '$' COLUMNS (a text PATH '$')) j",
            Same(vec![n(0)], true),
        ),
        // FOR ORDINALITY columns don't carry the arguments.
        case(
            "E14+",
            "SELECT j.o, j.a FROM users u, JSON_TABLE(to_jsonb(u.ssn), '$' COLUMNS (o FOR ORDINALITY, a text PATH '$')) j",
            Same(vec![n(1)], true),
        ),
        case(
            "E14+",
            "SELECT x.o, x.a FROM users u, XMLTABLE('/r' PASSING (u.ssn::xml) COLUMNS o FOR ORDINALITY, a text PATH '.') x",
            Same(vec![n(1)], true),
        ),
        case(
            "E15",
            "SELECT g.x FROM users u, unnest(ARRAY[u.ssn]) g(x)",
            Same(vec![n(0)], true),
        ),
        // Catalog relation columns are clean.
        case(
            "E16",
            "SELECT c.relname, u.ssn FROM pg_class c, users u",
            Same(vec![p(1)], false),
        ),
        // Unknown, in a statement naming a proxy relation.
        case(
            "E17",
            "SELECT t.x, u.id FROM not_in_catalog t, users u",
            Same(vec![n(0)], false),
        )
        .config(unresolved),
        // An aliased join hides its items behind the alias, whose column list
        // renames its columns by position.
        case(
            "E18",
            "SELECT l.v FROM orders o2, LATERAL (SELECT total AS v FROM ((SELECT ssn FROM users) s CROSS JOIN (SELECT 1 AS k) k) AS j(total)) l",
            Same(vec![p(0)], false),
        ),
        case(
            "E18",
            "SELECT x.* FROM orders o2, LATERAL (SELECT total FROM ((SELECT ssn FROM users) s CROSS JOIN (SELECT 1 AS k) k) AS j(total)) x",
            Same(vec![p(0)], false),
        ),
        case(
            "E18",
            "SELECT (SELECT total FROM ((SELECT ssn FROM users) s CROSS JOIN (SELECT 1 AS k) k) AS j(total) LIMIT 1) FROM orders",
            Same(vec![n(0)], true),
        ),
        // `u` inside the join is hidden: u.ssn is the outer users'.
        case(
            "E19",
            "SELECT l.v FROM users u, LATERAL (SELECT u.ssn AS v FROM (orders u CROSS JOIN orders o) AS j) l",
            Same(vec![p(0)], false),
        ),
        case(
            "E19",
            "SELECT (SELECT u.ssn FROM (orders u CROSS JOIN orders o) AS j LIMIT 1) FROM users u",
            Same(vec![n(0)], true),
        ),
        case(
            "E19",
            "SELECT (SELECT u.ssn FROM (orders u JOIN orders o ON true) AS j LIMIT 1) FROM users u",
            Same(vec![n(0)], true),
        ),
        case(
            "E19",
            "SELECT l.v FROM users u, LATERAL (SELECT u.email AS v FROM (orders u CROSS JOIN orders o) AS j) l",
            Rewritten(vec!["repeat("], vec![], false),
        ),
        case(
            "E19",
            "SELECT l.v FROM users u, LATERAL (SELECT u.ssn AS v FROM (orders u CROSS JOIN orders o) AS j) l",
            Rewritten(vec!["NULL::varchar AS v"], vec![], false),
        )
        .user("analyst"),
        case(
            "E20",
            "SELECT l.v FROM (SELECT ssn FROM users) s, LATERAL (SELECT s.ssn AS v FROM ((SELECT 'clean'::varchar AS ssn) s CROSS JOIN orders o) AS j) l",
            Same(vec![p(0)], false),
        ),
        // USING (...) AS x names the merged columns; it hides nothing.
        case(
            "E21",
            "SELECT l.v FROM (SELECT 'c'::varchar AS ssn) x, LATERAL (SELECT x.ssn AS v FROM (SELECT ssn FROM users) a JOIN (SELECT ssn FROM users) b USING (ssn) AS x) l",
            Same(vec![p(0)], true),
        ),
        case(
            "E22",
            "SELECT j.x FROM ((SELECT ssn AS x FROM users) s JOIN orders o ON true) AS j",
            Same(vec![p(0)], false),
        ),
        // `*` over an aliased join of catalog relations: `j.*`, whose width
        // the catalog can't be trusted for.
        case(
            "E23",
            "SELECT * FROM (orders a JOIN orders b ON true) j, users u",
            Block("unknown width"),
        ),
        case(
            "E23",
            "SELECT j.*, upper(u.ssn) FROM (orders a JOIN orders b ON true) j, users u",
            Block("unknown width"),
        ),
        case(
            "E23",
            "SELECT * FROM ((SELECT ssn AS x FROM users) s JOIN orders o ON true) AS j",
            Block("unknown width"),
        ),
        case(
            "E23",
            "SELECT 1 WHERE EXISTS (SELECT * FROM (orders a JOIN orders b ON true) j)",
            allow(),
        ),
        case(
            "E23",
            "SELECT * FROM (SELECT * FROM (orders a JOIN orders b ON true) j) s",
            allow(),
        ),
        case(
            "E23",
            "SELECT * FROM (orders a JOIN orders b ON true) j, users u",
            Rewritten(vec!["SELECT j.*, u.id AS id"], vec![], false),
        )
        .user("analyst"),
    ]
}

fn grouping_ordering() -> Vec<Case> {
    use Expect::*;
    let flag = format!(
        "{PROXY_CONFIG}\n[[masked_columns]]\nname = \"users\"\ncolumn = \"opted_in\"\npolicy = \"ssn\"\n"
    );
    vec![
        case(
            "F1",
            "SELECT DISTINCT ssn FROM users",
            Same(vec![p(0)], false),
        ),
        case(
            "F2",
            "SELECT ssn, count(*) FROM users GROUP BY ssn HAVING count(*) > 1",
            Same(vec![p(0)], true),
        ),
        case(
            "F3",
            "SELECT count(*) FROM users GROUP BY ssn",
            Same(vec![], true),
        ),
        case(
            "F4",
            "SELECT ssn FROM users ORDER BY ssn DESC LIMIT 5 OFFSET 2",
            Same(vec![p(0)], true),
        ),
        case(
            "F5",
            "SELECT ssn FROM users ORDER BY 1",
            Same(vec![p(0)], false),
        ),
        case(
            "F6",
            "SELECT DISTINCT ON (ssn) ssn, email FROM users ORDER BY ssn, id",
            Rewritten(vec!["repeat("], vec![p(0)], true),
        ),
        case(
            "F7",
            "SELECT ssn FROM users GROUP BY 1",
            Same(vec![p(0)], false),
        ),
        case(
            "F8",
            "SELECT id FROM users GROUP BY id HAVING max(ssn) > '5'",
            Same(vec![], true),
        ),
        case(
            "F9",
            "SELECT ssn FROM users ORDER BY upper(ssn) LIMIT 1",
            Same(vec![p(0)], true),
        ),
        // Output names aren't whole-row references.
        case(
            "F10",
            "SELECT upper(name) AS n FROM users ORDER BY n",
            allow(),
        ),
        // Postgres sorts by the output, ssn.
        case(
            "F11",
            "SELECT ssn AS name FROM users ORDER BY name",
            Same(vec![p(0)], true),
        ),
        case(
            "F12",
            "SELECT upper(name) AS n, count(*) FROM users GROUP BY n",
            allow(),
        ),
        // A clause root never reaches `column_ref`.
        case(
            "F13",
            "SELECT id FROM users WHERE opted_in",
            Same(vec![], true),
        )
        .config(flag),
    ]
}

fn conditions() -> Vec<Case> {
    use Expect::*;
    vec![
        case(
            "G1",
            "SELECT id FROM users WHERE ssn = $1",
            Same(vec![], true),
        ),
        case(
            "G2",
            "SELECT id FROM users WHERE ssn::int > 5",
            Same(vec![], true),
        ),
        case(
            "G3",
            "SELECT id, name FROM users WHERE upper(ssn) LIKE upper($1) AND name = $2",
            Same(vec![], true),
        ),
        case(
            "G4",
            "SELECT id FROM users WHERE ssn IN (SELECT ssn FROM users_2024)",
            Same(vec![], true),
        ),
        case(
            "G5",
            "SELECT id FROM users WHERE ssn = ANY($1) OR ssn IS NULL",
            Same(vec![], true),
        ),
        case(
            "G6",
            "SELECT o.id FROM orders o JOIN users u ON u.id = o.user_id AND u.ssn = $1",
            Same(vec![], true),
        ),
        // Conditions compare real values: `ssn = $1` is left as written.
        case(
            "G7",
            "SELECT id FROM users WHERE ssn = $1 AND email = $2",
            Rewritten(vec!["WHERE ssn = $1 AND ", "repeat("], vec![], true),
        ),
        case(
            "G8",
            "SELECT id FROM users WHERE EXISTS (SELECT 1 FROM users_2024 p WHERE p.ssn = users.ssn)",
            Same(vec![], true),
        ),
        case(
            "G9",
            "SELECT id FROM users u WHERE row_to_json(u)::text LIKE '%9%'",
            Rewritten(
                vec![
                    "ROW(u.id, u.name, u.ssn, ",
                    "u.opted_in, u.salary)::public.users",
                ],
                vec![],
                true,
            ),
        ),
        case(
            "G10",
            "SELECT id FROM user_loud WHERE loud = $1",
            Rewritten(vec!["FROM (SELECT users.id"], vec![], true),
        ),
        case(
            "G11",
            "SELECT id FROM ssn_flags WHERE starts_9",
            Same(vec![], true),
        ),
    ]
}

fn computed_outputs() -> Vec<Case> {
    use Expect::*;
    vec![
        case("H1", "SELECT upper(ssn) FROM users", Same(vec![n(0)], true)),
        case(
            "H2",
            "SELECT 'x' || ssn AS tagged FROM users",
            Same(vec![n(0)], true),
        ),
        case("H3", "SELECT ssn::int FROM users", Same(vec![n(0)], true)),
        case(
            "H4",
            "SELECT coalesce(ssn, '') FROM users",
            Same(vec![n(0)], true),
        ),
        case(
            "H5",
            "SELECT CASE WHEN ssn IS NULL THEN 'none' ELSE ssn END FROM users",
            Same(vec![n(0)], true),
        ),
        case(
            "H6",
            "SELECT id, ssn = '123-45-6789' AS hit FROM users",
            Same(vec![n(1)], true),
        ),
        case(
            "H7",
            "SELECT length(ssn), ssn IS NULL FROM users",
            Same(vec![n(0), n(1)], true),
        ),
        case(
            "H8",
            "SELECT max(ssn), count(ssn), count(*) FROM users",
            Same(vec![n(0), n(1)], true),
        ),
        case(
            "H9",
            "SELECT string_agg(ssn, ',') FROM users",
            Same(vec![n(0)], true),
        ),
        case(
            "H10",
            "SELECT id, lag(ssn) OVER (ORDER BY id) FROM users",
            Same(vec![n(1)], true),
        ),
        case(
            "H11",
            "SELECT id, row_number() OVER (ORDER BY ssn) FROM users",
            Same(vec![n(1)], true),
        ),
        case(
            "H12",
            "SELECT count(*) FILTER (WHERE ssn LIKE '9%') FROM users",
            Same(vec![n(0)], true),
        ),
        case(
            "H13",
            "SELECT json_build_object('s', ssn), to_jsonb(ssn) FROM users",
            Same(vec![n(0), n(1)], true),
        ),
        case(
            "H14",
            "SELECT ROW(id, ssn), ARRAY[ssn] FROM users",
            Same(vec![n(0), n(1)], true),
        ),
        case(
            "H15",
            "SELECT u FROM users u",
            Rewritten(vec!["ROW(u.id"], vec![n(0)], true),
        ),
        case(
            "H16",
            "SELECT row_to_json(u) FROM users u",
            Rewritten(vec!["ROW(u.id"], vec![n(0)], true),
        ),
        // No SQL masks, so no ROW().
        case("H17", "SELECT p FROM patients p", Same(vec![n(0)], true)),
        case(
            "H18",
            "SELECT (u).ssn FROM users u",
            Rewritten(vec!["ROW(u.id"], vec![n(0)], true),
        ),
        case(
            "H19",
            "SELECT xmlelement(name x, ssn) FROM users",
            Same(vec![n(0)], true),
        ),
        case(
            "H20",
            "SELECT string_agg(name, ',' ORDER BY ssn) FROM users",
            Same(vec![n(0)], true),
        ),
        case(
            "H21",
            "SELECT id, rank() OVER w FROM users WINDOW w AS (PARTITION BY ssn)",
            Same(vec![n(1)], true),
        ),
        case(
            "H22",
            "SELECT id, rank() OVER (w ORDER BY id) FROM users WINDOW w AS (PARTITION BY ssn)",
            Same(vec![n(1)], true),
        ),
        case(
            "H23",
            "SELECT CASE WHEN ssn LIKE '9%' THEN 'nine' ELSE 'other' END FROM users",
            Same(vec![n(0)], true),
        ),
        case(
            "H24",
            "SELECT u::text FROM users u",
            Rewritten(vec!["ROW(u.id"], vec![n(0)], true),
        ),
        case(
            "H25",
            "SELECT u.row_to_json FROM users u",
            Block("calls row_to_json() on the whole row"),
        ),
        case(
            "H26",
            "SELECT public.users.to_jsonb FROM public.users",
            Block("on the whole row"),
        ),
        case(
            "H27",
            "SELECT p.concat FROM patients p",
            Block("on the whole row"),
        ),
        case(
            "H28",
            "SELECT s.to_json FROM (SELECT ssn FROM users) s",
            Block("on the whole row"),
        ),
        case("H29", "SELECT o.row_to_json FROM orders o", allow()),
    ]
}

fn target_sublinks() -> Vec<Case> {
    use Expect::*;
    vec![
        case(
            "I1",
            "SELECT (SELECT ssn FROM users WHERE id = 1)",
            Same(vec![n(0)], true),
        ),
        case(
            "I2",
            "SELECT o.id, (SELECT u.ssn FROM users u WHERE u.id = o.user_id) FROM orders o",
            Same(vec![n(1)], true),
        ),
        case(
            "I3",
            "SELECT (SELECT upper(ssn) FROM users LIMIT 1)",
            Same(vec![n(0)], true),
        ),
        case(
            "I4",
            "SELECT ARRAY(SELECT ssn FROM users)",
            Same(vec![n(0)], true),
        ),
        case(
            "I5",
            "SELECT EXISTS (SELECT 1 FROM users WHERE ssn = $1)",
            Same(vec![], true),
        ),
        case(
            "I6",
            "SELECT $1::text IN (SELECT ssn FROM users) AS found",
            Same(vec![n(0)], true),
        ),
        case(
            "I7",
            "SELECT o.id, o.user_id IN (SELECT id FROM users WHERE ssn LIKE '9%') FROM orders o",
            Same(vec![], true),
        ),
        case("I8", "SELECT EXISTS (SELECT ssn FROM users)", allow()),
        // JSON_ARRAY(query) aggregates the query's rows, like ARRAY(query).
        case(
            "I9",
            "SELECT JSON_ARRAY(SELECT ssn FROM users)",
            Same(vec![n(0)], true),
        ),
        case(
            "I9",
            "SELECT JSON_ARRAY(SELECT ssn FROM users RETURNING text)",
            Same(vec![n(0)], true),
        ),
        case(
            "I9",
            "SELECT x FROM (SELECT JSON_ARRAY(SELECT ssn FROM users) AS x) s",
            Same(vec![n(0)], true),
        ),
        case(
            "I9",
            "SELECT JSON_OBJECT('k': JSON_ARRAY(SELECT ssn FROM users))",
            Same(vec![n(0)], true),
        ),
        case(
            "I9",
            "SELECT JSON_ARRAY(SELECT x FROM (SELECT ssn AS x FROM users) s)",
            Same(vec![n(0)], true),
        ),
        case(
            "I9",
            "SELECT id FROM orders WHERE JSON_ARRAY(SELECT ssn FROM users)::text <> ''",
            Same(vec![], true),
        ),
        case(
            "I9",
            "INSERT INTO audit (note) SELECT JSON_ARRAY(SELECT ssn FROM users)::text",
            Block("INSERT would move"),
        ),
        case(
            "I9",
            "SELECT pg_notify('c', JSON_ARRAY(SELECT ssn FROM users)::text)",
            Block("pg_notify() would move"),
        ),
    ]
}

fn returning() -> Vec<Case> {
    use Expect::*;
    vec![
        case(
            "J1",
            "UPDATE users SET name = $1 WHERE id = $2 RETURNING ssn",
            Same(vec![p(0)], true),
        ),
        case(
            "J2",
            "DELETE FROM users WHERE id = $1 RETURNING *",
            Rewritten(vec!["RETURNING users.id AS id"], vec![p(2)], true),
        ),
        case(
            "J3",
            "UPDATE users SET name = 'x' WHERE id = 1 RETURNING id, upper(ssn)",
            Same(vec![n(1)], true),
        ),
        case(
            "J4",
            "INSERT INTO users (id, name, ssn) VALUES ($1, $2, $3) RETURNING id, ssn",
            Same(vec![p(1)], true),
        ),
        case(
            "J5",
            "INSERT INTO users (id, ssn) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET ssn = excluded.ssn RETURNING ssn",
            Same(vec![p(0)], true),
        ),
        case(
            "J6",
            "UPDATE orders o SET total = 0 FROM users u WHERE u.id = o.user_id AND u.ssn = $1 RETURNING o.id, u.ssn",
            Same(vec![p(1)], true),
        ),
        case(
            "J7",
            "UPDATE users SET name = $1 WHERE ssn = $2 RETURNING id",
            Same(vec![], true),
        ),
        case(
            "J8",
            "INSERT INTO users (id, name) SELECT id + 100, name FROM users WHERE ssn LIKE '9%' RETURNING ssn",
            Same(vec![p(0)], true),
        ),
        case(
            "J9",
            "UPDATE users SET name = 'x' WHERE id = 1 RETURNING old.ssn, new.ssn",
            Same(vec![p(0), p(1)], true),
        ),
        case(
            "J10",
            "UPDATE users SET name = 'x' WHERE id = 1 RETURNING old.*",
            Rewritten(vec!["RETURNING old.id AS id"], vec![p(2)], true),
        ),
        case(
            "J11",
            "DELETE FROM users WHERE id = 1 RETURNING old",
            Rewritten(vec!["ROW(old.id"], vec![n(0)], true),
        ),
        case(
            "J12",
            "UPDATE users SET name = 'x' RETURNING WITH (OLD AS o) o.ssn",
            Same(vec![p(0)], true),
        ),
        case(
            "J13",
            "UPDATE orders SET total = 0 WHERE id = 1 RETURNING id",
            Same(vec![], true),
        ),
    ]
}

fn writes() -> Vec<Case> {
    use Expect::*;
    vec![
        case(
            "K1",
            "INSERT INTO orders (id, user_id, total) SELECT id, id, length(ssn) FROM users",
            Block("INSERT would move values of proxy-masked columns (public.users.ssn)"),
        ),
        case(
            "K2",
            "INSERT INTO users_2024 (id, name) SELECT id, ssn FROM users",
            Block("INSERT"),
        ),
        case(
            "K3",
            "INSERT INTO users_2024 SELECT * FROM users",
            Block("INSERT"),
        ),
        case(
            "K4",
            "INSERT INTO orders (user_id, total) SELECT id, 0 FROM users WHERE ssn = $1",
            Same(vec![], true),
        ),
        case(
            "K5",
            "INSERT INTO orders (user_id, total) VALUES ((SELECT id FROM users WHERE ssn = $1), 0)",
            Same(vec![], true),
        ),
        case(
            "K6",
            "INSERT INTO users (id, name) VALUES (3, (SELECT ssn FROM users WHERE id = 1))",
            Block("INSERT"),
        ),
        case(
            "K7",
            "INSERT INTO users (id, ssn) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET name = users.ssn",
            Block("ON CONFLICT DO UPDATE"),
        ),
        case(
            "K8",
            "UPDATE users SET name = ssn WHERE id = 1",
            Block("UPDATE"),
        ),
        case(
            "K9",
            "UPDATE users SET name = CASE WHEN ssn LIKE '9%' THEN 'nine' ELSE name END",
            Block("UPDATE"),
        ),
        case(
            "K10",
            "UPDATE orders SET total = (SELECT length(ssn) FROM users WHERE users.id = orders.user_id)",
            Block("UPDATE"),
        ),
        case(
            "K11",
            "UPDATE users SET ssn = upper(ssn) WHERE id = 1",
            Block("UPDATE"),
        ),
        // Writes a proxy relation.
        case(
            "K12",
            "UPDATE users SET ssn = $1 WHERE id = $2",
            Same(vec![], true),
        ),
        case(
            "K13",
            "UPDATE orders o SET total = 0 FROM users u WHERE u.id = o.user_id AND u.ssn LIKE '9%'",
            Same(vec![], true),
        ),
        case(
            "K14",
            "DELETE FROM users WHERE ssn = $1",
            Same(vec![], true),
        ),
        case(
            "K15",
            "DELETE FROM orders USING users u WHERE u.id = orders.user_id AND u.ssn = $1",
            Same(vec![], true),
        ),
        case(
            "K16",
            "INSERT INTO users (id, ssn) VALUES ($1, $2)",
            Same(vec![], true),
        ),
        case(
            "K17",
            "UPDATE users SET email = ssn WHERE id = 1",
            Block("UPDATE"),
        ),
        case("K18", "UPDATE users SET ssn = ssn", Block("UPDATE")),
        // Sinks are syntactic.
        case(
            "K19",
            "INSERT INTO audit (note) SELECT ssn FROM users WHERE false",
            Block("INSERT"),
        ),
        case(
            "K20",
            "UPDATE users SET (name, opted_in) = (SELECT ssn, true FROM users_2024 LIMIT 1)",
            Block("UPDATE"),
        ),
        // Triggers, constraints and defaults of any table may read
        // proxy-masked columns and quote them in messages.
        case(
            "K21",
            "INSERT INTO audit DEFAULT VALUES",
            Same(vec![], true),
        ),
        case(
            "K21",
            "INSERT INTO audit VALUES (1, 'x')",
            Same(vec![], true),
        ),
        case(
            "K21",
            "INSERT INTO audit SELECT id, name FROM users WHERE name = 'bob'",
            Same(vec![], true),
        ),
        case("K21", "DELETE FROM orders WHERE id = 2", Same(vec![], true)),
        case("K21", "COPY audit FROM STDIN", Same(vec![], true)),
        // Deferred constraint triggers fire at COMMIT.
        case("K21", "COMMIT", Same(vec![], true)),
        case("K21", "END", Same(vec![], true)),
        case("K21", "PREPARE TRANSACTION 'x'", Same(vec![], true)),
        case("K21", "BEGIN", allow()),
        case("K21", "ROLLBACK", allow()),
        // The subscript is part of the SET target.
        case(
            "K22",
            "UPDATE tags SET labels[length(u.ssn)] = 'x' FROM users u WHERE u.id = tags.id",
            Block("UPDATE"),
        ),
    ]
}

fn ctas_into_dml_ctes() -> Vec<Case> {
    use Expect::*;
    vec![
        case(
            "L1",
            "CREATE TABLE scratch AS SELECT id, ssn FROM users",
            Block("CREATE TABLE AS"),
        ),
        case(
            "L2",
            "CREATE TABLE scratch AS SELECT id FROM users WHERE ssn = '1'",
            Same(vec![], true),
        ),
        case(
            "L3",
            "SELECT id, ssn INTO scratch FROM users",
            Block("SELECT INTO"),
        ),
        case(
            "L4",
            "SELECT id INTO scratch FROM users WHERE ssn LIKE '9%'",
            Same(vec![], true),
        ),
        case(
            "L5",
            "CREATE MATERIALIZED VIEW mv AS SELECT upper(ssn) FROM users",
            Block("CREATE MATERIALIZED VIEW"),
        ),
        case(
            "L6",
            "CREATE TABLE scratch AS SELECT ssn FROM users WITH NO DATA",
            Block("CREATE TABLE AS"),
        ),
        case(
            "L7",
            "WITH moved AS (DELETE FROM users WHERE id = 1 RETURNING id, ssn) INSERT INTO orders (id, user_id, total) SELECT id, id, length(ssn) FROM moved",
            Block("INSERT"),
        ),
        case(
            "L8",
            "WITH u AS (UPDATE users SET name = ssn WHERE id = 1 RETURNING id) SELECT id FROM u",
            Block("UPDATE"),
        ),
        case(
            "L9",
            "WITH d AS (DELETE FROM users WHERE id = $1 RETURNING ssn) SELECT ssn FROM d",
            Same(vec![p(0)], true),
        ),
        case(
            "L10",
            "WITH ins AS (INSERT INTO orders (user_id, total) SELECT id, 0 FROM users WHERE ssn = $1 RETURNING id) SELECT count(*) FROM ins",
            Same(vec![], true),
        ),
        case(
            "L11",
            "WITH d AS (DELETE FROM users WHERE id = $1 RETURNING *) SELECT * FROM d",
            Rewritten(vec!["RETURNING users.id AS id"], vec![p(2)], true),
        ),
        case("L12", "CREATE TABLE users AS SELECT 1", Block("shadow")),
        // The table gets the whole union.
        case(
            "L13",
            "SELECT id::text INTO t FROM users UNION ALL SELECT ssn FROM users",
            Block("SELECT INTO"),
        ),
    ]
}

fn copy() -> Vec<Case> {
    use Expect::*;
    vec![
        case("M1", "COPY users TO STDOUT", Block("COPY")),
        case(
            "M2",
            "COPY users (id, ssn) TO STDOUT WITH (FORMAT csv)",
            Block("COPY"),
        ),
        case(
            "M3",
            "COPY users (id, name) TO STDOUT",
            Rewritten(
                vec!["COPY (SELECT id AS id, name AS name FROM public.users) TO STDOUT"],
                vec![],
                false,
            ),
        ),
        case(
            "M4",
            "COPY users (id, email) TO STDOUT",
            Rewritten(vec!["repeat("], vec![], false),
        ),
        case(
            "M5",
            "COPY (SELECT id, upper(ssn) FROM users) TO STDOUT",
            Block("COPY"),
        ),
        case(
            "M6",
            "COPY (SELECT id FROM users WHERE ssn = '1') TO STDOUT",
            Same(vec![], true),
        ),
        case(
            "M7",
            "COPY (SELECT * FROM user_ssns) TO STDOUT",
            Block("COPY"),
        ),
        case("M8", "COPY users_2024 TO STDOUT", Block("COPY")),
        // Writes a proxy relation.
        case("M9", "COPY users FROM STDIN", Same(vec![], true)),
        case("M10", "COPY orders TO STDOUT", allow()),
        case("M11", "COPY users TO '/tmp/x'", Block("file or program")),
    ]
}

fn cursors_prepare_execute() -> Vec<Case> {
    use Expect::*;
    vec![
        case(
            "N1",
            "DECLARE c CURSOR FOR SELECT id, ssn FROM users",
            Block("DECLARE CURSOR"),
        ),
        case(
            "N2",
            "DECLARE c CURSOR FOR SELECT id, name FROM users",
            allow(),
        ),
        // Any proxy use: a protocol Execute of portal c gets no masks.
        case(
            "N3",
            "DECLARE c CURSOR FOR SELECT id FROM users WHERE ssn::int > 5",
            Block("DECLARE CURSOR"),
        ),
        case(
            "N4",
            "PREPARE p AS SELECT ssn FROM users WHERE id = $1",
            Block("PREPARE"),
        ),
        case(
            "N5",
            "PREPARE p AS SELECT id, name FROM users WHERE id = $1",
            allow(),
        ),
        case(
            "N6",
            "PREPARE p AS SELECT id FROM users WHERE ssn = $1",
            Block("PREPARE"),
        ),
        case("N7", "EXECUTE p(1)", Block("EXECUTE")),
        // Every masked user (lead decision on §6.14).
        case("N7", "EXECUTE p(1)", Block("EXECUTE")).user("analyst"),
        case("N8", "FETCH ALL FROM c", Same(vec![], true)),
        case("N8", "MOVE NEXT IN c", Same(vec![], true)),
        case("N8", "FETCH ALL FROM c", allow()).user("analyst"),
        case("N8", "MOVE NEXT IN c", allow()).user("analyst"),
        case(
            "N9",
            "PREPARE p AS UPDATE users SET name = ssn WHERE id = $1",
            Block("UPDATE"),
        ),
        case(
            "N10",
            "BEGIN; DECLARE c CURSOR FOR SELECT ssn FROM users; FETCH ALL FROM c; COMMIT",
            Block("DECLARE CURSOR"),
        ),
        case(
            "N11",
            "DECLARE c CURSOR WITH HOLD FOR SELECT id FROM users WHERE ssn::int > 5",
            Block("DECLARE CURSOR"),
        ),
        case(
            "N12",
            "EXECUTE p((SELECT ssn FROM users LIMIT 1))",
            Block("EXECUTE"),
        ),
        case(
            "N13",
            "PREPARE p AS UPDATE users SET name = $1 WHERE id = $2 RETURNING ssn",
            Block("PREPARE"),
        ),
        case("N14", "CREATE TABLE t AS EXECUTE p(1)", Block("EXECUTE")),
        case(
            "N15",
            "PREPARE p AS SELECT id, name FROM users WHERE id = $1; EXECUTE p(1)",
            Same(vec![], true),
        ),
        case(
            "N15",
            "PREPARE p AS SELECT id, ssn FROM users WHERE id = $1; EXECUTE p(1)",
            Rewritten(vec!["NULL::varchar AS ssn", "EXECUTE p(1)"], vec![], false),
        )
        .user("analyst"),
        case("N16", "EXECUTE __pgdog_1", Block("EXECUTE")),
        case(
            "N17",
            "PREPARE p AS SELECT id FROM users ORDER BY ssn",
            Block("PREPARE"),
        ),
    ]
}

fn side_effects() -> Vec<Case> {
    use Expect::*;
    vec![
        case(
            "O1",
            "SELECT set_config('app.x', ssn, false) FROM users",
            Block("set_config"),
        ),
        case(
            "O2",
            "SELECT pg_notify('ch', ssn) FROM users",
            Block("pg_notify"),
        ),
        case(
            "O3",
            "SELECT setval('order_seq', length(ssn)) FROM users",
            Block("setval"),
        ),
        case(
            "O4",
            "SELECT pg_logical_emit_message(true, 'pfx', ssn) FROM users",
            Block("pg_logical_emit_message"),
        ),
        case(
            "O5",
            "SELECT id FROM users WHERE set_config('app.x', ssn, false) IS NOT NULL",
            Block("set_config"),
        ),
        case(
            "O6",
            "SELECT pg_advisory_lock(hashtext(ssn)) FROM users",
            Block("pg_advisory_lock"),
        ),
        case(
            "O7",
            "SELECT lo_from_bytea(0, convert_to(ssn, 'UTF8')) FROM users",
            Block("lo_from_bytea"),
        ),
        case(
            "O8",
            "SELECT set_config('app.matched', 'yes', false) FROM users WHERE ssn = $1",
            Same(vec![], true),
        ),
        case(
            "O9",
            "SELECT pg_notify('ch', name) FROM users ORDER BY ssn",
            Same(vec![], true),
        ),
        case(
            "O10",
            "SELECT pg_catalog.set_config('app.x', upper(ssn), true) FROM users",
            Block("set_config"),
        ),
        case("O11", "SELECT current_setting('app.x')", allow()),
        case(
            "O12",
            "SELECT id FROM users WHERE pg_advisory_xact_lock(hashtext(ssn)) IS NOT NULL",
            Block("pg_advisory_xact_lock"),
        ),
        case(
            "O13",
            "SELECT * FROM pg_logical_slot_get_changes('s', NULL, NULL)",
            Block("not allowed"),
        ),
        case(
            "O14",
            "SELECT setseed(length(ssn) / 100.0) FROM users",
            Block("setseed"),
        ),
        case(
            "O15",
            "SELECT * FROM set_config('app.x', (SELECT ssn FROM users LIMIT 1), false)",
            Block("set_config"),
        ),
        // Checked by name, despite the user-defined candidate.
        case(
            "O16",
            "SELECT set_config('app.x', ssn, false) FROM users",
            Block("set_config"),
        )
        .catalog(catalog_shadowing_set_config),
        case(
            "O17",
            "SELECT pg_restore_relation_stats('relation', 'public.audit'::regclass, 'relpages', length(ssn)) FROM users",
            Block(""),
        ),
        case(
            "O18",
            "SELECT pg_replication_slot_advance('s', ssn::pg_lsn) FROM users",
            Block("pg_replication_slot_advance"),
        ),
        case(
            "O19",
            "SELECT pg_copy_logical_replication_slot(ssn, 'x') FROM users",
            Block("pg_copy_logical_replication_slot"),
        ),
        case("O20", "SELECT nextval(ssn) FROM users", Block("nextval")),
    ]
}

fn functions() -> Vec<Case> {
    use Expect::*;
    vec![
        case(
            "P1",
            "SELECT my_func(ssn) FROM users",
            Block("isn't in the catalog"),
        ),
        case(
            "P2",
            "SELECT stash(ssn) FROM users",
            Block("calling public.stash() would move values"),
        ),
        case(
            "P3",
            "SELECT stash(name) FROM users WHERE ssn = $1",
            Same(vec![], true),
        ),
        case(
            "P4",
            "SELECT safe_fn(ssn) FROM users",
            Same(vec![n(0)], true),
        ),
        // Every candidate allowlisted: trusted, not a user-defined call.
        case(
            "P5",
            "SELECT digest(ssn, 'sha256') FROM users",
            Same(vec![n(0)], true),
        ),
        // Not inlined: its parameter reaches no sink.
        case("P6", "SELECT last4(ssn) FROM users", Same(vec![n(0)], true)),
        case(
            "P7",
            "SELECT id FROM users WHERE last4(ssn) = $1",
            Same(vec![], true),
        ),
        // Left as a call: the body reads proxy-masked columns.
        case(
            "P8",
            "SELECT user_ssn(o.user_id) FROM orders o",
            Same(vec![n(0)], true),
        ),
        case(
            "P9",
            "SELECT s.ssn FROM ssns() s WHERE s.id = 1",
            Same(vec![n(0)], true),
        ),
        // Not inlined, so the inlining conditions don't apply.
        case("P10", "SELECT user_ssn_definer(1)", Same(vec![n(0)], true)),
        case("P10", "SELECT volatile_ssn(1)", Same(vec![n(0)], true)),
        case("P10", "SELECT atomic_ssn(1)", Same(vec![n(0)], true)),
        case("P10+", "SELECT imm_ssn(1)", Same(vec![n(0)], true)),
        case("P11", "SELECT plpgsql_fn()", Block("plpgsql")),
        case("P12", "SELECT last4(name) FROM users", allow()),
        case("P13", "SELECT ssn_is(1, $1)", Same(vec![n(0)], true)),
        case(
            "P16",
            "SELECT upper_safe(ssn) FROM users",
            Same(vec![n(0)], true),
        ),
        case(
            "P17",
            "SELECT id FROM orders WHERE id @@@ user_id",
            Same(vec![], true),
        ),
        case(
            "P18",
            "SELECT ssn === 'x' FROM users",
            Same(vec![n(0)], true),
        ),
        // A SQL-masked body is inlined, as before.
        case(
            "P19",
            "SELECT email_of(1)",
            Rewritten(vec!["__pgdog_args", "repeat("], vec![], false),
        ),
        case("P21", "SELECT * FROM ssns()", Block("can't place masks")),
        case("P22", "SELECT count_users()", allow()),
        // A body that writes runs triggers and constraints on real values.
        case("P24", "SELECT bump_name(1)", Same(vec![], true)),
        case(
            "P24",
            "SELECT bump_name(id) FROM orders",
            Same(vec![], true),
        ),
        case("P24", "SELECT * FROM bump_name(1)", Same(vec![], true)),
        case("P24", "SELECT wrap_bump(1)", Same(vec![], true)),
        case("P24", "SELECT wipe_users()", Same(vec![], true)),
        case("P24", "SELECT * FROM bump_v", Same(vec![], true)),
        case("P24", "SELECT b FROM bump_v", Same(vec![], true)),
        case(
            "P24",
            "SELECT id FROM orders WHERE bump_name(id) > 0",
            Same(vec![], true),
        ),
    ]
}

/// User-defined functions called with values of proxy-masked columns: their
/// bodies are analyzed for where parameters can go.
fn param_sinks() -> Vec<Case> {
    use Expect::*;
    vec![
        case(
            "P14",
            "SELECT notify_fn(ssn) FROM users",
            Block("calling public.notify_fn() would move values"),
        ),
        case(
            "P14+",
            "SELECT id FROM users WHERE notify_fn(ssn) IS NULL",
            Block("calling public.notify_fn()"),
        ),
        // Positional and qualified parameters.
        case(
            "P14+",
            "SELECT notify_p(ssn) FROM users",
            Block("calling public.notify_p()"),
        ),
        case(
            "P14+",
            "SELECT notify_q(upper(ssn)) FROM users",
            Block("calling public.notify_q()"),
        ),
        // Clean arguments don't reach the body's sink.
        case("P14+", "SELECT notify_fn(name) FROM users", allow()),
        // Through a nested call whose parameter reaches a sink.
        case(
            "P15",
            "SELECT wrap_stash(ssn) FROM users",
            Block("calling public.wrap_stash()"),
        ),
        case(
            "P16+",
            "SELECT upper_safe(upper_safe(ssn)) FROM users",
            Same(vec![n(0)], true),
        ),
        // Parameters compared in the body's conditions go nowhere.
        case(
            "P16+",
            "SELECT ssn_is(id, ssn) FROM users",
            Same(vec![n(0)], true),
        ),
        case(
            "P16+",
            "SELECT user_ssn_p(length(ssn)) FROM users",
            Same(vec![n(0)], true),
        ),
        case(
            "P20",
            "SELECT * FROM stash((SELECT ssn FROM users LIMIT 1)) s",
            Block("calling public.stash()"),
        ),
        case(
            "P23",
            "SELECT id FROM users WHERE ssn ~~~ 'x'",
            Block("calling public.noisy_eq()"),
        ),
        case(
            "P24",
            "SELECT recursive_fn(length(ssn)) FROM users",
            Block("recursive"),
        ),
    ]
}

fn views() -> Vec<Case> {
    use Expect::*;
    let tables = PROXY_CONFIG.replacen("[general]", "[general]\ninline_views = false", 1);
    vec![
        case(
            "Q1",
            "SELECT ssn FROM user_ssns",
            Rewritten(
                vec![
                    "SELECT ssn AS ssn FROM (SELECT users.id AS id, users.ssn AS ssn FROM public.users) user_ssns(id, ssn)",
                ],
                vec![p(0)],
                false,
            ),
        ),
        case(
            "Q2",
            "SELECT ssn, email FROM user_contacts WHERE id = $1",
            Rewritten(vec!["users.ssn AS ssn", "repeat("], vec![p(0)], false),
        ),
        case(
            "Q3",
            "SELECT loud FROM user_loud",
            Rewritten(vec!["upper("], vec![n(0)], true),
        ),
        case(
            "Q4",
            "SELECT ssn FROM ssn_barrier",
            Same(vec![pt(0)], false),
        ),
        case("Q5", "SELECT loud FROM ssn_barrier", Same(vec![n(0)], true)),
        case(
            "Q6",
            "SELECT id FROM ssn_barrier WHERE loud = $1",
            Same(vec![], true),
        ),
        case(
            "Q7",
            "SELECT * FROM ssn_barrier",
            Rewritten(vec!["ssn_barrier.loud AS loud"], vec![pt(1), n(2)], true),
        ),
        case("Q8", "SELECT ssn FROM ssn_counts", Same(vec![pt(0)], false)),
        case("Q9", "SELECT name FROM user_names", Block("no definition")),
        case(
            "Q10",
            "SELECT v.s FROM user_ssns AS v(i, s) WHERE v.i = 1",
            Rewritten(vec![") v(i, s) WHERE v.i = 1"], vec![p(0)], false),
        ),
        case(
            "Q11",
            "UPDATE user_ssns SET ssn = $1 WHERE id = $2",
            Block("write through"),
        ),
        case(
            "Q12",
            "SELECT ssn FROM nested_v",
            Rewritten(vec!["FROM (SELECT user_ssns.ssn"], vec![p(0)], false),
        ),
        case(
            "Q13",
            "SELECT * FROM user_ssns",
            Rewritten(vec!["SELECT * FROM (SELECT"], vec![p(1)], false),
        ),
        case(
            "Q14",
            "LOCK TABLE user_ssns",
            Block("only be read in a FROM list"),
        ),
        // Table-like: masked by lineage.
        case("Q15", "SELECT ssn FROM user_ssns", Same(vec![pt(0)], false)).config(tables.clone()),
        // A write through a view writes its relations, and runs their
        // triggers and constraints.
        case(
            "Q16",
            "UPDATE user_names_v SET name = $1 WHERE id = $2",
            Same(vec![], true),
        ),
        case(
            "Q16",
            "DELETE FROM user_names_v WHERE id = $1",
            Same(vec![], true),
        ),
        case(
            "Q16",
            "INSERT INTO user_names_v (id, name) VALUES (1, 'x')",
            Same(vec![], true),
        ),
        case(
            "Q16",
            "WITH w AS (DELETE FROM user_names_v WHERE id = $1 RETURNING id) SELECT id FROM w",
            Same(vec![], true),
        ),
        case(
            "Q16",
            "UPDATE user_names_v SET name = 'x' WHERE id = 1",
            Same(vec![], true),
        )
        .config(tables),
    ]
}

/// Plain EXPLAIN only plans: values reach no sink but those the planner
/// evaluates. EXPLAIN ANALYZE runs the statement.
fn explain() -> Vec<Case> {
    use Expect::*;
    vec![
        case(
            "R1",
            "EXPLAIN SELECT ssn FROM users WHERE ssn = $1",
            Same(vec![], true),
        ),
        case(
            "R2",
            "EXPLAIN (ANALYZE, BUFFERS) SELECT id FROM users WHERE ssn::int > 5",
            Same(vec![], true),
        ),
        case(
            "R3",
            "EXPLAIN ANALYZE SELECT upper(ssn) FROM users",
            Same(vec![], true),
        ),
        case(
            "R4",
            "EXPLAIN SELECT * FROM users",
            Rewritten(vec!["users.ssn AS ssn"], vec![], false),
        ),
        case(
            "R5",
            "EXPLAIN ANALYZE UPDATE users SET name = ssn WHERE id = 1",
            Block("UPDATE"),
        ),
        case(
            "R6",
            "EXPLAIN ANALYZE UPDATE users SET name = 'x' WHERE ssn = $1",
            Same(vec![], true),
        ),
        case(
            "R7",
            "EXPLAIN UPDATE users SET name = ssn WHERE id = 1",
            Same(vec![], true),
        ),
        case(
            "R8",
            "EXPLAIN ANALYZE SELECT pg_notify('ch', ssn) FROM users",
            Block("pg_notify"),
        ),
        case(
            "R9",
            "EXPLAIN (ANALYZE) CREATE TABLE scratch AS SELECT ssn FROM users",
            Block("CREATE TABLE AS"),
        ),
        case(
            "R10",
            "EXPLAIN (FORMAT JSON) SELECT ssn FROM users",
            allow(),
        ),
        case(
            "R11",
            "EXPLAIN INSERT INTO audit (note) SELECT ssn FROM users",
            Same(vec![], true),
        ),
        case(
            "R11+",
            "EXPLAIN ANALYZE INSERT INTO audit (note) SELECT ssn FROM users",
            Block("INSERT"),
        ),
        case(
            "R12",
            "EXPLAIN (ANALYZE false) UPDATE users SET name = ssn",
            Same(vec![], true),
        ),
        case(
            "R13",
            "EXPLAIN (ANALYZE, VERBOSE) SELECT ssn FROM users",
            allow(),
        ),
        case(
            "R14",
            "EXPLAIN ANALYZE MERGE INTO orders o USING users u ON o.user_id = u.id WHEN MATCHED THEN DELETE",
            Block("MERGE"),
        ),
        case(
            "R15",
            "EXPLAIN SELECT set_config('x', ssn, false) FROM users",
            Same(vec![], true),
        ),
        case(
            "R16",
            "EXPLAIN EXECUTE p((SELECT ssn FROM users LIMIT 1))",
            Block("EXECUTE"),
        ),
        case("R16", "EXPLAIN ANALYZE EXECUTE p(1)", Block("EXECUTE")),
        // Planning can call the operator's function on pg_statistic values.
        case(
            "R17",
            "EXPLAIN SELECT id FROM users WHERE ssn ~~~ 'x'",
            Block("calling public.noisy_eq()"),
        ),
        case(
            "R17+",
            "EXPLAIN SELECT notify_fn(ssn) FROM users",
            Block("calling public.notify_fn()"),
        ),
        // The planner runs IMMUTABLE functions on constants, and the plan
        // shows the result.
        case("R18+", "EXPLAIN SELECT imm_ssn(1)", Block("IMMUTABLE")),
        case(
            "R18+",
            "EXPLAIN ANALYZE SELECT id FROM orders WHERE imm_ssn(1) = 'x'",
            Block("IMMUTABLE"),
        ),
        case(
            "R18+",
            "EXPLAIN SELECT wrap_imm(1)",
            Block("calls an IMMUTABLE function"),
        ),
        case("R18+", "EXPLAIN SELECT user_ssn(1)", Same(vec![], true)),
        // EXPLAIN EXECUTE evaluates the parameters and plans with them.
        case(
            "R19+",
            "PREPARE p AS SELECT id FROM orders WHERE total::text = $1; EXPLAIN EXECUTE p(user_ssn(1))",
            Block("EXECUTE would move values"),
        ),
        // A plain EXPLAIN of SELECT INTO creates no table.
        case(
            "R20+",
            "EXPLAIN SELECT ssn INTO scratch FROM users",
            allow(),
        ),
        case(
            "R20+",
            "EXPLAIN ANALYZE SELECT ssn INTO scratch FROM users",
            Block("SELECT INTO"),
        ),
    ]
}

fn multi_statement() -> Vec<Case> {
    use Expect::*;
    vec![
        case(
            "S1",
            "SELECT 1; SELECT ssn FROM users",
            Same(vec![at(1, p(0))], false),
        ),
        case(
            "S2",
            "BEGIN; SELECT id, ssn FROM users WHERE id = 1; COMMIT",
            Same(vec![at(1, p(1))], true),
        ),
        case(
            "S3",
            "SET application_name = 'dbg'; SELECT * FROM users; SELECT ssn FROM users WHERE ssn = '1'",
            Rewritten(vec![], vec![at(1, p(2)), at(2, p(0))], true),
        ),
        case(
            "S4",
            "UPDATE users SET name = 'x' WHERE id = 1 RETURNING ssn; SELECT upper(ssn) FROM users",
            Same(vec![p(0), at(1, n(0))], true),
        ),
        case(
            "S5",
            "SELECT ssn FROM users; UPDATE users SET name = ssn",
            Block("UPDATE"),
        ),
        case(
            "S6",
            "SELECT ssn FROM users; COPY users TO STDOUT",
            Block("COPY"),
        ),
        case(
            "S7",
            "PREPARE p AS SELECT id FROM users WHERE id = $1; EXECUTE p(1); DEALLOCATE p",
            Same(vec![], true),
        ),
        case("S8", "SELECT ssn FROM users;", Same(vec![p(0)], false)),
        case(
            "S9",
            "EXPLAIN SELECT ssn FROM users; SELECT ssn FROM users",
            Same(vec![at(1, p(0))], false),
        ),
        case(
            "S10",
            "SELECT id FROM orders; SELECT ssn FROM users WHERE id = 1; SELECT name FROM users",
            Same(vec![at(1, p(0))], false),
        ),
        // PgDog only follows a search_path change sent as a query of its own.
        case(
            "S11",
            "SET search_path TO public; SELECT ssn FROM users",
            Block("query of their own"),
        ),
        case(
            "S12",
            "SELECT set_config('search_path', 'public', false); SELECT ssn FROM users",
            Block("set_config"),
        ),
        case(
            "S13",
            "SELECT ssn FROM users; SET search_path TO other",
            Block("query of their own"),
        ),
        case(
            "S13",
            "SELECT id FROM orders; SET search_path TO other",
            Block("query of their own"),
        ),
        case(
            "S13",
            "; SET search_path TO other",
            Block("query of their own"),
        ),
        case(
            "S13",
            "/* hint */ SET search_path TO other",
            Block("query of their own"),
        ),
        case("S13", "SELECT 1; RESET ALL", Block("query of their own")),
        case("S13", "SELECT 1; DISCARD ALL", Block("query of their own")),
        case(
            "S13",
            "SELECT 1; SET ROLE someone",
            Block("query of their own"),
        ),
        case(
            "S14",
            "SET search_path TO other; SELECT 1",
            Block("query of their own"),
        ),
        case("S14", "SET search_path TO other", allow()),
        case("S14", "  set LOCAL search_path TO other", allow()),
        case("S14", "RESET ALL", allow()),
        case("S14", "DISCARD ALL", allow()),
        case("S14", "SET ROLE someone", allow()),
        case(
            "S14",
            "SET statement_timeout TO 1000; SELECT ssn FROM users",
            Same(vec![at(1, p(0))], false),
        ),
        // Empty statements don't count.
        case(
            "S15",
            "SELECT 1;; SELECT ssn FROM users",
            Same(vec![at(1, p(0))], false),
        ),
        case(
            "S16",
            "SELECT upper(ssn) FROM users; SELECT 1",
            Same(vec![n(0)], true),
        ),
        case(
            "S17",
            "DROP TABLE archive; SELECT ssn FROM users",
            Block("name resolution"),
        ),
        // Redaction depends on the relation COPY FROM, VACUUM and ANALYZE name.
        case(
            "S17",
            "DROP TABLE archive; COPY users FROM STDIN",
            Block("name resolution"),
        ),
        case(
            "S17",
            "DROP TABLE archive; VACUUM users",
            Block("name resolution"),
        ),
        case(
            "S17",
            "DROP TABLE archive; ANALYZE users",
            Block("name resolution"),
        ),
        case(
            "S17",
            "CREATE TABLE t2 (id int); VACUUM",
            Same(vec![], true),
        ),
        // The form PgDog tracks.
        case(
            "S18",
            "SELECT set_config('search_path', 'other', false)",
            Block("set_config"),
        ),
        case(
            "S19",
            "SELECT id, set_config('search_path', 'other', false) FROM orders",
            Block("set_config"),
        ),
    ]
}

fn mixed_with_sql_masks() -> Vec<Case> {
    use Expect::*;
    vec![
        case(
            "T1",
            "SELECT id, ssn, email FROM users WHERE email LIKE $1 AND ssn = $2 ORDER BY ssn",
            Rewritten(vec!["AND ssn = $2 ORDER BY ssn"], vec![p(1)], true),
        ),
        case(
            "T2",
            "SELECT upper(ssn), upper(email) FROM users",
            Rewritten(vec!["repeat("], vec![n(0)], true),
        ),
        case(
            "T3",
            "SELECT id, ssn FROM users WHERE ssn = $1",
            Rewritten(
                vec!["SELECT id AS id, NULL::varchar AS ssn FROM users WHERE NULL::varchar = $1"],
                vec![],
                false,
            ),
        )
        .user("analyst"),
        case(
            "T4",
            "COPY users TO STDOUT",
            Rewritten(vec!["COPY (SELECT", "NULL::varchar AS ssn"], vec![], false),
        )
        .user("analyst"),
        case(
            "T5",
            "UPDATE users SET name = ssn WHERE id = 1",
            Rewritten(vec!["SET name = NULL::varchar"], vec![], false),
        )
        .user("analyst"),
        case(
            "T6",
            "SELECT ssn FROM users UNION ALL SELECT mrn FROM patients",
            Rewritten(vec!["NULL::varchar", "NULL::text"], vec![], false),
        )
        .user("analyst"),
        case(
            "T7",
            "SELECT u.row_to_json FROM users u",
            Block("on the whole row"),
        )
        .user("analyst"),
        // Nested expansion is only for users with proxy masks.
        case("T8", "SELECT * FROM (SELECT * FROM orders) s", allow()).user("analyst"),
    ]
}

fn exempt_user() -> Vec<Case> {
    [
        "SELECT ssn, upper(ssn) FROM users WHERE ssn = $1",
        "COPY users TO STDOUT",
        "UPDATE users SET name = ssn",
        "SELECT set_config('x', ssn, false) FROM users",
    ]
    .into_iter()
    .map(|sql| case("U", sql, allow()).user("admin"))
    .collect()
}

fn parameters_literals() -> Vec<Case> {
    use Expect::*;
    vec![
        case(
            "V1",
            "SELECT ssn FROM users WHERE id = $1",
            Same(vec![p(0)], false),
        ),
        case(
            "V2",
            "SELECT ssn, email FROM users WHERE ssn = $1 AND email = $2",
            Rewritten(vec!["WHERE ssn = $1"], vec![p(0)], true),
        ),
        case(
            "V3",
            "SELECT ssn FROM users WHERE ssn = '123-45-6789' AND id = 7",
            Same(vec![p(0)], true),
        ),
        case(
            "V4",
            "SELECT id FROM users WHERE ssn::int = $1::int",
            Same(vec![], true),
        ),
        // The placeholder is clean on the shape path.
        case(
            "V5",
            "SELECT 'lit', ssn FROM users WHERE id = 3",
            Same(vec![p(1)], false),
        ),
    ]
}

fn existing_blocks() -> Vec<Case> {
    use Expect::*;
    const DDL: &str = "DDL expressions";
    let mut cases = vec![
        case("W1", "DO $$ BEGIN PERFORM 1; END $$", Block("")),
        case(
            "W2",
            "MERGE INTO users u USING orders o ON u.id = o.user_id WHEN MATCHED THEN DELETE",
            Block(""),
        ),
        case(
            "W3",
            "SELECT * FROM pg_stats WHERE tablename = 'users'",
            Block("pg_stats"),
        ),
        case("W4", "CREATE INDEX ON users ((ssn::int))", Block("")),
        case(
            "W5",
            "SELECT query_to_xml('SELECT ssn FROM users', true, true, '')",
            Block("query_to_xml"),
        ),
        case(
            "W6",
            "PREPARE p AS MERGE INTO orders o USING users u ON o.user_id = u.id WHEN MATCHED THEN DELETE",
            Block("MERGE"),
        ),
        case("W7", "SELECT lo_get(1)", Block("lo_get")),
        case(
            "W8",
            "SELECT pg_logical_slot_peek_changes('s', NULL, NULL)",
            Block("not allowed"),
        ),
        case(
            "W9",
            "ALTER TABLE orders ADD COLUMN x text DEFAULT public.user_ssn(1)",
            Block(DDL),
        ),
        case(
            "W10",
            "CREATE TABLE t (x text DEFAULT public.user_ssn(1))",
            Block(DDL),
        ),
        case(
            "W11",
            "ALTER TABLE audit ALTER note TYPE text USING public.user_ssn(id)",
            Block(DDL),
        ),
        case(
            "W12",
            "CREATE INDEX ON audit ((public.user_ssn(id)))",
            Block(DDL),
        ),
        // DDL and maintenance of any relation run event triggers, CHECK and
        // index expression functions, which may read proxy-masked columns.
        case(
            "W13",
            "CREATE TABLE t (x text DEFAULT 'a')",
            Same(vec![], true),
        ),
        case("W14", "VACUUM ANALYZE users", Same(vec![], true)),
        case("W16", "ANALYZE orders", Same(vec![], true)),
    ];
    cases.extend(
        ["LOCK TABLE users", "TRUNCATE users", "VACUUM"]
            .into_iter()
            .map(|sql| case("W15", sql, Same(vec![], true))),
    );
    cases
}

#[test]
fn test_proxy_plain_outputs() {
    check(plain_outputs());
}

#[test]
fn test_proxy_stars() {
    check(stars());
}

#[test]
fn test_proxy_subqueries_ctes() {
    check(subqueries_ctes());
}

#[test]
fn test_proxy_set_operations() {
    check(set_operations());
}

#[test]
fn test_proxy_values_lateral_joins() {
    check(values_lateral_joins());
}

#[test]
fn test_proxy_grouping_ordering() {
    check(grouping_ordering());
}

#[test]
fn test_proxy_conditions() {
    check(conditions());
}

#[test]
fn test_proxy_computed_outputs() {
    check(computed_outputs());
}

#[test]
fn test_proxy_target_sublinks() {
    check(target_sublinks());
}

#[test]
fn test_proxy_returning() {
    check(returning());
}

#[test]
fn test_proxy_writes() {
    check(writes());
}

#[test]
fn test_proxy_ctas_into_dml_ctes() {
    check(ctas_into_dml_ctes());
}

#[test]
fn test_proxy_copy() {
    check(copy());
}

#[test]
fn test_proxy_cursors_prepare_execute() {
    check(cursors_prepare_execute());
}

#[test]
fn test_proxy_side_effects() {
    check(side_effects());
}

#[test]
fn test_proxy_functions() {
    check(functions());
}

#[test]
fn test_proxy_param_sinks() {
    check(param_sinks());
}

/// Bodies parsed to find where parameters go by a masker analyzing `sql`
/// as `engineer`, and why it blocked, if it did.
fn param_parses(sql: &str) -> (usize, Option<String>) {
    let policies =
        Policies::with_registry(Config::from_toml(PROXY_CONFIG).unwrap(), &proxy_registry())
            .unwrap();
    let catalog = catalog();
    let assignments = Assignments::new(&policies, "db", &catalog);
    let profile = policies.profile("engineer", "db");
    let ctx = Context {
        catalog: &catalog,
        assignments: &assignments,
        policies: &policies,
        profile: &profile,
        search_path: vec!["public".into()],
    };
    let mut result = None;
    make::try_owned(|mem| {
        let mut stmts = mem.parse(sql)?;
        let mut masker = Masker::new(mem, &ctx);
        for (index, stmt) in stmts.as_mut().into_iter().enumerate() {
            masker.statement(stmt);
            masker.finish_statement(index);
        }
        result = Some((masker.param_parses(), masker.blocked.clone()));
        Ok::<_, pg_raw_parse::Error>(stmts)
    })
    .unwrap();
    result.unwrap()
}

#[test]
fn test_param_sinks_memoized() {
    // Each body is parsed once, however often the function is called.
    assert_eq!(
        param_parses(
            "SELECT last4(ssn), upper_safe(ssn), last4(upper(ssn)) FROM users; SELECT last4(ssn) FROM users WHERE upper_safe(ssn) = $1"
        ),
        (2, None)
    );
    // Only calls with values of proxy-masked columns need it.
    assert_eq!(
        param_parses("SELECT last4(name), upper_safe($1) FROM users"),
        (0, None)
    );
    // wrap_stash, and stash, which it calls with its parameter.
    let (parses, blocked) = param_parses("SELECT wrap_stash(ssn) FROM users");
    assert_eq!(parses, 2);
    assert!(blocked.is_some_and(|reason| reason.contains("wrap_stash")));
}

#[test]
fn test_proxy_views() {
    check(views());
}

#[test]
fn test_proxy_explain() {
    check(explain());
}

#[test]
fn test_proxy_multi_statement() {
    check(multi_statement());
}

#[test]
fn test_proxy_mixed_with_sql_masks() {
    check(mixed_with_sql_masks());
}

#[test]
fn test_proxy_exempt_user() {
    check(exempt_user());
}

#[test]
fn test_proxy_parameters_literals() {
    check(parameters_literals());
}

#[test]
fn test_existing_blocks_with_proxies() {
    check(existing_blocks());
}

#[test]
fn test_proxy_unknown_type_oid() {
    // A proxy-masked column of a type the catalog doesn't know: NULL.
    let legacy = format!(
        "{PROXY_CONFIG}\n[[masked_columns]]\nname = \"legacy\"\ncolumn = \"code\"\npolicy = \"ssn\"\n"
    );
    check(vec![
        case(
            "X8",
            "SELECT code FROM legacy",
            Expect::Same(vec![n(0)], false),
        )
        .config(legacy),
    ]);
}

/// Rewrites list the SQL-masked columns they rewrote: references to
/// proxy-masked columns aren't rewritten.
#[test]
fn test_proxy_columns_not_listed_as_rewritten() {
    let policies =
        Policies::with_registry(Config::from_toml(PROXY_CONFIG).unwrap(), &proxy_registry())
            .unwrap();
    let catalog = catalog();
    let assignments = Assignments::new(&policies, "db", &catalog);
    let profile = policies.profile("engineer", "db");
    let ctx = Context {
        catalog: &catalog,
        assignments: &assignments,
        policies: &policies,
        profile: &profile,
        search_path: vec!["public".into()],
    };
    for (sql, expected) in [
        (
            "SELECT * FROM users WHERE ssn = $1",
            vec!["public.users.email"],
        ),
        ("SELECT ssn FROM user_ssns", vec![]),
        (
            "SELECT s.*, upper(u.ssn) FROM (SELECT * FROM orders) s, users u",
            vec![],
        ),
    ] {
        let Outcome::Rewritten { masked, .. } = analyze(sql, &ctx) else {
            panic!("{sql}: a rewrite");
        };
        let expected: std::collections::BTreeSet<String> =
            expected.into_iter().map(str::to_owned).collect();
        assert_eq!(masked, expected, "{sql}");
    }
}

/// Every corpus row.
fn corpus() -> Vec<Case> {
    [
        plain_outputs(),
        stars(),
        subqueries_ctes(),
        set_operations(),
        values_lateral_joins(),
        grouping_ordering(),
        conditions(),
        computed_outputs(),
        target_sublinks(),
        returning(),
        writes(),
        ctas_into_dml_ctes(),
        copy(),
        cursors_prepare_execute(),
        side_effects(),
        functions(),
        param_sinks(),
        views(),
        explain(),
        multi_statement(),
        mixed_with_sql_masks(),
        exempt_user(),
        parameters_literals(),
        existing_blocks(),
    ]
    .concat()
}

/// A corpus row, for the engine tests.
pub(crate) struct Row {
    pub id: &'static str,
    pub user: &'static str,
    pub sql: &'static str,
    pub config: String,
    pub catalog: fn() -> Catalog,
}

/// Every corpus row, for the engine tests.
pub(crate) fn rows() -> Vec<Row> {
    corpus()
        .into_iter()
        .map(|case| Row {
            id: case.id,
            user: case.user,
            sql: case.sql,
            config: case.config.unwrap_or_else(|| PROXY_CONFIG.to_owned()),
            catalog: case.catalog,
        })
        .collect()
}

/// Every corpus row with literals gets the same decision through its shape.
/// Statements calling `set_config` have no shape: whether they're allowed
/// depends on their literals.
#[test]
fn test_proxy_shape_parity() {
    let corpus = corpus();
    let mut checked = 0;
    let mut failures = vec![];
    for case in &corpus {
        if case.sql.contains("set_config") {
            assert!(
                shape::literals(case.sql).is_none(),
                "{} {:?} has a shape",
                case.id,
                case.sql
            );
            continue;
        }
        let Some(shaped) = case.run(true) else {
            continue;
        };
        checked += 1;
        let full = case.run(false).expect("full analysis").canonical();
        let shaped = shaped.canonical();
        if full != shaped {
            failures.push(format!(
                "{} ({}) {:?}\n    full  {full:?}\n    shape {shaped:?}",
                case.id, case.user, case.sql
            ));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
    assert!(checked > 90, "most of the corpus has a shape: {checked}");
}
