//! Masks compiled to SQL expression templates.
//!
//! Every mask is a SQL expression over the placeholder `val` (the masked column)
//! and the policy's `arguments`. The analyzer substitutes the placeholders with
//! column references at the AST level, so templates never go through string
//! interpolation with query text.
use std::collections::HashSet;
use std::ops::ControlFlow;

use pg_raw_parse::Node;
use pg_raw_parse::walk::{Recurse, walk_manual};

use crate::config::{Error, FALLBACK_REMOVED, MaskKind, MaskSpec, Policy, Search};

/// Placeholder for the masked column in templates.
pub const VALUE: &str = "val";

/// Broad type categories, used to pick type-appropriate masks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeFamily {
    Text,
    Numeric,
    Date,
    Timestamp,
    Time,
    Boolean,
    Uuid,
    Json,
    Bytea,
    Other,
}

impl TypeFamily {
    /// Classify a type name as reported by `information_schema.columns.data_type`
    /// or written in a policy.
    pub fn of(data_type: &str) -> Self {
        match data_type.trim().to_ascii_lowercase().as_str() {
            "text" | "character varying" | "varchar" | "character" | "char" | "bpchar" | "name"
            | "citext" => Self::Text,
            "smallint" | "integer" | "int" | "int2" | "int4" | "int8" | "bigint" | "numeric"
            | "decimal" | "real" | "float4" | "double precision" | "float8" => Self::Numeric,
            "date" => Self::Date,
            "timestamp"
            | "timestamp without time zone"
            | "timestamp with time zone"
            | "timestamptz" => Self::Timestamp,
            "time" | "time without time zone" | "time with time zone" | "timetz" => Self::Time,
            "boolean" | "bool" => Self::Boolean,
            "uuid" => Self::Uuid,
            "json" | "jsonb" => Self::Json,
            "bytea" => Self::Bytea,
            _ => Self::Other,
        }
    }
}

/// Type names safe to use in a cast, as reported by `information_schema`.
pub fn castable(data_type: &str) -> bool {
    !matches!(TypeFamily::of(data_type), TypeFamily::Other)
        || matches!(data_type, "inet" | "cidr" | "interval" | "money")
}

/// Operators allowed in raw searches (see `search = "raw"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SearchOp {
    Equality,
    In,
    Any,
    Distinct,
    IsNull,
    Range,
    Like,
}

impl SearchOp {
    fn parse(op: &str) -> Result<Vec<Self>, Error> {
        Ok(match op.to_ascii_lowercase().as_str() {
            "=" | "<>" | "!=" => vec![Self::Equality],
            "in" => vec![Self::In],
            "any" => vec![Self::Any],
            "distinct" => vec![Self::Distinct],
            "is_null" => vec![Self::IsNull],
            "<" | ">" | "<=" | ">=" | "between" | "range" => vec![Self::Range],
            "like" | "ilike" => vec![Self::Like],
            other => {
                return Err(Error::Invalid(format!(
                    "unknown search operator \"{other}\""
                )));
            }
        })
    }

    fn defaults() -> HashSet<Self> {
        [
            Self::Equality,
            Self::In,
            Self::Any,
            Self::Distinct,
            Self::IsNull,
        ]
        .into()
    }
}

/// A mask, ready to apply.
#[derive(Debug, Clone, PartialEq)]
pub enum Mask {
    /// The column is not masked for this user.
    Unmasked,
    /// Rewritten in the statement.
    Sql {
        /// SQL expression over `val` and the policy arguments.
        template: String,
        /// Operators usable on the raw value in predicates. Empty unless
        /// the rule sets `search = "raw"`.
        raw_search: HashSet<SearchOp>,
    },
    /// Masked in the results by [`crate::profile::Policies::proxies`]`[proxy]`.
    /// References are never rewritten.
    Proxy { proxy: usize },
}

/// A SQL mask's parts, borrowed.
#[derive(Debug, Clone, Copy)]
pub struct SqlMask<'a> {
    /// SQL expression over `val` and the policy arguments.
    pub template: &'a str,
    /// Operators usable on the raw value in predicates.
    pub raw_search: &'a HashSet<SearchOp>,
}

impl Mask {
    pub fn is_masked(&self) -> bool {
        !matches!(self, Self::Unmasked)
    }

    /// The SQL mask, if the column is rewritten in statements.
    pub fn sql(&self) -> Option<SqlMask<'_>> {
        match self {
            Self::Sql {
                template,
                raw_search,
            } => Some(SqlMask {
                template,
                raw_search,
            }),
            Self::Unmasked | Self::Proxy { .. } => None,
        }
    }

    /// Index of the proxy mask in [`crate::profile::Policies::proxies`], if
    /// the column is masked in the results.
    pub fn proxy(&self) -> Option<usize> {
        match self {
            Self::Proxy { proxy } => Some(*proxy),
            Self::Unmasked | Self::Sql { .. } => None,
        }
    }
}

/// Quote a SQL string literal.
pub fn literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Compile a SQL mask, or `none`, for a policy. Proxy masks are checked with
/// [`check_proxy`] and built from a [`crate::proxy::Registry`].
pub fn compile(policy: &Policy, spec: &MaskSpec) -> Result<Mask, Error> {
    let context = |msg: String| Error::Invalid(format!("policy \"{}\": {msg}", policy.name));
    let family = TypeFamily::of(&policy.data_type);
    let kind = spec
        .kind
        .ok_or_else(|| context("every policy and rule needs a \"mask\"".into()))?;

    if spec.fallback.is_some() {
        return Err(context(FALLBACK_REMOVED.into()));
    }
    if kind != MaskKind::Proxy && (spec.proxy.is_some() || spec.options.is_some()) {
        return Err(context(
            "\"proxy\" and \"options\" need mask = \"proxy\"".into(),
        ));
    }

    let template = match kind {
        MaskKind::None => return Ok(Mask::Unmasked),
        MaskKind::Proxy => {
            return Err(context(
                "mask \"proxy\" is built from a registry, not compiled".into(),
            ));
        }
        MaskKind::Null => "NULL".to_owned(),
        MaskKind::Constant => literal(
            spec.value
                .as_deref()
                .ok_or_else(|| context("mask \"constant\" needs a \"value\"".into()))?,
        ),
        MaskKind::Default => match family {
            TypeFamily::Text => "'****'".into(),
            TypeFamily::Numeric => "0".into(),
            TypeFamily::Date => "'1970-01-01'".into(),
            TypeFamily::Timestamp => "'1970-01-01 00:00:00'".into(),
            TypeFamily::Time => "'00:00:00'".into(),
            TypeFamily::Boolean => "false".into(),
            TypeFamily::Uuid => "'00000000-0000-0000-0000-000000000000'".into(),
            TypeFamily::Json => "'{}'".into(),
            TypeFamily::Bytea => "''".into(),
            TypeFamily::Other => "NULL".into(),
        },
        MaskKind::Partial => {
            require(family, TypeFamily::Text, "partial", &context)?;
            let prefix = spec.keep_prefix.unwrap_or(0);
            let suffix = spec.keep_suffix.unwrap_or(0);
            let fill = literal(spec.fill.as_deref().unwrap_or("*"));
            format!(
                "left({VALUE}, {prefix}) || repeat({fill}, greatest(length({VALUE}) - {}, 0)) || right({VALUE}, {suffix})",
                prefix + suffix
            )
        }
        MaskKind::Email => {
            require(family, TypeFamily::Text, "email", &context)?;
            format!("regexp_replace({VALUE}, '^[^@]*', '****')")
        }
        MaskKind::Hash => match family {
            TypeFamily::Text => format!("encode(sha256(convert_to({VALUE}, 'UTF8')), 'hex')"),
            TypeFamily::Bytea => format!("sha256({VALUE})"),
            _ => return Err(context("mask \"hash\" needs a text or bytea type".into())),
        },
        MaskKind::Round => {
            require(family, TypeFamily::Numeric, "round", &context)?;
            format!("round({VALUE}::numeric, {})", spec.digits.unwrap_or(0))
        }
        MaskKind::Truncate => {
            if !matches!(family, TypeFamily::Date | TypeFamily::Timestamp) {
                return Err(context(
                    "mask \"truncate\" needs a date or timestamp type".into(),
                ));
            }
            let unit = spec.unit.as_deref().unwrap_or("year");
            format!("date_trunc({}, {VALUE})", literal(unit))
        }
        MaskKind::Sql => spec
            .expression
            .clone()
            .ok_or_else(|| context("mask \"sql\" needs an \"expression\"".into()))?,
    };

    check_template(&template, &policy.arguments).map_err(context)?;

    let raw_search = match spec.search {
        Search::Masked => HashSet::new(),
        Search::Raw => match &spec.search_operators {
            None => SearchOp::defaults(),
            Some(ops) => {
                let mut parsed = HashSet::new();
                for op in ops {
                    parsed.extend(SearchOp::parse(op)?);
                }
                parsed
            }
        },
    };

    Ok(Mask::Sql {
        template,
        raw_search,
    })
}

/// Check a proxy rule, and return the name of its proxy mask. Proxy masks
/// apply to results only, so the SQL mask keys and raw search don't apply.
pub fn check_proxy<'s>(policy: &Policy, spec: &'s MaskSpec) -> Result<&'s str, Error> {
    let context = |msg: String| Error::Invalid(format!("policy \"{}\": {msg}", policy.name));
    if spec.kind != Some(MaskKind::Proxy) {
        return Err(context("not a proxy mask".into()));
    }
    if spec.fallback.is_some() {
        return Err(context(FALLBACK_REMOVED.into()));
    }
    let name = spec
        .proxy
        .as_deref()
        .ok_or_else(|| context("mask \"proxy\" needs a \"proxy\"".into()))?;
    if spec.search == Search::Raw {
        return Err(context(
            "search = \"raw\" doesn't apply to mask = \"proxy\": conditions on proxy-masked columns always compare real values".into(),
        ));
    }

    let sql_keys = [
        ("value", spec.value.is_some()),
        ("keep_prefix", spec.keep_prefix.is_some()),
        ("keep_suffix", spec.keep_suffix.is_some()),
        ("fill", spec.fill.is_some()),
        ("digits", spec.digits.is_some()),
        ("unit", spec.unit.is_some()),
        ("expression", spec.expression.is_some()),
        ("search_operators", spec.search_operators.is_some()),
    ];
    match sql_keys.iter().find(|(_, set)| *set) {
        Some((key, _)) => Err(context(format!(
            "\"{key}\" doesn't apply to mask = \"proxy\""
        ))),
        None => Ok(name),
    }
}

fn require(
    family: TypeFamily,
    expected: TypeFamily,
    mask: &str,
    context: &impl Fn(String) -> Error,
) -> Result<(), Error> {
    if family == expected {
        Ok(())
    } else {
        Err(context(format!(
            "mask \"{mask}\" doesn't support this policy's data_type"
        )))
    }
}

/// Templates must parse and may only reference `val` and the policy's arguments.
fn check_template(template: &str, arguments: &[String]) -> Result<(), String> {
    let parsed = pg_raw_parse::parse(&format!("SELECT ({template})"))
        .map_err(|err| format!("invalid mask expression \"{template}\": {err}"))?
        .into_inner();

    let stmt = match parsed.iter().collect::<Vec<_>>().as_slice() {
        [stmt] => *stmt,
        _ => {
            return Err(format!(
                "mask expression \"{template}\" must be one expression"
            ));
        }
    };

    let bad = walk_manual(stmt.into(), |node| match node {
        Node::ColumnRef(column) => {
            let fields: Vec<_> = column.fields().iter().collect();
            match fields.as_slice() {
                [field] => match field.as_str() {
                    Some(name) if name == VALUE || arguments.iter().any(|a| a == name) => {
                        Recurse::no()
                    }
                    Some(name) => ControlFlow::Break(name.to_owned()),
                    None => ControlFlow::Break("*".to_owned()),
                },
                _ => ControlFlow::Break(
                    pg_raw_parse::deparse(node)
                        .map(|d| d.as_str().to_owned())
                        .unwrap_or_default(),
                ),
            }
        }
        Node::SubLink(_) | Node::RangeVar(_) => ControlFlow::Break("a subquery".to_owned()),
        _ => Recurse::yes(),
    });

    match bad {
        Some(name) => Err(format!(
            "mask expression \"{template}\" can only reference \"{VALUE}\" and the policy's arguments, not {name}"
        )),
        None => Ok(()),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config::Config;

    fn policy(toml: &str) -> Policy {
        Config::from_toml(toml).unwrap().policies.remove(0)
    }

    #[test]
    fn test_builtin_masks() {
        let p = policy(
            r##"
[[policies]]
name = "ssn"
data_type = "text"
mask = "partial"
keep_suffix = 4
fill = "#"
"##,
        );
        let Mask::Sql {
            template,
            raw_search,
        } = compile(&p, &p.mask_spec()).unwrap()
        else {
            panic!("masked");
        };
        assert_eq!(
            template,
            "left(val, 0) || repeat('#', greatest(length(val) - 4, 0)) || right(val, 4)"
        );
        assert!(raw_search.is_empty());
    }

    #[test]
    fn test_accessors() {
        let p = policy(
            r#"
[[policies]]
name = "ssn"
data_type = "text"
mask = "partial"
keep_suffix = 4

[[policies.rules]]
roles = ["admin"]
mask = "none"
"#,
        );
        let mask = compile(&p, &p.mask_spec()).unwrap();
        assert!(mask.is_masked());
        let sql = mask.sql().expect("a SQL mask");
        assert!(sql.template.contains("right(val, 4)"), "{}", sql.template);
        assert!(sql.raw_search.is_empty());
        assert_eq!(mask.proxy(), None);

        let none = compile(&p, &p.rules[0].mask_spec()).unwrap();
        assert_eq!(none, Mask::Unmasked);
        assert!(!none.is_masked());
        assert!(none.sql().is_none());
        assert_eq!(none.proxy(), None);
    }

    #[test]
    fn test_type_mismatch() {
        let p = policy(
            r#"
[[policies]]
name = "salary"
data_type = "integer"
mask = "email"
"#,
        );
        assert!(compile(&p, &p.mask_spec()).is_err());
    }

    #[test]
    fn test_sql_template_references() {
        let p = policy(
            r#"
[[policies]]
name = "email"
data_type = "text"
arguments = ["opted_in"]
mask = "sql"
expression = "CASE WHEN opted_in THEN val ELSE NULL END"
"#,
        );
        assert!(compile(&p, &p.mask_spec()).is_ok());

        let p = policy(
            r#"
[[policies]]
name = "email"
data_type = "text"
mask = "sql"
expression = "(SELECT password FROM users LIMIT 1)"
"#,
        );
        assert!(compile(&p, &p.mask_spec()).is_err());

        let p = policy(
            r#"
[[policies]]
name = "email"
data_type = "text"
mask = "sql"
expression = "other_column"
"#,
        );
        assert!(compile(&p, &p.mask_spec()).is_err());
    }

    #[test]
    fn test_raw_search_sql_still_allowed() {
        let p = policy(
            r#"
[[policies]]
name = "ssn"
data_type = "text"
mask = "null"
search = "raw"
search_operators = ["=", "like"]
"#,
        );
        let Mask::Sql { raw_search, .. } = compile(&p, &p.mask_spec()).unwrap() else {
            panic!("masked");
        };
        assert_eq!(raw_search, [SearchOp::Equality, SearchOp::Like].into());

        // A SQL rule of a proxy policy can still search on raw values.
        let p = policy(
            r#"
[[policies]]
name = "ssn"
data_type = "text"
mask = "proxy"
proxy = "hmac_sha256"

[[policies.rules]]
roles = ["support"]
mask = "null"
search = "raw"
"#,
        );
        assert_eq!(check_proxy(&p, &p.mask_spec()).unwrap(), "hmac_sha256");
        let mask = compile(&p, &p.rules[0].mask_spec()).unwrap();
        assert!(!mask.sql().unwrap().raw_search.is_empty());
    }

    /// A proxy policy with `extra` added to its keys.
    fn proxy_policy(extra: &str) -> Policy {
        policy(&format!(
            r#"
[[policies]]
name = "ssn"
data_type = "text"
mask = "proxy"
proxy = "hmac_sha256"
{extra}
"#
        ))
    }

    #[test]
    fn test_check_proxy() {
        let p = proxy_policy("options = { length = 16 }");
        assert_eq!(check_proxy(&p, &p.mask_spec()).unwrap(), "hmac_sha256");
        // Proxy masks aren't SQL masks.
        let err = compile(&p, &p.mask_spec()).unwrap_err().to_string();
        assert!(err.contains("not compiled"), "{err}");

        let mut spec = p.mask_spec();
        spec.proxy = None;
        let err = check_proxy(&p, &spec).unwrap_err().to_string();
        assert!(err.contains("needs a \"proxy\""), "{err}");
        spec.kind = Some(MaskKind::Null);
        assert!(check_proxy(&p, &spec).is_err());
    }

    #[test]
    fn test_proxy_rejects_raw_search() {
        let p = proxy_policy("search = \"raw\"");
        let err = check_proxy(&p, &p.mask_spec()).unwrap_err().to_string();
        assert!(err.contains("search = \"raw\" doesn't apply"), "{err}");

        let p = proxy_policy("search_operators = [\"=\"]");
        let err = check_proxy(&p, &p.mask_spec()).unwrap_err().to_string();
        assert!(
            err.contains("\"search_operators\" doesn't apply to mask = \"proxy\""),
            "{err}"
        );

        // On a rule too.
        let p = proxy_policy(
            "[[policies.rules]]\nroles = [\"support\"]\nmask = \"proxy\"\nproxy = \"ff1\"\nsearch = \"raw\"",
        );
        let err = check_proxy(&p, &p.rules[0].mask_spec())
            .unwrap_err()
            .to_string();
        assert!(err.contains("search = \"raw\" doesn't apply"), "{err}");
    }

    #[test]
    fn test_proxy_rejects_sql_keys() {
        for (key, line) in [
            ("keep_suffix", "keep_suffix = 4"),
            ("value", "value = \"x\""),
            ("expression", "expression = \"val\""),
            ("digits", "digits = 2"),
            ("unit", "unit = \"day\""),
            ("fill", "fill = \"#\""),
            ("keep_prefix", "keep_prefix = 1"),
        ] {
            let p = proxy_policy(line);
            let err = check_proxy(&p, &p.mask_spec()).unwrap_err().to_string();
            assert!(
                err.contains(&format!("\"{key}\" doesn't apply to mask = \"proxy\"")),
                "{line}: {err}"
            );
        }
    }

    #[test]
    fn test_proxy_keys_need_proxy() {
        for line in ["proxy = \"x\"", "options = { length = 16 }"] {
            let p = policy(&format!(
                "[[policies]]\nname = \"ssn\"\ndata_type = \"text\"\nmask = \"null\"\n{line}\n"
            ));
            let err = compile(&p, &p.mask_spec()).unwrap_err().to_string();
            assert!(err.contains("need mask = \"proxy\""), "{line}: {err}");
            assert!(!err.contains("fallback"), "{line}: {err}");
        }
    }

    #[test]
    fn test_fallback_rejected() {
        // Config::check rejects it first; a spec built in code is rejected too.
        let p = proxy_policy("");
        let mut spec = p.mask_spec();
        spec.fallback = Some(toml::Value::String("null".into()));
        for err in [
            check_proxy(&p, &spec).unwrap_err(),
            compile(&p, &spec).unwrap_err(),
        ] {
            assert!(
                err.to_string().contains("\"fallback\" was removed"),
                "{err}"
            );
        }
    }
}
