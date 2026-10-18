//! What values carry from proxy-masked columns, and the output columns of a
//! query level.

/// What a value carries from proxy-masked columns.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub(crate) enum Taint {
    #[default]
    Clean,
    /// Values of a proxy-masked column, unchanged: `Policies::proxies[proxy]`,
    /// column type `type_oid` (0 = unknown).
    Proxy { proxy: usize, type_oid: u32 },
    /// Computed from proxy-masked values: NULL in results.
    Computed,
    /// Lineage unknown: `Computed` if the statement is proxy-relevant, else `Clean`.
    Unknown,
}

impl Taint {
    /// Combine the inputs of one value. `Clean` is the identity.
    pub fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Clean, other) | (other, Self::Clean) => other,
            (a, b) if a == b => a,
            _ => Self::Computed,
        }
    }

    /// Combine the sources of one column, e.g. the branches of a UNION.
    pub fn union(self, other: Self) -> Self {
        match (self, other) {
            (a, b) if a == b => a,
            (Self::Clean | Self::Unknown, Self::Clean | Self::Unknown) => Self::Unknown,
            _ => Self::Computed,
        }
    }

    /// The taint of a value computed from this one.
    pub fn computed(self) -> Self {
        match self {
            Self::Proxy { .. } => Self::Computed,
            other => other,
        }
    }

    /// Settle `Unknown` once it's known whether the statement is proxy-relevant.
    pub fn resolve(self, relevant: bool) -> Self {
        match self {
            Self::Unknown if relevant => Self::Computed,
            Self::Unknown => Self::Clean,
            other => other,
        }
    }

    pub fn is_clean(self) -> bool {
        self == Self::Clean
    }
}

/// One output column of a query level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutputColumn {
    /// The name Postgres gives it, when certain. `None` when Postgres'
    /// FigureColname might differ.
    pub name: Option<String>,
    pub taint: Taint,
}

/// What a query level's outputs say about a column name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lookup {
    /// Columns with this name, combined.
    Certain(Taint),
    /// No column certainly has this name, but columns with uncertain names,
    /// or the open rest, might: they carry at most this.
    Possible(Taint),
    Absent,
}

/// Output columns of a query level, or the columns of a derived FROM item.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Outputs {
    /// Columns at known positions.
    pub columns: Vec<OutputColumn>,
    /// `Some(t)`: more columns follow, at unknown positions and with unknown
    /// names, carrying at most `t`.
    pub rest: Option<Taint>,
}

impl Outputs {
    /// Columns nothing is known about: the fail-closed placeholder.
    pub fn unknown() -> Self {
        Self {
            columns: vec![],
            rest: Some(Taint::Unknown),
        }
    }

    /// Add the next column. Once the outputs are open, its position is
    /// unknown, so it joins `rest`.
    pub fn push(&mut self, column: OutputColumn) {
        match self.rest {
            Some(rest) => self.rest = Some(rest.union(column.taint)),
            None => self.columns.push(column),
        }
    }

    /// Columns of unknown number follow, carrying at most `taint`.
    pub fn open(&mut self, taint: Taint) {
        self.rest = Some(self.rest.map_or(taint, |rest| rest.union(taint)));
    }

    /// The outputs of a set operation: columns are combined by position, and
    /// named after the left branch's.
    pub fn union(self, right: Outputs) -> Outputs {
        if self.rest.is_some() || right.rest.is_some() || self.columns.len() != right.columns.len()
        {
            return Outputs {
                columns: vec![],
                rest: Some(self.bound().union(right.bound())),
            };
        }
        let columns = self
            .columns
            .into_iter()
            .zip(right.columns)
            .map(|(left, right)| OutputColumn {
                name: left.name,
                taint: left.taint.union(right.taint),
            })
            .collect();
        Outputs {
            columns,
            rest: None,
        }
    }

    /// The most any column carries.
    pub fn bound(&self) -> Taint {
        self.columns
            .iter()
            .map(|column| column.taint)
            .chain(self.rest)
            .reduce(Taint::union)
            .unwrap_or_default()
    }

    /// Rename the first columns after an alias column list.
    pub fn renamed(mut self, aliases: &[String]) -> Outputs {
        for (i, alias) in aliases.iter().enumerate() {
            match self.columns.get_mut(i) {
                Some(column) => column.name = Some(alias.clone()),
                // The alias names the next column of an open list; it follows
                // the known ones.
                None => match self.rest {
                    Some(taint) => self.columns.push(OutputColumn {
                        name: Some(alias.clone()),
                        taint,
                    }),
                    None => break,
                },
            }
        }
        self
    }

    /// Every column clean, e.g. a recursive CTE that read no proxy values.
    pub fn cleaned(self) -> Outputs {
        Outputs {
            columns: self
                .columns
                .into_iter()
                .map(|column| OutputColumn {
                    name: column.name,
                    taint: Taint::Clean,
                })
                .collect(),
            rest: self.rest.map(|_| Taint::Clean),
        }
    }

    /// The columns a name may refer to.
    pub fn lookup(&self, name: &str) -> Lookup {
        let certain = self
            .columns
            .iter()
            .filter(|column| column.name.as_deref() == Some(name))
            .map(|column| column.taint)
            .reduce(Taint::union);
        if let Some(taint) = certain {
            return Lookup::Certain(taint);
        }
        self.columns
            .iter()
            .filter(|column| column.name.is_none())
            .map(|column| column.taint)
            .chain(self.rest)
            .reduce(Taint::union)
            .map_or(Lookup::Absent, Lookup::Possible)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const A: Taint = Taint::Proxy {
        proxy: 0,
        type_oid: 1043,
    };
    const A_TEXT: Taint = Taint::Proxy {
        proxy: 0,
        type_oid: 25,
    };
    const B: Taint = Taint::Proxy {
        proxy: 1,
        type_oid: 1043,
    };

    fn column(name: &str, taint: Taint) -> OutputColumn {
        OutputColumn {
            name: Some(name.into()),
            taint,
        }
    }

    #[test]
    fn test_join_union_table() {
        use Taint::{Clean, Computed, Unknown};

        // (left, right, join, union)
        let table = [
            (Clean, Clean, Clean, Clean),
            (Clean, A, A, Computed),
            (Clean, Computed, Computed, Computed),
            (Clean, Unknown, Unknown, Unknown),
            (A, A, A, A),
            (A, A_TEXT, Computed, Computed),
            (A, B, Computed, Computed),
            (A, Computed, Computed, Computed),
            (A, Unknown, Computed, Computed),
            (Computed, Computed, Computed, Computed),
            (Computed, Unknown, Computed, Computed),
            (Unknown, Unknown, Unknown, Unknown),
        ];
        for (left, right, join, union) in table {
            assert_eq!(left.join(right), join, "{left:?} join {right:?}");
            assert_eq!(right.join(left), join, "{right:?} join {left:?}");
            assert_eq!(left.union(right), union, "{left:?} union {right:?}");
            assert_eq!(right.union(left), union, "{right:?} union {left:?}");
        }

        assert_eq!(A.computed(), Computed);
        assert_eq!(Unknown.computed(), Unknown);
        assert_eq!(Clean.computed(), Clean);
        assert!(Clean.is_clean());
        assert!(!Unknown.is_clean());
    }

    #[test]
    fn test_resolve() {
        assert_eq!(Taint::Unknown.resolve(true), Taint::Computed);
        assert_eq!(Taint::Unknown.resolve(false), Taint::Clean);
        for taint in [Taint::Clean, A, Taint::Computed] {
            assert_eq!(taint.resolve(true), taint);
            assert_eq!(taint.resolve(false), taint);
        }
    }

    #[test]
    fn test_outputs_union_open() {
        let left = Outputs {
            columns: vec![column("a", A), column("b", Taint::Clean)],
            rest: None,
        };
        let right = Outputs {
            columns: vec![column("x", A), column("y", A)],
            rest: None,
        };
        let union = left.clone().union(right.clone());
        assert_eq!(
            union,
            Outputs {
                columns: vec![column("a", A), column("b", Taint::Computed)],
                rest: None,
            }
        );

        // Either side open: every position is unknown.
        let mut open = right;
        open.open(Taint::Clean);
        assert_eq!(
            left.clone().union(open),
            Outputs {
                columns: vec![],
                rest: Some(Taint::Computed),
            }
        );

        // Different widths fail closed too.
        let narrow = Outputs {
            columns: vec![column("x", Taint::Clean)],
            rest: None,
        };
        assert_eq!(narrow.union(left).columns, vec![]);

        assert_eq!(Outputs::default().bound(), Taint::Clean);
        assert_eq!(Outputs::unknown().bound(), Taint::Unknown);
        assert_eq!(
            Outputs {
                columns: vec![column("a", A)],
                rest: None
            }
            .bound(),
            A
        );
    }

    #[test]
    fn test_outputs_push_after_open() {
        let mut outputs = Outputs::default();
        outputs.push(column("a", Taint::Clean));
        outputs.open(Taint::Clean);
        outputs.push(column("b", A));
        assert_eq!(outputs.columns, vec![column("a", Taint::Clean)]);
        assert_eq!(outputs.rest, Some(Taint::Computed));
        assert_eq!(outputs.lookup("a"), Lookup::Certain(Taint::Clean));
        assert_eq!(outputs.lookup("b"), Lookup::Possible(Taint::Computed));

        // An alias list names the known columns first, then the next ones.
        let renamed = outputs.clone().renamed(&["x".into(), "y".into()]);
        assert_eq!(
            renamed.columns,
            vec![column("x", Taint::Clean), column("y", Taint::Computed)]
        );
        assert_eq!(renamed.rest, Some(Taint::Computed));

        let closed = Outputs {
            columns: vec![column("a", A)],
            rest: None,
        };
        assert_eq!(closed.lookup("b"), Lookup::Absent);
        assert_eq!(
            closed
                .clone()
                .renamed(&["x".into(), "y".into()])
                .columns
                .len(),
            1
        );
        assert_eq!(closed.cleaned().columns, vec![column("a", Taint::Clean)]);

        // Duplicate names combine; uncertain names may be anything.
        let mixed = Outputs {
            columns: vec![
                column("a", A),
                column("a", Taint::Clean),
                OutputColumn {
                    name: None,
                    taint: B,
                },
            ],
            rest: None,
        };
        assert_eq!(mixed.lookup("a"), Lookup::Certain(Taint::Computed));
        assert_eq!(mixed.lookup("z"), Lookup::Possible(B));
    }
}
