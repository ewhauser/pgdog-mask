#!/usr/bin/env python3
"""Regenerate the seed corpora in fuzz/seeds from the crate's own tests.

statement: SQL string literals in src/ and tests/.
config: the fuzzing config and the integration configs.

Run from the repository root: python3 fuzz/scripts/seeds.py
"""
import hashlib
import pathlib
import re
import shutil

ROOT = pathlib.Path(__file__).resolve().parents[2]
SEEDS = ROOT / "fuzz" / "seeds"

SQL = re.compile(
    r"^\s*(/\*|--|\(|SELECT|WITH|INSERT|UPDATE|DELETE|MERGE|COPY|EXPLAIN|PREPARE|EXECUTE|"
    r"DECLARE|FETCH|CREATE|ALTER|DROP|TRUNCATE|SET|RESET|SHOW|BEGIN|START|COMMIT|ROLLBACK|"
    r"VALUES|TABLE|CALL|DO|GRANT|REVOKE|LOCK|COMMENT|SECURITY|LISTEN|NOTIFY|VACUUM|ANALYZE|"
    r"REFRESH|DISCARD|DEALLOCATE|CLOSE|IMPORT|REINDEX|CLUSTER)\b",
    re.IGNORECASE,
)
STRING = re.compile(r'r(#+)"(.*?)"\1|"((?:[^"\\]|\\.)*)"', re.DOTALL)


def unescape(text):
    return re.sub(
        r"\\(.)",
        lambda m: {"n": "\n", "t": "\t", "\\": "\\", '"': '"', "'": "'", "0": ""}.get(
            m.group(1), m.group(0)
        ),
        # Line continuations.
        re.sub(r"\\\n\s*", "", text),
    )


def statements():
    for path in sorted([*ROOT.glob("src/**/*.rs"), *ROOT.glob("tests/*.rs")]):
        for match in STRING.finditer(path.read_text()):
            raw, plain = match.group(2), match.group(3)
            sql = raw if raw is not None else unescape(plain)
            # Format strings aren't SQL yet.
            if "{" in sql or not SQL.match(sql):
                continue
            yield sql


def configs():
    yield (ROOT / "fuzz" / "src" / "fixture.rs").read_text().split('r#"', 1)[1].split('"#', 1)[0]
    for path in sorted(ROOT.glob("integration/**/*.toml")):
        text = path.read_text()
        if "[[policies]]" in text or "[general]" in text:
            yield text


def write(target, inputs):
    out = SEEDS / target
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    seen = set()
    for text in inputs:
        data = text.encode()
        name = hashlib.sha1(data).hexdigest()
        if name not in seen:
            seen.add(name)
            (out / name).write_bytes(data)
    print(f"{target}: {len(seen)} seeds")


write("statement", statements())
write("config", configs())
