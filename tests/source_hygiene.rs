//! Properties of the source tree itself, enforced on every `cargo test`.
//!
//! Nothing here is about runtime behaviour. This closes a gap where a real defect can ship while
//! every other gate — `cargo check`, `cargo clippy`, the integration suite, the e2e suite — passes
//! green, because none of those gates looks at the artifact in question.
//!
//! # Why this exists when `verify_convergence.sh` already checks the same thing
//!
//! Deliberate duplication, and the two are not interchangeable.
//!
//! `scripts/verify_convergence.sh::check_no_raw_sql` is a shell gate: it has to be *run*, it needs a
//! shell, and its first two versions were both silently broken. One used `ENDFILE`, a gawk extension
//! that is an always-false variable reference under the `mawk` actually installed here, so the block
//! never executed and the check reported CLEAN against a planted `execute_unprepared`. The second
//! exempted anything near the word "pragma" and reported CLEAN against a planted
//! `DELETE FROM api_keys`. A gate that cannot fail is worse than no gate, because it is reported as
//! evidence.
//!
//! This file is compiled and run by `cargo test`, so it executes in CI, in an IDE, and on any
//! developer's machine without anyone remembering a script. It also carries its own meta-test —
//! [`the_raw_sql_scanner_detects_what_it_is_looking_for`] — proving the scanner can actually see a
//! violation, which is precisely what both broken shell versions lacked.
//!
//! Ported from `simply_hook_executor`'s `tests/source_hygiene.rs`. The JavaScript half of the peer's
//! file lives in `tests/frontend_syntax_test.rs` here and is not duplicated.

use std::path::{Path, PathBuf};

/// Resolves a path relative to the crate root, so these tests are independent of the working
/// directory `cargo test` happens to be invoked from.
fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

/// Every construct that puts a hand-written SQL string in front of the database.
///
/// `Expr::cust` is included even though it sits inside the query builder: it splices an
/// uninterpreted fragment into a statement, so it carries exactly the injection risk the builder
/// otherwise removes.
const RAW_SQL_MARKERS: [&str; 8] = [
    "execute_unprepared",
    "Statement::from_string",
    "Statement::from_sql_and_values",
    "from_raw_sql",
    "query_one_raw",
    "query_all_raw",
    "execute_raw",
    "Expr::cust",
];

/// The **shape** of a DML statement: a leading keyword and the structural word that must follow it.
///
/// Matching the pair rather than the bare keyword is what makes this usable. A first version tested
/// for `SELECT `/`INSERT `/`UPDATE `/`DELETE ` case-insensitively and flagged eight ordinary English
/// error messages — `"Cannot delete yourself"`, `"you have no delete access to any group"`,
/// `"can_write or can_delete require can_read"`. Every one was prose, and a gate that cries wolf
/// eight times gets deleted rather than fixed.
///
/// A statement, by contrast, has a grammar: something is selected *from*, inserted *into*, updated
/// and *set*, deleted *from*. English almost never puts those words in that order, and SQL cannot
/// avoid it.
const DML_SHAPES: [(&str, &str); 4] = [
    ("SELECT ", " FROM "),
    ("INSERT ", " INTO "),
    ("UPDATE ", " SET "),
    ("DELETE ", " FROM "),
];

/// The paths permitted to contain raw SQL, each for a reason the query builder cannot address.
///
/// **The test that matters is not "is it on the list" but "is it reachable from a request".** Both
/// entries run once at startup and neither can be reached by any HTTP caller, which is why the
/// injection risk the builder removes does not apply to them. [`no_handler_is_ever_exempted`]
/// enforces that property mechanically rather than trusting this comment.
const ALLOWED: [(&str, &str); 2] = [
    (
        "src/db.rs",
        "SQLite `PRAGMA` statements and their readback. A pragma is not a query — it configures how \
         the engine behaves, not what it is asked — and SeaORM's builders cannot express one. \
         Backend-gated to SQLite and issued once at startup.",
    ),
    (
        "src/migration/",
        "DDL. Generated columns (`GENERATED ALWAYS AS`), per-backend storage classes, and SQLite's \
         create-copy-drop-rename table rebuild have no representation in SeaQuery's schema builder. \
         Migrations run once at startup, before the listener binds, and interpolate no caller-supplied \
         value — every substitution across the directory is a compile-time `const` or a column name \
         from a fixed array.",
    ),
];

/// Walks `src/`, returning every `.rs` file's repo-relative path and contents.
fn source_files() -> Vec<(String, String)> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).expect("src/ is readable") {
            let path = entry.expect("directory entry is readable").path();
            if path.is_dir() {
                walk(&path, root, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let relative = path
                    .strip_prefix(root)
                    .expect("every walked path is under the repo root")
                    .to_string_lossy()
                    .replace('\\', "/");
                let contents = std::fs::read_to_string(&path).expect("a source file is readable");
                out.push((relative, contents));
            }
        }
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    walk(&root.join("src"), root, &mut out);
    assert!(!out.is_empty(), "the walk found no source files — the path is wrong");
    out
}

/// Whether `relative` is covered by an [`ALLOWED`] entry. A trailing `/` matches a whole directory.
fn is_allowed(relative: &str) -> bool {
    ALLOWED.iter().any(|(allowed, _)| {
        if let Some(dir) = allowed.strip_suffix('/') {
            relative.starts_with(dir)
        } else {
            relative == *allowed
        }
    })
}

/// True for a line that is a comment rather than code. Naming a construct is not using one.
fn is_comment(line: &str) -> bool {
    let code = line.trim_start();
    code.starts_with("//") || code.starts_with('*') || code.starts_with("/*")
}

/// **No hand-written SQL reaches the database from any query path in `src/`.**
///
/// Typed SeaORM is not a style preference. A hand-built statement is a place where a filter can be
/// forgotten — `WHERE owner_key_id = …` omitted is a tenancy breach that compiles — and where a
/// value can be interpolated instead of bound. The entity API makes the first a type error and the
/// second impossible, so the rule worth enforcing is not "write good SQL" but "do not write SQL".
#[test]
fn no_raw_sql_outside_the_documented_exceptions() {
    let mut violations = Vec::new();

    for (relative, contents) in source_files() {
        if is_allowed(&relative) {
            continue;
        }
        for (number, line) in contents.lines().enumerate() {
            if is_comment(line) {
                continue;
            }
            for marker in RAW_SQL_MARKERS {
                if line.contains(marker) {
                    violations.push(format!("{relative}:{}  uses {marker}", number + 1));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "raw SQL found outside the documented exceptions:\n  {}\n\nUse SeaORM entities or \
         expression builders. If this is genuinely unavoidable — DDL the schema builder cannot \
         express, or a connection pragma — add it to ALLOWED with the reason and record it in \
         AGENT_NOTES.MD. It must not be reachable from a request.",
        violations.join("\n  ")
    );
}

/// **No DML keyword is hand-written outside the exemptions.**
///
/// The marker scan above catches the SeaORM constructs that carry raw SQL. This catches the string
/// itself, which is the part that actually touches data — a future helper with a different name, a
/// `format!`-assembled statement passed to something not on the marker list, or a query built
/// through a driver the marker list does not know about.
#[test]
fn no_dml_keyword_is_hand_written_outside_the_exceptions() {
    let mut violations = Vec::new();

    for (relative, contents) in source_files() {
        if is_allowed(&relative) {
            continue;
        }
        for (number, line) in contents.lines().enumerate() {
            if is_comment(line) {
                continue;
            }
            // Only inside a string literal: `.select_only()` is not SQL, and neither is a variable
            // named `delete_target`.
            let Some(open) = line.find('"') else { continue };
            let literal = line[open..].to_uppercase();
            for (keyword, follower) in DML_SHAPES {
                // Both halves, in order — see `DML_SHAPES` for why the pair and not the keyword.
                // Searched from the keyword's own start, not past it: `DELETE ` already consumed
                // the space that ` FROM ` needs, so slicing past the keyword makes `DELETE FROM`
                // unmatchable — which the meta-test below caught.
                let Some(at) = literal.find(keyword) else { continue };
                if literal[at..].contains(follower) {
                    violations.push(format!(
                        "{relative}:{}  string literal contains `{}{}`",
                        number + 1,
                        keyword.trim_end(),
                        follower.trim_end()
                    ));
                    break;
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "hand-written DML found outside the documented exceptions:\n  {}",
        violations.join("\n  ")
    );
}

/// **No request handler is ever exempted**, whatever the allowlist says.
///
/// This is the invariant the allowlist is a proxy for. An exemption in `src/api/` sits on a path a
/// caller can reach, which is the one place the injection risk is real — and the peer had exactly
/// that briefly, for a literal `SELECT 1` in an *unauthenticated* readiness probe, the worst possible
/// location for one. Encoded as a test so the rule survives a future edit to `ALLOWED` made by
/// someone who has not read the comment above it.
#[test]
fn no_handler_is_ever_exempted() {
    for (allowed, _) in ALLOWED {
        assert!(
            !allowed.starts_with("src/api/"),
            "{allowed} is a request-reachable module and must never hold a raw-SQL exemption. \
             Move the statement into a migration, or express it through SeaORM."
        );
    }
}

/// The allowlist must not outlive its justification.
///
/// An entry naming a path that no longer exists, or that no longer contains raw SQL, is an exemption
/// nobody is checking — and the next file to land there inherits it silently.
#[test]
fn every_allowlisted_exception_still_exists_and_is_still_needed() {
    let files = source_files();
    for (relative, reason) in ALLOWED {
        let bare = relative.trim_end_matches('/');
        assert!(repo_path(bare).exists(), "allowlisted path {relative} no longer exists — drop it");

        let still_needed = files
            .iter()
            .filter(|(p, _)| p.starts_with(bare))
            .any(|(_, contents)| RAW_SQL_MARKERS.iter().any(|m| contents.contains(m)));

        assert!(
            still_needed,
            "{relative} is allowlisted for raw SQL but no longer contains any — drop the entry \
             rather than leaving a standing exemption. Recorded reason: {reason}"
        );
    }
}

/// The scanner has to be able to see a violation, or every test above proves nothing.
///
/// This is the check the two broken shell versions of this gate did not have. Both reported CLEAN
/// against a deliberately planted violation, and both were believed to be working.
#[test]
fn the_raw_sql_scanner_detects_what_it_is_looking_for() {
    let marker_hit =
        |line: &str| !is_comment(line) && RAW_SQL_MARKERS.iter().any(|m| line.contains(m));
    let dml_hit = |line: &str| {
        if is_comment(line) {
            return false;
        }
        line.find('"').is_some_and(|open| {
            let literal = line[open..].to_uppercase();
            DML_SHAPES.iter().any(|(keyword, follower)| {
                literal.find(keyword).is_some_and(|at| literal[at..].contains(follower))
            })
        })
    };

    assert!(
        marker_hit(r#"    db.execute_unprepared("DROP TABLE api_keys").await?;"#),
        "the marker scanner missed a real call"
    );
    assert!(
        !marker_hit(r#"    // execute_unprepared is documented here, not called"#),
        "the marker scanner flagged prose describing a call"
    );

    assert!(
        dml_hit(r#"    let sql = format!("DELETE FROM api_keys WHERE id = {id}");"#),
        "the DML scanner missed a hand-built statement"
    );
    assert!(
        !dml_hit(r#"    // DELETE FROM is mentioned in this comment"#),
        "the DML scanner flagged a comment"
    );
    // The false positives that sank the first version of this check. Each is real code in `src/`.
    for prose in [
        r#"    return Err(AppError::Forbidden("Cannot delete yourself".to_owned()));"#,
        r#"        "you have no delete access to any group holding this record".to_owned(),"#,
        r#"        "can_write or can_delete require can_read to be true".to_owned(),"#,
        r#"        "Only a master key can permanently delete an IP record".to_owned(),"#,
        r#"    let msg = "Deleted the group";"#,
    ] {
        assert!(!dml_hit(prose), "the DML scanner flagged prose: {prose}");
    }

    // And it still catches a statement written in lowercase.
    assert!(
        dml_hit(r#"    let sql = "update api_keys set is_master = 1";"#),
        "the DML scanner missed a lowercase statement"
    );
}
