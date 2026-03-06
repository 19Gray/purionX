use anyhow::Result;
use std::path::Path;
use walkdir::WalkDir;

use crate::finding::{Finding, ScanResult, Severity};
use crate::rules::{a01, a02, a03, a04};

const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    "dist",
];

const SUPPORTED_EXT: &[&str] = &[
    "rs", "py", "go", "js", "ts", "java", "kt", "toml", "yaml", "yml", "json", "env", "cfg", "ini",
    "conf", "txt",
];

const SUPPORTED_NAMES: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "requirements.txt",
    "Pipfile",
    "package.json",
    "go.mod",
    ".env",
];

// ─────────────────────────────────────────────
//  Public API
// ─────────────────────────────────────────────

pub fn scan_target(target: &str, min_severity: &Severity) -> Result<ScanResult> {
    let mut result = ScanResult::new(target);
    let path = Path::new(target);

    if path.is_file() {
        result.findings.extend(scan_file(target));
    } else if path.is_dir() {
        for entry in WalkDir::new(target)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| !SKIP_DIRS.contains(&e.file_name().to_str().unwrap_or("")))
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let fp = entry.path().to_string_lossy().to_string();
                result.findings.extend(scan_file(&fp));
            }
        }
    } else {
        anyhow::bail!("Target not found: {}", target);
    }

    // Assign sequential IDs
    for (idx, f) in result.findings.iter_mut().enumerate() {
        f.id = idx + 1;
    }

    // Filter by minimum severity
    result.findings.retain(|f| f.severity >= *min_severity);

    Ok(result)
}

// ─────────────────────────────────────────────
//  Internal helpers
// ─────────────────────────────────────────────

fn should_scan(filepath: &str) -> bool {
    let path = Path::new(filepath);
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if SUPPORTED_NAMES.contains(&name) {
            return true;
        }
    }
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        return SUPPORTED_EXT.contains(&ext);
    }
    false
}

fn scan_file(filepath: &str) -> Vec<Finding> {
    if !should_scan(filepath) {
        return vec![];
    }

    let content = match std::fs::read_to_string(filepath) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let is_rust = Path::new(filepath)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e == "rs")
        .unwrap_or(false);

    // Keep raw lines so we can show the real source in reports
    let raw_lines: Vec<(usize, String)> = content
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.to_owned()))
        .collect();

    // For Rust files, blank out string literals and line comments before
    // matching. This stops the scanner from flagging its own rule strings
    // (e.g. a title field that mentions "MD5" or "DES").
    let scan_lines: Vec<(usize, String)> = if is_rust {
        raw_lines
            .iter()
            .map(|(n, l)| (*n, sanitise_rust_line(l)))
            .collect()
    } else {
        raw_lines.clone()
    };

    let scan_refs: Vec<(usize, &str)> = scan_lines.iter().map(|(n, l)| (*n, l.as_str())).collect();

    let mut findings = Vec::new();
    findings.extend(a01::scan(filepath, &scan_refs));
    findings.extend(a02::scan(filepath, &scan_refs));
    findings.extend(a03::scan(filepath, &scan_refs));
    findings.extend(a04::scan(filepath, &scan_refs));

    // Restore original snippet text for display
    for f in &mut findings {
        if let Some((_, raw)) = raw_lines.iter().find(|(n, _)| *n == f.line) {
            f.snippet = raw.trim().to_owned();
        }
    }

    findings
}

// ─────────────────────────────────────────────
//  Rust source sanitiser
// ─────────────────────────────────────────────

/// Blanks out the *content* of Rust string literals and strips line comments,
/// so patterns defined inside title/recommendation/Regex fields are never
/// matched as real vulnerabilities.
///
/// Handles: normal strings "...", escape sequences \n etc,
///          raw strings r"..." r#"..."# r##"..."##, and // comments.
fn sanitise_rust_line(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    let mut in_str = false;

    while let Some(ch) = chars.next() {
        if in_str {
            match ch {
                '\\' => {
                    out.push(' ');
                    if chars.next().is_some() {
                        out.push(' ');
                    }
                }
                '"' => {
                    in_str = false;
                    out.push('"');
                }
                _ => out.push(' '),
            }
        } else {
            match ch {
                // Line comment — drop the rest of the line
                '/' if chars.peek() == Some(&'/') => break,

                // Raw string: r"..." or r##"..."##
                'r' if matches!(chars.peek(), Some(&'"') | Some(&'#')) => {
                    out.push('r');
                    let mut hashes = 0usize;
                    while chars.peek() == Some(&'#') {
                        chars.next();
                        hashes += 1;
                        out.push('#');
                    }
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        out.push('"');
                        // Consume raw body until closing `"` + correct number of `#`
                        'raw: loop {
                            match chars.next() {
                                None => break,
                                Some('"') => {
                                    let mut n = 0usize;
                                    while n < hashes && chars.peek() == Some(&'#') {
                                        chars.next();
                                        n += 1;
                                    }
                                    if n == hashes {
                                        out.push('"');
                                        for _ in 0..hashes {
                                            out.push('#');
                                        }
                                        break 'raw;
                                    }
                                    // quote was inside the raw string — keep going
                                }
                                Some(_) => {} // body character — swallow
                            }
                        }
                    }
                }

                // Normal string
                '"' => {
                    in_str = true;
                    out.push('"');
                }

                other => out.push(other),
            }
        }
    }
    out
}
