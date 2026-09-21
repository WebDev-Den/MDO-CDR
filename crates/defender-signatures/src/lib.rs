//! Signature scanning for the defender pipeline.
//!
//! The scanner is the **second line of defense** after CDR. CDR rebuilds the
//! artifact, so well-known malware patterns usually do not survive. Signature
//! scanning catches:
//!   - canary strings that MUST survive (EICAR — used to verify the scanner
//!     is wired up),
//!   - byte patterns that should NEVER appear inside media artifacts
//!     (executable headers, shell shebangs),
//!   - user-supplied indicators of compromise.
//!
//! Matching uses the Aho–Corasick algorithm so a single pass over the buffer
//! checks every pattern. Each rule carries a `SignatureLocation` constraint
//! so a pattern that only matters at the start of the file (e.g. an ELF
//! magic) is not reported when it happens to occur mid-stream inside a
//! legitimate payload.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

/// Where inside the buffer a signature pattern is allowed to match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureLocation {
    /// Pattern matches anywhere in the buffer.
    Anywhere,
    /// Pattern only matches if it begins within the first N bytes.
    FirstBytes(u64),
    /// Pattern only matches if it begins within the last N bytes.
    LastBytes(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureRule {
    pub name: String,
    pub pattern: Vec<u8>,
    pub location: SignatureLocation,
}

impl SignatureRule {
    pub fn anywhere(name: impl Into<String>, pattern: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            pattern: pattern.into(),
            location: SignatureLocation::Anywhere,
        }
    }

    pub fn first_bytes(name: impl Into<String>, pattern: impl Into<Vec<u8>>, limit: u64) -> Self {
        Self {
            name: name.into(),
            pattern: pattern.into(),
            location: SignatureLocation::FirstBytes(limit),
        }
    }

    pub fn last_bytes(name: impl Into<String>, pattern: impl Into<Vec<u8>>, limit: u64) -> Self {
        Self {
            name: name.into(),
            pattern: pattern.into(),
            location: SignatureLocation::LastBytes(limit),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureHit {
    pub rule_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineEnvelope {
    pub reason: String,
    pub sha256: String,
    pub original_size: u64,
    pub output_size: u64,
    pub stage_details: Vec<String>,
}

/// Stateful multi-pattern scanner built once from a list of rules.
///
/// Cloning is cheap — the underlying Aho–Corasick automaton is shared via
/// an internal `Arc` inside the `aho_corasick` crate.
#[derive(Debug, Clone)]
pub struct SignatureEngine {
    automaton: Option<AhoCorasick>,
    rules: Vec<SignatureRule>,
}

impl SignatureEngine {
    /// Build an engine from user-supplied rules only (no baseline).
    pub fn from_rules(rules: Vec<SignatureRule>) -> Self {
        Self::build(rules)
    }

    /// Build an engine that merges the hardcoded baseline rules with
    /// user-supplied rules. Baseline rules always come first and cannot be
    /// disabled by the user.
    pub fn with_baseline(user_rules: Vec<SignatureRule>) -> Self {
        let mut rules = baseline_rules();
        rules.extend(user_rules);
        Self::build(rules)
    }

    fn build(rules: Vec<SignatureRule>) -> Self {
        let non_empty: Vec<&SignatureRule> = rules
            .iter()
            .filter(|value| !value.pattern.is_empty())
            .collect();
        if non_empty.is_empty() {
            return Self {
                automaton: None,
                rules,
            };
        }
        let patterns: Vec<&[u8]> = non_empty
            .iter()
            .map(|value| value.pattern.as_slice())
            .collect();
        let built = AhoCorasickBuilder::new()
            .match_kind(MatchKind::Standard)
            .ascii_case_insensitive(false)
            .build(&patterns)
            .ok();
        Self {
            automaton: built,
            rules,
        }
    }

    pub fn scan(&self, input: &[u8]) -> Vec<SignatureHit> {
        let Some(automaton) = self.automaton.as_ref() else {
            return Vec::new();
        };
        // Map the dense pattern index (the one Aho–Corasick knows about)
        // back to the original rule index so we can report location-aware
        // hits. Rules with an empty pattern were skipped at build time.
        let mut rule_index_for_pattern = Vec::with_capacity(self.rules.len());
        for (index, rule) in self.rules.iter().enumerate() {
            if !rule.pattern.is_empty() {
                rule_index_for_pattern.push(index);
            }
        }

        let input_len = input.len() as u64;
        let mut hits = Vec::new();
        let mut seen = vec![false; self.rules.len()];
        for mat in automaton.find_overlapping_iter(input) {
            let pattern_index = mat.pattern().as_usize();
            let Some(&rule_index) = rule_index_for_pattern.get(pattern_index) else {
                continue;
            };
            if seen[rule_index] {
                continue;
            }
            let rule = &self.rules[rule_index];
            let match_start = mat.start() as u64;
            if !is_location_allowed(
                &rule.location,
                match_start,
                input_len,
                rule.pattern.len() as u64,
            ) {
                continue;
            }
            seen[rule_index] = true;
            hits.push(SignatureHit {
                rule_name: rule.name.clone(),
            });
        }
        hits
    }
}

impl Default for SignatureEngine {
    fn default() -> Self {
        Self::with_baseline(Vec::new())
    }
}

fn is_location_allowed(
    location: &SignatureLocation,
    match_start: u64,
    input_len: u64,
    pattern_len: u64,
) -> bool {
    match location {
        SignatureLocation::Anywhere => true,
        SignatureLocation::FirstBytes(limit) => match_start < *limit,
        SignatureLocation::LastBytes(limit) => {
            let match_end = match_start.saturating_add(pattern_len);
            let window_start = input_len.saturating_sub(*limit);
            match_end > window_start
        }
    }
}

/// Hardcoded rules that always run, regardless of user configuration.
///
/// These are byte patterns that should never legitimately appear inside a
/// rebuilt media artifact. If one DOES appear post-CDR, either the rebuild
/// left something it should not have or the policy accepted a file type
/// that bypasses rebuild (e.g. the "Other" kind passthrough).
pub fn baseline_rules() -> Vec<SignatureRule> {
    vec![
        // EICAR antivirus test string. Not malicious itself — used to verify
        // the scanner is wired up in each environment.
        SignatureRule::anywhere(
            "eicar_test_string",
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".to_vec(),
        ),
        // Windows PE executable header. A media artifact should never
        // contain `MZ` followed by the DOS stub and `PE\0\0`.
        SignatureRule::first_bytes("pe_dos_header", b"MZ".to_vec(), 2),
        SignatureRule::anywhere("pe_signature", b"PE\0\0".to_vec()),
        // ELF magic — Linux executable.
        SignatureRule::first_bytes("elf_magic", b"\x7fELF".to_vec(), 4),
        // Mach-O 32-bit and 64-bit magics (both endians).
        SignatureRule::first_bytes("macho_magic_32_be", b"\xFE\xED\xFA\xCE".to_vec(), 4),
        SignatureRule::first_bytes("macho_magic_32_le", b"\xCE\xFA\xED\xFE".to_vec(), 4),
        SignatureRule::first_bytes("macho_magic_64_be", b"\xFE\xED\xFA\xCF".to_vec(), 4),
        SignatureRule::first_bytes("macho_magic_64_le", b"\xCF\xFA\xED\xFE".to_vec(), 4),
        // Shell script shebangs — reject if a media artifact tries to
        // masquerade as a POSIX script.
        SignatureRule::first_bytes("sh_shebang", b"#!/bin/sh".to_vec(), 16),
        SignatureRule::first_bytes("bash_shebang", b"#!/bin/bash".to_vec(), 16),
        SignatureRule::first_bytes("env_shebang", b"#!/usr/bin/env".to_vec(), 16),
        // Additional script interpreter shebangs. A media artifact should
        // never start with an interpreter directive.
        SignatureRule::first_bytes("python_shebang", b"#!/usr/bin/python".to_vec(), 24),
        SignatureRule::first_bytes("perl_shebang", b"#!/usr/bin/perl".to_vec(), 20),
        SignatureRule::first_bytes("ruby_shebang", b"#!/usr/bin/ruby".to_vec(), 20),
        SignatureRule::first_bytes("node_shebang", b"#!/usr/bin/node".to_vec(), 20),
        SignatureRule::first_bytes("php_shebang", b"<?php".to_vec(), 8),
        // Java class file magic — compiled bytecode.
        SignatureRule::first_bytes("java_class_magic", b"\xCA\xFE\xBA\xBE".to_vec(), 4),
        // OLE/CFB (Compound File Binary) — used by legacy Office formats
        // (DOC, XLS, PPT). These containers frequently carry macros and
        // should never appear inside a media artifact.
        SignatureRule::first_bytes(
            "ole_cfb_magic",
            b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1".to_vec(),
            8,
        ),
        // DEX (Dalvik Executable) — Android bytecode.
        SignatureRule::first_bytes("dex_magic", b"dex\n".to_vec(), 4),
        // Windows batch file common opening commands — text-based, no fixed
        // magic, but these tokens at the very start are a strong indicator.
        SignatureRule::first_bytes("batch_echo_off", b"@echo off".to_vec(), 12),
        // WebAssembly binary module magic.
        SignatureRule::first_bytes("wasm_magic", b"\x00asm".to_vec(), 4),
        // RAR archive magic — not a media artifact, potential polyglot
        // carrier.
        SignatureRule::first_bytes("rar_magic", b"Rar!\x1a\x07".to_vec(), 8),
        // 7z archive magic.
        SignatureRule::first_bytes("seven_zip_magic", b"7z\xBC\xAF\x27\x1C".to_vec(), 8),
    ]
}

/// Backwards-compatible linear substring search. Still used by
/// non-performance-critical callers in the main crate for ad-hoc probes
/// (e.g. PDF footer detection). New code should prefer the engine.
pub fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    if needle.is_empty() {
        return true;
    }
    let end = haystack.len() - needle.len();
    for offset in 0..=end {
        let window = &haystack[offset..offset + needle.len()];
        if window == needle {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{SignatureEngine, SignatureRule};

    #[test]
    fn finds_matching_rule() {
        let engine =
            SignatureEngine::from_rules(vec![SignatureRule::anywhere("x", b"ABC".to_vec())]);
        let hits = engine.scan(b"zzABCzz");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_name, "x");
    }

    #[test]
    fn empty_rules_returns_no_hits() {
        let engine = SignatureEngine::from_rules(Vec::new());
        let hits = engine.scan(b"anything");
        assert!(hits.is_empty());
    }

    #[test]
    fn first_bytes_matches_within_window() {
        let engine = SignatureEngine::from_rules(vec![SignatureRule::first_bytes(
            "magic",
            b"MZ".to_vec(),
            4,
        )]);
        assert_eq!(engine.scan(b"MZfoo").len(), 1);
    }

    #[test]
    fn first_bytes_rejects_outside_window() {
        let engine = SignatureEngine::from_rules(vec![SignatureRule::first_bytes(
            "magic",
            b"MZ".to_vec(),
            4,
        )]);
        // "MZ" starts at offset 8 which is outside the first-4-bytes window.
        assert!(engine.scan(b"........MZfoo").is_empty());
    }

    #[test]
    fn last_bytes_matches_tail() {
        let engine = SignatureEngine::from_rules(vec![SignatureRule::last_bytes(
            "eof",
            b"%%EOF".to_vec(),
            8,
        )]);
        let mut buf = vec![0u8; 100];
        buf.extend_from_slice(b"%%EOF");
        assert_eq!(engine.scan(&buf).len(), 1);
    }

    #[test]
    fn last_bytes_rejects_head() {
        let engine = SignatureEngine::from_rules(vec![SignatureRule::last_bytes(
            "eof",
            b"%%EOF".to_vec(),
            8,
        )]);
        let mut buf = b"%%EOF".to_vec();
        buf.extend_from_slice(&vec![0u8; 1000]);
        // Match is at the start; the last-8-bytes window is far away.
        assert!(engine.scan(&buf).is_empty());
    }

    #[test]
    fn each_rule_reports_at_most_once() {
        let engine =
            SignatureEngine::from_rules(vec![SignatureRule::anywhere("x", b"AB".to_vec())]);
        let hits = engine.scan(b"ABABABAB");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn baseline_catches_eicar() {
        let engine = SignatureEngine::with_baseline(Vec::new());
        let payload = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let hits = engine.scan(payload);
        let names: Vec<_> = hits.iter().map(|value| value.rule_name.as_str()).collect();
        assert!(names.contains(&"eicar_test_string"));
    }

    #[test]
    fn baseline_catches_pe_but_only_at_start() {
        let engine = SignatureEngine::with_baseline(Vec::new());
        // MZ at offset 0 matches pe_dos_header (first_bytes 2).
        assert!(
            engine
                .scan(b"MZ\x90\x00")
                .iter()
                .any(|value| value.rule_name == "pe_dos_header")
        );
        // MZ embedded deep inside does not match pe_dos_header.
        let mut buf = vec![0u8; 100];
        buf.extend_from_slice(b"MZstuff");
        assert!(
            !engine
                .scan(&buf)
                .iter()
                .any(|value| value.rule_name == "pe_dos_header")
        );
    }
}
