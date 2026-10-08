//! Guardrails module: Inspects AI-generated payload source code to protect
//! the operator's machine from unintended backdoors, malicious build scripts,
//! or self-targeting loops, and verifies structural code completeness.

use colored::Colorize;
use regex::Regex;
use std::sync::LazyLock;

static LOCALHOST_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"127\.0\.0\.1").unwrap(),
        Regex::new(r"::1\b").unwrap(),
        Regex::new(r"\blocalhost\b").unwrap(),
        Regex::new(r"\b0\.0\.0\.0\b").unwrap(),
    ]
});

static DESTRUCTIVE_PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        (Regex::new(r"rm\s+-rf\s+/").unwrap(), "System wipe command (rm -rf /)"),
        (Regex::new(r"del\s+/f\s+/s\s+/q\s+C:\\").unwrap(), "System wipe command (del C:\\)"),
        (Regex::new(r"format\s+[A-Z]:").unwrap(), "Disk format invocation"),
        (Regex::new(r":\(\)\{\s*:\|:&\s*\};:").unwrap(), "Fork bomb detected"),
    ]
});

static REMOTE_DL_PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        (Regex::new(r"curl\s+-[sS]?[kK]?[oO]?\s+https?://").unwrap(), "External curl download"),
        (Regex::new(r"wget\s+https?://").unwrap(), "External wget download"),
        (Regex::new(r"DownloadFile\(").unwrap(), "WebClient DownloadFile call"),
        (Regex::new(r"DownloadString\(").unwrap(), "WebClient DownloadString call"),
    ]
});

pub struct GuardrailReport {
    pub is_safe: bool,
    pub is_complete: bool,
    pub warnings: Vec<String>,
}

pub struct GuardrailChecker;

impl GuardrailChecker {
    pub fn inspect(code: &str, lang_ext: &str) -> GuardrailReport {
        let mut warnings = Vec::new();

        // 1. Check for localhost/127.0.0.1 hardcoded connections that could target the operator
        for re in LOCALHOST_PATTERNS.iter() {
            if re.is_match(code) {
                warnings.push(format!(
                    "CRITICAL: Payload contains local loopback reference: '{}'. Could target operator host!",
                    re.as_str()
                ));
            }
        }

        // 2. Check for dangerous destructive host commands embedded in strings
        for (re, desc) in DESTRUCTIVE_PATTERNS.iter() {
            if re.is_match(code) {
                warnings.push(format!("CRITICAL: Malicious destructive pattern found: {}", desc));
            }
        }

        // 3. Check for external remote dropper URLs (preventing untrusted secondary payload downloads)
        for (re, desc) in REMOTE_DL_PATTERNS.iter() {
            if re.is_match(code) {
                warnings.push(format!("Suspicious remote dropper code detected: {}", desc));
            }
        }

        // 4. Structural Syntax & Completeness Verification
        let open_braces = code.chars().filter(|&c| c == '{').count();
        let close_braces = code.chars().filter(|&c| c == '}').count();
        let is_brace_balanced = open_braces == close_braces;

        if !is_brace_balanced {
            warnings.push(format!(
                "STRUCTURAL WARNING: Mismatched curly braces detected ({} open vs {} closed). Code may have been truncated by token limits.",
                open_braces, close_braces
            ));
        }

        // Check for required main entrypoint
        let has_entrypoint = match lang_ext {
            "rs" => code.contains("fn main"),
            "cpp" => code.contains("main(") || code.contains("WinMain"),
            "cs" => code.contains("Main("),
            _ => true,
        };

        if !has_entrypoint {
            warnings.push(format!(
                "STRUCTURAL WARNING: No standard entrypoint found for target language '{}'. Compilation will likely fail.",
                lang_ext
            ));
        }

        let is_safe = !warnings.iter().any(|w| w.starts_with("CRITICAL:"));
        let is_complete = is_brace_balanced && has_entrypoint;

        GuardrailReport {
            is_safe,
            is_complete,
            warnings,
        }
    }

    pub fn print_report(report: &GuardrailReport) {
        if report.warnings.is_empty() {
            println!("{} Code passed all operator safety and completeness checks.", "[✓]".green().bold());
        } else {
            for warn in &report.warnings {
                if warn.starts_with("CRITICAL:") {
                    eprintln!("{} {}", "[!]".red().bold(), warn.red().bold());
                } else if warn.starts_with("STRUCTURAL WARNING:") {
                    eprintln!("{} {}", "[!]".yellow().bold(), warn.yellow().bold());
                } else {
                    println!("{} {}", "[?]".yellow().bold(), warn.yellow());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_code() {
        let code = r#"
            // Clean reverse shell
            fn main() {
                println!("Connecting to {{DOOM_LHOST}}:{{DOOM_LPORT}}");
            }
        "#;
        let report = GuardrailChecker::inspect(code, "rs");
        assert!(report.is_safe);
        assert!(report.is_complete);
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn test_flag_destructive() {
        let code = r#"
            system("rm -rf /");
        "#;
        let report = GuardrailChecker::inspect(code, "cpp");
        assert!(!report.is_safe);
    }

    #[test]
    fn test_flag_loopback() {
        let code = r#"
            connect("127.0.0.1", 4444);
        "#;
        let report = GuardrailChecker::inspect(code, "cpp");
        assert!(!report.is_safe);
    }

    #[test]
    fn test_flag_truncated() {
        let truncated_code = r#"
            fn main() {
                let x = 42;
                // AI cut off here...
        "#;
        let report = GuardrailChecker::inspect(truncated_code, "rs");
        assert!(!report.is_complete);
        assert!(report.warnings.iter().any(|w| w.contains("Mismatched curly braces")));
    }
}
