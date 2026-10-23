//! Guardrails module: Inspects AI-generated payload source code to protect
//! the operator's machine from unintended backdoors, malicious build scripts,
//! or self-targeting loops, and verifies structural code completeness.

use colored::Colorize;
use regex::Regex;
use std::collections::VecDeque;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

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

/// Sliding window rate limiter and token safety budget tracker.
/// Prevents runaway prompt loops, denial-of-wallet, or rate limit exhaustion
/// during automated batch payload generation.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SafetyBudgetTracker {
    window_duration: Duration,
    max_requests: usize,
    max_tokens: usize,
    request_log: VecDeque<Instant>,
    token_log: VecDeque<(Instant, usize)>,
}

#[allow(dead_code)]
impl SafetyBudgetTracker {
    pub fn new(window_duration: Duration, max_requests: usize, max_tokens: usize) -> Self {
        Self {
            window_duration,
            max_requests,
            max_tokens,
            request_log: VecDeque::new(),
            token_log: VecDeque::new(),
        }
    }

    /// Prune entries older than the current sliding window.
    fn prune(&mut self, now: Instant) {
        let cutoff = now.checked_sub(self.window_duration).unwrap_or(now);
        while let Some(&ts) = self.request_log.front() {
            if ts < cutoff {
                self.request_log.pop_front();
            } else {
                break;
            }
        }
        while let Some(&(ts, _)) = self.token_log.front() {
            if ts < cutoff {
                self.token_log.pop_front();
            } else {
                break;
            }
        }
    }

    /// Returns the total tokens consumed within the current sliding window.
    pub fn current_tokens(&mut self, now: Instant) -> usize {
        self.prune(now);
        self.token_log.iter().map(|(_, tokens)| *tokens).sum()
    }

    /// Returns current active request count within the sliding window.
    pub fn current_requests(&mut self, now: Instant) -> usize {
        self.prune(now);
        self.request_log.len()
    }

    /// Check if a request consuming `estimated_tokens` is allowed under current budget.
    pub fn check_budget(&mut self, estimated_tokens: usize, now: Instant) -> Result<(), String> {
        self.prune(now);

        if self.request_log.len() >= self.max_requests {
            return Err(format!(
                "Rate limit exceeded: {} requests recorded in sliding window (max {})",
                self.request_log.len(),
                self.max_requests
            ));
        }

        let total_tokens: usize = self.token_log.iter().map(|(_, t)| *t).sum();
        if total_tokens.saturating_add(estimated_tokens) > self.max_tokens {
            return Err(format!(
                "Token budget exceeded: current {} + incoming {} exceeds maximum {}",
                total_tokens, estimated_tokens, self.max_tokens
            ));
        }

        Ok(())
    }

    /// Record a completed request and its consumed token count.
    pub fn record_usage(&mut self, tokens: usize, now: Instant) {
        self.prune(now);
        self.request_log.push_back(now);
        self.token_log.push_back((now, tokens));
    }

    /// Convenience helper checking budget at the current timestamp.
    pub fn check_budget_now(&mut self, estimated_tokens: usize) -> Result<(), String> {
        self.check_budget(estimated_tokens, Instant::now())
    }

    /// Convenience helper recording usage at the current timestamp.
    pub fn record_usage_now(&mut self, tokens: usize) {
        self.record_usage(tokens, Instant::now());
    }

    /// Reset tracker state.
    pub fn reset(&mut self) {
        self.request_log.clear();
        self.token_log.clear();
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

    #[test]
    fn test_budget_tracker_sliding_window() {
        let mut tracker = SafetyBudgetTracker::new(Duration::from_secs(60), 3, 1000);
        let t0 = Instant::now();

        assert!(tracker.check_budget(200, t0).is_ok());
        tracker.record_usage(200, t0);

        assert!(tracker.check_budget(300, t0 + Duration::from_secs(10)).is_ok());
        tracker.record_usage(300, t0 + Duration::from_secs(10));

        assert_eq!(tracker.current_requests(t0 + Duration::from_secs(20)), 2);
        assert_eq!(tracker.current_tokens(t0 + Duration::from_secs(20)), 500);

        // Third request: 400 tokens -> total 900 <= 1000, 3 requests <= 3
        assert!(tracker.check_budget(400, t0 + Duration::from_secs(20)).is_ok());
        tracker.record_usage(400, t0 + Duration::from_secs(20));

        // 4th request exceeds max_requests (3)
        assert!(tracker.check_budget(50, t0 + Duration::from_secs(25)).is_err());

        // Fast forward beyond the 60s window for t0 (t0 is at 0, t1 at 65s)
        let t1 = t0 + Duration::from_secs(65);
        // t0 pruned (200 tokens pruned), only t0+10 and t0+20 remain (2 requests, 700 tokens)
        assert_eq!(tracker.current_requests(t1), 2);
        assert_eq!(tracker.current_tokens(t1), 700);
        assert!(tracker.check_budget(200, t1).is_ok());

        // But 400 tokens would exceed (700 + 400 = 1100 > 1000)
        assert!(tracker.check_budget(400, t1).is_err());
    }

    #[test]
    fn test_budget_tracker_reset() {
        let mut tracker = SafetyBudgetTracker::new(Duration::from_secs(30), 2, 500);
        let t0 = Instant::now();
        tracker.record_usage(400, t0);
        assert_eq!(tracker.current_tokens(t0), 400);

        tracker.reset();
        assert_eq!(tracker.current_tokens(t0), 0);
        assert_eq!(tracker.current_requests(t0), 0);

        assert!(tracker.check_budget_now(100).is_ok());
        tracker.record_usage_now(100);
        assert_eq!(tracker.current_requests(Instant::now()), 1);
    }
}
