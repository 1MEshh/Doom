//! Doom: AI-Powered Polymorphic EDR/AV Evasion Payload Generator
//! Built for red teams and professional penetration testers.

mod ai;
mod guardrails;
mod prompt;
mod sanitizer;

use ai::cloud::{CloudEngine, CloudProvider};
use ai::ollama::OllamaEngine;
use ai::AiEngine;
use clap::Parser;
use colored::Colorize;
use guardrails::GuardrailChecker;
use inquire::{Confirm, MultiSelect, Select, Text};
use prompt::{EvasionProfile, PromptBuilder, TargetLanguage};
use sanitizer::{TokenScrubber, TriggerWordSanitizer};
use std::error::Error;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(name = "doom")]
#[command(version = "0.1.0")]
#[command(about = "Polymorphic EDR/AV Evasion Payload Generator", long_about = None)]
struct CliArgs {
    /// Non-interactive batch mode: skip interactive wizard
    #[arg(short, long)]
    batch: bool,

    /// Target language (rust, cpp, csharp)
    #[arg(short, long, default_value = "rust")]
    lang: String,

    /// AI Engine in batch mode (ollama, deepseek, openai)
    #[arg(short, long, default_value = "ollama")]
    engine: String,

    /// LHOST listener IP or hostname
    #[arg(long, default_value = "10.10.14.50")]
    lhost: String,

    /// LPORT listener port (1-65535)
    #[arg(long, default_value = "4444")]
    lport: String,

    /// SOCKS5 or HTTP proxy URL (e.g. socks5://127.0.0.1:9050 for Tor)
    #[arg(short, long)]
    proxy: Option<String>,

    /// Output destination file
    #[arg(short, long)]
    output: Option<String>,
}

fn print_banner() {
    let banner = r#"
    ██████╗  ██████╗  ██████╗ ███╗   ███╗
    ██╔══██╗██╔═══██╗██╔═══██╗████╗ ████║
    ██║  ██║██║   ██║██║   ██║██╔████╔██║
    ██║  ██║██║   ██║██║   ██║██║╚██╔╝██║
    ██████╔╝╚██████╔╝╚██████╔╝██║ ╚═╝ ██║
    ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝
    "#;
    println!("{}", banner.red().bold());
    println!(
        "{} {}",
        ":: Doom - Polymorphic EDR Evasion Generator ::".bright_white().bold(),
        "v0.1.0 [Hardened]".dimmed()
    );
    println!(
        "{}\n",
        "Confidentiality & OPSEC: Tor/SOCKS5 Proxy Ready | Client Data Tokenized | Anti-Flagging Active".cyan()
    );
}

/// Validate listener host (IP address or valid FQDN)
fn validate_lhost(input: &str) -> Result<(), String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("LHOST cannot be empty.".to_string());
    }
    // Check if valid IP
    if trimmed.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    // Check if valid hostname: alphanumeric, dots, hyphens
    if trimmed.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-') {
        return Ok(());
    }
    Err("Invalid LHOST: Must be a valid IPv4, IPv6, or domain name without special characters.".to_string())
}

/// Validate port number (strictly 1..=65535)
fn validate_lport(input: &str) -> Result<u16, String> {
    match input.trim().parse::<u16>() {
        Ok(port) if port > 0 => Ok(port),
        _ => Err("Invalid LPORT: Must be a numeric port between 1 and 65535.".to_string()),
    }
}

/// Safely write payload to disk with parent directory creation, overwrite confirmation,
/// and restrictive Unix permissions (0600)
fn safe_write_payload(file_path: &Path, content: &str) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = file_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    if file_path.exists() {
        let overwrite = Confirm::new(&format!(
            "Target file '{}' already exists. Overwrite?",
            file_path.display()
        ))
        .with_default(false)
        .prompt()?;

        if !overwrite {
            return Err("File write aborted by operator to prevent overwrite.".into());
        }
    }

    fs::write(file_path, content)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(file_path)?.permissions();
        perms.set_mode(0o600); // Read/write only for owner
        fs::set_permissions(file_path, perms)?;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    print_banner();

    let args = CliArgs::parse();

    if args.batch {
        run_batch_mode(args).await?;
    } else {
        run_interactive_wizard(args.proxy).await?;
    }

    Ok(())
}

async fn run_interactive_wizard(cli_proxy: Option<String>) -> Result<(), Box<dyn Error>> {
    // 1. Select AI Provider
    let provider_options = vec![
        "DeepSeek AI (Cloud API - V3 / R1 - Cost-efficient & Powerful)",
        "Local Ollama (100% Private, Offline, Untraceable)",
        "OpenAI / Compatible (BYOK, Requires API Key)",
        "Anthropic Claude (BYOK, Requires API Key)",
    ];

    let chosen_provider = Select::new("Select AI Engine:", provider_options).prompt()?;

    // Optional Tor / SOCKS5 proxy setup for network anonymity
    let proxy_url: Option<String> = if chosen_provider.starts_with("Local Ollama") {
        None
    } else if let Some(p) = cli_proxy {
        println!("{} Using proxy from CLI: {}", "[✓]".green(), p);
        Some(p)
    } else {
        let use_proxy = Confirm::new("Route traffic through Tor or SOCKS5/HTTP Proxy? (Hides your real IP from API)")
            .with_default(false)
            .prompt()?;
        if use_proxy {
            let p = Text::new("Proxy URL:")
                .with_default("socks5://127.0.0.1:9050")
                .prompt()?;
            Some(p)
        } else {
            None
        }
    };

    let ai_engine: Box<dyn AiEngine> = if chosen_provider.starts_with("DeepSeek") {
        let env_key = Zeroizing::new(std::env::var("DEEPSEEK_API_KEY").unwrap_or_default());
        let api_key = if env_key.is_empty() {
            inquire::Password::new("DeepSeek API Key:")
                .with_display_mode(inquire::PasswordDisplayMode::Masked)
                .without_confirmation()
                .prompt()?
        } else {
            println!("{} Using detected DEEPSEEK_API_KEY from environment.", "[✓]".green());
            env_key.to_string()
        };

        let model = Text::new("DeepSeek Model:")
            .with_default("deepseek-chat")
            .prompt()?;

        Box::new(CloudEngine::new(
            api_key,
            CloudProvider::DeepSeek { model },
            proxy_url,
        )?)
    } else if chosen_provider.starts_with("Local Ollama") {
        let model = Text::new("Ollama Model Name:")
            .with_default("deepseek-coder")
            .prompt()?;
        Box::new(OllamaEngine::new(None, model))
    } else if chosen_provider.starts_with("OpenAI") {
        let env_key = Zeroizing::new(std::env::var("OPENAI_API_KEY").unwrap_or_default());
        let api_key = if env_key.is_empty() {
            inquire::Password::new("OpenAI API Key:")
                .with_display_mode(inquire::PasswordDisplayMode::Masked)
                .without_confirmation()
                .prompt()?
        } else {
            println!("{} Using detected OPENAI_API_KEY from environment.", "[✓]".green());
            env_key.to_string()
        };

        let model = Text::new("Model:")
            .with_default("gpt-4o")
            .prompt()?;

        Box::new(CloudEngine::new(
            api_key,
            CloudProvider::OpenAiCompatible {
                endpoint: "https://api.openai.com/v1/chat/completions".to_string(),
                model,
            },
            proxy_url,
        )?)
    } else {
        let env_key = Zeroizing::new(std::env::var("ANTHROPIC_API_KEY").unwrap_or_default());
        let api_key = if env_key.is_empty() {
            inquire::Password::new("Anthropic API Key:")
                .with_display_mode(inquire::PasswordDisplayMode::Masked)
                .without_confirmation()
                .prompt()?
        } else {
            println!("{} Using detected ANTHROPIC_API_KEY from environment.", "[✓]".green());
            env_key.to_string()
        };

        let model = Text::new("Model:")
            .with_default("claude-3-5-sonnet-20241022")
            .prompt()?;

        Box::new(CloudEngine::new(
            api_key,
            CloudProvider::Anthropic { model },
            proxy_url,
        )?)
    };

    // 2. Select Target Language
    let lang_options = vec!["Rust (.rs)", "C++ (.cpp)", "C# (.cs)"];
    let chosen_lang = Select::new("Payload Output Language:", lang_options).prompt()?;
    let target_lang = match chosen_lang {
        s if s.starts_with("Rust") => TargetLanguage::Rust,
        s if s.starts_with("C++") => TargetLanguage::Cpp,
        _ => TargetLanguage::CSharp,
    };

    // 3. Select Payload Archetype
    let archetype_options = vec![
        "TCP Reverse Shell (Direct socket bridge)",
        "Process Injection (Early Bird / APC Queue injection into explorer.exe)",
        "In-Memory Stager (Fetch executable buffer via HTTP & execute)",
        "Custom Archetype",
    ];
    let chosen_archetype = Select::new("Payload Archetype:", archetype_options).prompt()?;
    let payload_type = if chosen_archetype.starts_with("Custom") {
        Text::new("Describe payload behavior:").prompt()?
    } else {
        chosen_archetype.to_string()
    };

    // 4. Configure Listener & Strict Perimeter Validation (VULN-03)
    let lhost = loop {
        let input = Text::new("Listener LHOST (Operator IP):")
            .with_default("10.10.14.50")
            .prompt()?;
        match validate_lhost(&input) {
            Ok(()) => break input,
            Err(e) => eprintln!("{} {}", "[!]".red().bold(), e),
        }
    };

    let lport = loop {
        let input = Text::new("Listener LPORT (1-65535):")
            .with_default("4444")
            .prompt()?;
        match validate_lport(&input) {
            Ok(port) => break port,
            Err(e) => eprintln!("{} {}", "[!]".red().bold(), e),
        }
    };

    // 5. Select Evasion Primitives
    let evasion_features = vec![
        "Direct Syscalls (Hell's Gate / Halo's Gate - bypass ntdll hooks)",
        "Dynamic API Hashing (DJB2 / Murmur - conceal IAT signatures)",
        "Stack String & Buffer Encryption (XOR/RC4 in memory)",
        "Anti-Sandbox Timing & Memory Checks (VirtualAllocExNuma delays)",
    ];
    let selected_evasions = MultiSelect::new("Active Evasion Techniques:", evasion_features)
        .with_default(&[0, 1, 2, 3])
        .prompt()?;

    let custom_notes = Text::new("Additional Custom Instructions (optional):")
        .with_default("")
        .prompt()?;

    // 6. Data Sanitization & Anti-Flagging Transformation
    println!("\n{}", "[-] Sanitizing network indicators & euphemizing keywords...".cyan());
    let mut scrubber = TokenScrubber::new();
    let lhost_token = "{{DOOM_LHOST}}";
    let lport_token = "{{DOOM_LPORT}}";
    scrubber.register(lhost_token, &lhost);
    scrubber.register(lport_token, &lport.to_string());

    let scrubbed_custom = scrubber.scrub(&custom_notes);
    let safe_custom = TriggerWordSanitizer::sanitize(&scrubbed_custom);

    let profile = EvasionProfile {
        target_lang,
        payload_type: TriggerWordSanitizer::sanitize(&payload_type),
        lhost_placeholder: lhost_token.to_string(),
        lport_placeholder: lport_token.to_string(),
        enable_direct_syscalls: selected_evasions.iter().any(|s| s.starts_with("Direct Syscalls")),
        enable_api_hashing: selected_evasions.iter().any(|s| s.starts_with("Dynamic API Hashing")),
        enable_string_encryption: selected_evasions.iter().any(|s| s.starts_with("Stack String")),
        enable_sandbox_evasion: selected_evasions.iter().any(|s| s.starts_with("Anti-Sandbox")),
        custom_instructions: safe_custom,
    };

    let system_prompt = PromptBuilder::build_system_prompt();
    let user_prompt = PromptBuilder::build_user_prompt(&profile);

    println!("{}", "[+] Client indicators tokenized. Trigger words euphemized to prevent API bans.".green());
    println!("{}", "[*] Contacting AI engine to generate polymorphic evasion code...".yellow());

    // 7. AI Generation
    let raw_response = match ai_engine.generate(system_prompt, &user_prompt).await {
        Ok(res) => res,
        Err(e) => {
            eprintln!("{} Generation failed: {}", "[!]".red().bold(), e);
            return Ok(());
        }
    };

    let extracted_code = PromptBuilder::extract_code(&raw_response);

    // 8. Guardrails & Structural Completeness Inspection
    println!("{}", "\n[-] Running static guardrail & structural completeness analysis...".cyan());
    let report = GuardrailChecker::inspect(&extracted_code, target_lang.extension());
    GuardrailChecker::print_report(&report);

    if !report.is_safe || !report.is_complete {
        let proceed = Confirm::new("Warnings detected above. Do you still want to proceed and save this source code?")
            .with_default(false)
            .prompt()?;
        if !proceed {
            println!("{}", "Operation aborted by operator.".yellow());
            return Ok(());
        }
    }

    // 9. Rehydration & Safe File Output (VULN-02)
    let rehydrated_code = scrubber.rehydrate(&extracted_code);

    let default_filename = format!("doom_payload.{}", target_lang.extension());
    let outfile = Text::new("Save payload to:")
        .with_default(&default_filename)
        .prompt()?;

    safe_write_payload(Path::new(&outfile), &rehydrated_code)?;
    println!(
        "\n{} Payload successfully written to: {} (permissions: 0600)",
        "[✓]".green().bold(),
        outfile.bold()
    );

    // 10. Display Safe Compilation Instructions
    print_compilation_guide(target_lang, &outfile);

    Ok(())
}

async fn run_batch_mode(args: CliArgs) -> Result<(), Box<dyn Error>> {
    println!("{}", "[*] Running Doom in batch mode...".yellow());
    
    // Strict perimeter validation for batch mode (VULN-03)
    validate_lhost(&args.lhost).map_err(|e| format!("Batch parameter error: {}", e))?;
    let lport = validate_lport(&args.lport).map_err(|e| format!("Batch parameter error: {}", e))?;

    let target_lang = match args.lang.to_lowercase().as_str() {
        "cpp" => TargetLanguage::Cpp,
        "csharp" | "cs" => TargetLanguage::CSharp,
        _ => TargetLanguage::Rust,
    };

    let mut scrubber = TokenScrubber::new();
    let lhost_token = "{{DOOM_LHOST}}";
    let lport_token = "{{DOOM_LPORT}}";
    scrubber.register(lhost_token, &args.lhost);
    scrubber.register(lport_token, &lport.to_string());

    let profile = EvasionProfile {
        target_lang,
        payload_type: "diagnostic_command_bridge".to_string(),
        lhost_placeholder: lhost_token.to_string(),
        lport_placeholder: lport_token.to_string(),
        enable_direct_syscalls: true,
        enable_api_hashing: true,
        enable_string_encryption: true,
        enable_sandbox_evasion: true,
        custom_instructions: String::new(),
    };

    let system_prompt = PromptBuilder::build_system_prompt();
    let user_prompt = PromptBuilder::build_user_prompt(&profile);

    // Support proxy and multiple engines in batch mode (EDGE-03)
    let engine: Box<dyn AiEngine> = match args.engine.to_lowercase().as_str() {
        "deepseek" => {
            let key = std::env::var("DEEPSEEK_API_KEY").unwrap_or_default();
            if key.is_empty() {
                return Err("DEEPSEEK_API_KEY environment variable required for batch DeepSeek mode.".into());
            }
            Box::new(CloudEngine::new(
                key,
                CloudProvider::DeepSeek { model: "deepseek-chat".to_string() },
                args.proxy,
            )?)
        }
        "openai" => {
            let key = std::env::var("OPENAI_API_KEY").unwrap_or_default();
            if key.is_empty() {
                return Err("OPENAI_API_KEY environment variable required for batch OpenAI mode.".into());
            }
            Box::new(CloudEngine::new(
                key,
                CloudProvider::OpenAiCompatible {
                    endpoint: "https://api.openai.com/v1/chat/completions".to_string(),
                    model: "gpt-4o".to_string(),
                },
                args.proxy,
            )?)
        }
        _ => Box::new(OllamaEngine::new(None, "deepseek-coder".to_string())),
    };

    match engine.generate(system_prompt, &user_prompt).await {
        Ok(res) => {
            let extracted = PromptBuilder::extract_code(&res);
            let rehydrated = scrubber.rehydrate(&extracted);
            let filename = args
                .output
                .unwrap_or_else(|| format!("doom_payload.{}", target_lang.extension()));
            
            // Safe write in batch mode
            if let Some(parent) = Path::new(&filename).parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            fs::write(&filename, &rehydrated)?;
            
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&filename)?.permissions();
                perms.set_mode(0o600);
                fs::set_permissions(&filename, perms)?;
            }

            println!("{} Batch payload written to: {} (permissions: 0600)", "[✓]".green(), filename);
        }
        Err(e) => {
            eprintln!("{} Batch generation failed: {}", "[!]".red(), e);
        }
    }

    Ok(())
}

fn print_compilation_guide(lang: TargetLanguage, filename: &str) {
    println!("\n{}", "=== Safe Compilation Instructions ===".bright_white().bold());
    match lang {
        TargetLanguage::Rust => {
            println!("To cross-compile for Windows x64 with stripped symbols:");
            println!(
                "  {}",
                format!("rustc --target x86_64-pc-windows-gnu -C opt-level=z -C panic=abort -C link-arg=-s {} -o payload.exe", filename).cyan()
            );
        }
        TargetLanguage::Cpp => {
            println!("To compile with MinGW-w64 on Linux for Windows target:");
            println!(
                "  {}",
                format!("x86_64-w64-mingw32-g++ -s -O2 -mwindows {} -o payload.exe -lws2_32", filename).cyan()
            );
        }
        TargetLanguage::CSharp => {
            println!("To compile with Mono or .NET SDK:");
            println!(
                "  {}",
                format!("csc /target:winexe /optimize+ /out:payload.exe {}", filename).cyan()
            );
        }
    }
    println!("\n{}", "Stay safe and ensure you have authorized written consent.".dimmed());
}
