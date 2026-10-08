//! Local Ollama client: 100% private, offline, untraceable.

use super::AiEngine;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::future::Future;
use std::pin::Pin;

#[derive(Serialize)]
struct OllamaGenerateRequest<'a> {
    model: &'a str,
    prompt: &'a str,
    system: &'a str,
    stream: bool,
}

#[derive(Deserialize)]
struct OllamaGenerateResponse {
    response: String,
}

pub struct OllamaEngine {
    endpoint: String,
    model: String,
    client: Client,
}

impl OllamaEngine {
    pub fn new(host: Option<String>, model: String) -> Self {
        let base_host = host
            .or_else(|| std::env::var("OLLAMA_HOST").ok())
            .unwrap_or_else(|| "http://localhost:11434".to_string());
        
        let endpoint = format!("{}/api/generate", base_host.trim_end_matches('/'));

        Self {
            endpoint,
            model,
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(180))
                .build()
                .unwrap_or_default(),
        }
    }
}

impl AiEngine for OllamaEngine {
    fn generate<'a>(
        &'a self,
        system_prompt: &'a str,
        user_prompt: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, Box<dyn Error>>> + Send + 'a>> {
        Box::pin(async move {
            let req_body = OllamaGenerateRequest {
                model: &self.model,
                prompt: user_prompt,
                system: system_prompt,
                stream: false,
            };

            let res = self
                .client
                .post(&self.endpoint)
                .json(&req_body)
                .send()
                .await?;

            if !res.status().is_success() {
                let err_text = res.text().await.unwrap_or_default();
                return Err(format!("Ollama API returned error: {}", err_text).into());
            }

            let parsed: OllamaGenerateResponse = res.json().await?;
            Ok(parsed.response)
        })
    }
}
