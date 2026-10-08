//! Cloud provider client with zeroize in-memory credential wiping and Tor/SOCKS5 proxy routing.

use super::AiEngine;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Client, Proxy};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(secret: String) -> Self {
        Self(secret)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub enum CloudProvider {
    OpenAiCompatible { endpoint: String, model: String },
    DeepSeek { model: String },
    Anthropic { model: String },
}

#[derive(Serialize)]
struct OpenAiMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Serialize)]
struct OpenAiChatRequest<'a> {
    model: &'a str,
    messages: Vec<OpenAiMessage<'a>>,
    temperature: f32,
}

#[derive(Deserialize)]
struct OpenAiChoice {
    message: OpenAiResponseMessage,
}

#[derive(Deserialize)]
struct OpenAiResponseMessage {
    content: String,
}

#[derive(Deserialize)]
struct OpenAiChatResponse {
    choices: Vec<OpenAiChoice>,
}

pub struct CloudEngine {
    api_key: SecretString,
    provider: CloudProvider,
    client: Client,
}

impl CloudEngine {
    pub fn new(api_key: String, provider: CloudProvider, proxy_url: Option<String>) -> Result<Self, Box<dyn Error>> {
        let mut builder = Client::builder()
            .timeout(std::time::Duration::from_secs(180));

        if let Some(proxy_str) = proxy_url {
            if !proxy_str.trim().is_empty() {
                let proxy = Proxy::all(&proxy_str)?;
                builder = builder.proxy(proxy);
            }
        }

        let client = builder.build()?;

        Ok(Self {
            api_key: SecretString::new(api_key),
            provider,
            client,
        })
    }
}

impl AiEngine for CloudEngine {
    fn generate<'a>(
        &'a self,
        system_prompt: &'a str,
        user_prompt: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, Box<dyn Error>>> + Send + 'a>> {
        Box::pin(async move {
            match &self.provider {
                CloudProvider::OpenAiCompatible { endpoint, model } => {
                    let req_body = OpenAiChatRequest {
                        model,
                        messages: vec![
                            OpenAiMessage {
                                role: "system",
                                content: system_prompt,
                            },
                            OpenAiMessage {
                                role: "user",
                                content: user_prompt,
                            },
                        ],
                        temperature: 0.2,
                    };

                    // Use Zeroizing for intermediate bearer token to prevent heap residual leaks (VULN-01)
                    let bearer_formatted = Zeroizing::new(format!("Bearer {}", self.api_key.as_str()));
                    let mut auth_val = HeaderValue::from_str(bearer_formatted.as_str())?;
                    auth_val.set_sensitive(true);

                    let mut headers = HeaderMap::new();
                    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                    headers.insert(AUTHORIZATION, auth_val);

                    let res = self
                        .client
                        .post(endpoint)
                        .headers(headers)
                        .json(&req_body)
                        .send()
                        .await?;

                    if !res.status().is_success() {
                        let err = res.text().await.unwrap_or_default();
                        return Err(format!("Cloud API error: {}", err).into());
                    }

                    let parsed: OpenAiChatResponse = res.json().await?;
                    if let Some(choice) = parsed.choices.into_iter().next() {
                        Ok(choice.message.content)
                    } else {
                        Err("Empty response from Cloud LLM.".into())
                    }
                }
                CloudProvider::DeepSeek { model } => {
                    let endpoint = "https://api.deepseek.com/chat/completions";
                    let req_body = OpenAiChatRequest {
                        model,
                        messages: vec![
                            OpenAiMessage {
                                role: "system",
                                content: system_prompt,
                            },
                            OpenAiMessage {
                                role: "user",
                                content: user_prompt,
                            },
                        ],
                        temperature: 0.2,
                    };

                    let bearer_formatted = Zeroizing::new(format!("Bearer {}", self.api_key.as_str()));
                    let mut auth_val = HeaderValue::from_str(bearer_formatted.as_str())?;
                    auth_val.set_sensitive(true);

                    let mut headers = HeaderMap::new();
                    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                    headers.insert(AUTHORIZATION, auth_val);

                    let res = self
                        .client
                        .post(endpoint)
                        .headers(headers)
                        .json(&req_body)
                        .send()
                        .await?;

                    if !res.status().is_success() {
                        let err = res.text().await.unwrap_or_default();
                        return Err(format!("DeepSeek API error: {}", err).into());
                    }

                    let parsed: OpenAiChatResponse = res.json().await?;
                    if let Some(choice) = parsed.choices.into_iter().next() {
                        Ok(choice.message.content)
                    } else {
                        Err("Empty response from DeepSeek API.".into())
                    }
                }
                CloudProvider::Anthropic { model } => {
                    let body = serde_json::json!({
                        "model": model,
                        "max_tokens": 4096,
                        "system": system_prompt,
                        "messages": [
                            {"role": "user", "content": user_prompt}
                        ]
                    });

                    let mut api_key_val = HeaderValue::from_str(self.api_key.as_str())?;
                    api_key_val.set_sensitive(true);

                    let mut headers = HeaderMap::new();
                    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                    headers.insert("x-api-key", api_key_val);
                    headers.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));

                    let res = self
                        .client
                        .post("https://api.anthropic.com/v1/messages")
                        .headers(headers)
                        .json(&body)
                        .send()
                        .await?;

                    if !res.status().is_success() {
                        let err = res.text().await.unwrap_or_default();
                        return Err(format!("Anthropic API error: {}", err).into());
                    }

                    let parsed: serde_json::Value = res.json().await?;
                    if let Some(content_array) = parsed.get("content").and_then(|c| c.as_array()) {
                        if let Some(text_obj) = content_array.first().and_then(|item| item.get("text")) {
                            if let Some(text) = text_obj.as_str() {
                                return Ok(text.to_string());
                            }
                        }
                    }

                    Err("Failed to parse Anthropic response.".into())
                }
            }
        })
    }
}
