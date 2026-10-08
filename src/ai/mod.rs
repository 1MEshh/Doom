//! AI Provider abstraction layer.
//! Guarantees memory wiping for sensitive credentials via Zeroize.

pub mod cloud;
pub mod ollama;

use std::error::Error;
use std::future::Future;
use std::pin::Pin;

pub trait AiEngine: Send + Sync {
    /// Send prompt with system context and retrieve generated response
    fn generate<'a>(
        &'a self,
        system_prompt: &'a str,
        user_prompt: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, Box<dyn Error>>> + Send + 'a>>;
}
