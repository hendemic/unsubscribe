use std::time::Duration;

use anyhow::{Context, Result};
use unsubscribe_core::{HttpClient, HttpResponse};

/// Reqwest-based HTTP client adapter for the `HttpClient` trait.
///
/// Uses a 15-second timeout and 5-redirect limit to match legacy behavior.
pub struct ReqwestHttpClient {
    client: reqwest::blocking::Client,
}

impl ReqwestHttpClient {
    pub fn new() -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .context("Failed to build HTTP client")?;

        Ok(Self { client })
    }
}

impl HttpClient for ReqwestHttpClient {
    fn get(&self, url: &str) -> Result<HttpResponse> {
        let resp = self
            .client
            .get(url)
            .send()
            .with_context(|| format!("GET request failed: {url}"))?;

        let status = resp.status().as_u16();
        let body = resp.text().unwrap_or_default();

        Ok(HttpResponse { status, body })
    }

    fn get_with_headers(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse> {
        let mut builder = self.client.get(url);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let resp = builder
            .send()
            .with_context(|| format!("GET request failed: {url}"))?;

        let status = resp.status().as_u16();
        let body = resp.text().unwrap_or_default();

        Ok(HttpResponse { status, body })
    }

    fn post_form(&self, url: &str, params: &[(&str, &str)]) -> Result<HttpResponse> {
        let resp = self
            .client
            .post(url)
            .form(params)
            .send()
            .with_context(|| format!("POST form request failed: {url}"))?;

        let status = resp.status().as_u16();
        let body = resp.text().unwrap_or_default();

        Ok(HttpResponse { status, body })
    }

    fn post_body(&self, url: &str, content_type: &str, body: &str) -> Result<HttpResponse> {
        let resp = self
            .client
            .post(url)
            .header("Content-Type", content_type)
            .body(body.to_string())
            .send()
            .with_context(|| format!("POST body request failed: {url}"))?;

        let status = resp.status().as_u16();
        let resp_body = resp.text().unwrap_or_default();

        Ok(HttpResponse {
            status,
            body: resp_body,
        })
    }

    fn post_body_with_headers(
        &self,
        url: &str,
        content_type: &str,
        body: &str,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse> {
        let mut builder = self
            .client
            .post(url)
            .header("Content-Type", content_type)
            .body(body.to_string());
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let resp = builder
            .send()
            .with_context(|| format!("POST body request failed: {url}"))?;

        let status = resp.status().as_u16();
        let resp_body = resp.text().unwrap_or_default();

        Ok(HttpResponse {
            status,
            body: resp_body,
        })
    }
}
