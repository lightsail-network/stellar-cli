use std::str::FromStr;

use clap::arg;
use http::{HeaderName, HeaderValue};
use phf::phf_map;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use stellar_strkey::ed25519::PublicKey;

use super::locator;
use crate::utils::rpc::new_rpc_client;
use crate::{
    commands::HEADING_RPC,
    rpc::{self},
};
pub mod passphrase;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Config(#[from] locator::Error),

    #[error("network arg or rpc url and network passphrase are required if using the network")]
    Network,
    #[error(transparent)]
    Http(#[from] http::Error),
    #[error(transparent)]
    Rpc(#[from] rpc::Error),
    #[error(transparent)]
    Hyper(#[from] hyper::Error),
    #[error("Failed to parse JSON from {0}, {1}")]
    FailedToParseJSON(String, serde_json::Error),
    #[error("Invalid URL {0}")]
    InvalidUrl(String),
    #[error("funding failed: {0}")]
    FundingFailed(String),
    #[error("Invalid HTTP header: {0}")]
    InvalidHttpHeader(String),
}

#[derive(Debug, clap::Args, Clone, Default)]
#[group(skip)]
pub struct Args {
    /// RPC server endpoint
    #[arg(
        long = "rpc-url",
        requires = "network_passphrase",
        required_unless_present = "network",
        env = "STELLAR_RPC_URL",
        help_heading = HEADING_RPC,
    )]
    pub rpc_url: Option<String>,
    /// Network passphrase to sign the transaction sent to the rpc server
    #[arg(
        long = "network-passphrase",
        requires = "rpc_url",
        required_unless_present = "network",
        env = "STELLAR_NETWORK_PASSPHRASE",
        help_heading = HEADING_RPC,
    )]
    pub network_passphrase: Option<String>,
    /// RPC headers in key:value format, can be specified multiple times or as a newline separated list
    #[arg(
        long = "rpc-header",
        env = "STELLAR_RPC_HEADERS",
        help_heading = HEADING_RPC,
        value_parser = parse_http_header,
        num_args = 1,
        action = clap::ArgAction::Append,
        value_delimiter = '\n',
    )]
    pub rpc_headers: Vec<(String, String)>,
    /// Name of network to use from config
    #[arg(
        long,
        required_unless_present = "rpc_url",
        required_unless_present = "network_passphrase",
        env = "STELLAR_NETWORK",
        help_heading = HEADING_RPC,
    )]
    pub network: Option<String>,
}

impl Args {
    pub fn get(&self, locator: &locator::Args) -> Result<Network, Error> {
        if let Some(name) = self.network.as_deref() {
            if let Ok(network) = locator.read_network(name) {
                return Ok(network);
            }
        }
        if let (Some(rpc_url), Some(network_passphrase)) =
            (self.rpc_url.clone(), self.network_passphrase.clone())
        {
            Ok(Network {
                rpc_url,
                network_passphrase,
                rpc_headers: vec![],
            })
        } else {
            Err(Error::Network)
        }
    }
}

#[derive(Debug, clap::Args, Serialize, Deserialize, Clone)]
#[group(skip)]
pub struct Network {
    /// RPC server endpoint
    #[arg(
        long = "rpc-url",
        env = "STELLAR_RPC_URL",
        help_heading = HEADING_RPC,
    )]
    pub rpc_url: String,
    /// Network passphrase to sign the transaction sent to the rpc server
    #[arg(
            long,
            env = "STELLAR_NETWORK_PASSPHRASE",
            help_heading = HEADING_RPC,
    )]
    pub network_passphrase: String,
    /// RPC headers in key:value format, can be specified multiple times or as a newline separated list
    #[arg(
        long = "rpc-header",
        env = "STELLAR_RPC_HEADERS",
        help_heading = HEADING_RPC,
        value_parser = parse_http_header,
        num_args = 1,
        action = clap::ArgAction::Append,
        value_delimiter = '\n',
    )]
    pub rpc_headers: Vec<(String, String)>,
}

fn parse_http_header(s: &str) -> Result<(String, String), Error> {
    let pos = s
        .find(':')
        .ok_or_else(|| Error::InvalidHttpHeader(format!("missing `:` in `{}`", s)))?;
    let key = s[..pos].trim().to_string();
    let value = s[pos + 1..].trim().to_string();

    // Validate header name and value
    if HeaderName::from_str(&key).is_err() {
        return Err(Error::InvalidHttpHeader(format!("Invalid HTTP header key `{}`", key)));
    }

    if HeaderValue::from_str(&value).is_err() {
        return Err(Error::InvalidHttpHeader(format!("Invalid HTTP header value `{}`", value)));
    }

    Ok((key, value))
}

impl Network {
    pub async fn helper_url(&self, addr: &str) -> Result<http::Uri, Error> {
        use http::Uri;
        tracing::debug!("address {addr:?}");
        let rpc_uri = Uri::from_str(&self.rpc_url)
            .map_err(|_| Error::InvalidUrl(self.rpc_url.to_string()))?;
        if self.network_passphrase.as_str() == passphrase::LOCAL {
            let auth = rpc_uri.authority().unwrap().clone();
            let scheme = rpc_uri.scheme_str().unwrap();
            Ok(Uri::builder()
                .authority(auth)
                .scheme(scheme)
                .path_and_query(format!("/friendbot?addr={addr}"))
                .build()?)
        } else {
            let client = new_rpc_client(&self)?;
            let network = client.get_network().await?;
            tracing::debug!("network {network:?}");
            let uri = client.friendbot_url().await?;
            tracing::debug!("URI {uri:?}");
            Uri::from_str(&format!("{uri}?addr={addr}")).map_err(|e| {
                tracing::error!("{e}");
                Error::InvalidUrl(uri.to_string())
            })
        }
    }

    #[allow(clippy::similar_names)]
    pub async fn fund_address(&self, addr: &PublicKey) -> Result<(), Error> {
        let uri = self.helper_url(&addr.to_string()).await?;
        tracing::debug!("URL {uri:?}");
        let response = match uri.scheme_str() {
            Some("http") => hyper::Client::new().get(uri.clone()).await?,
            Some("https") => {
                let https = hyper_tls::HttpsConnector::new();
                hyper::Client::builder()
                    .build::<_, hyper::Body>(https)
                    .get(uri.clone())
                    .await?
            }
            _ => {
                return Err(Error::InvalidUrl(uri.to_string()));
            }
        };
        let request_successful = response.status().is_success();
        let body = hyper::body::to_bytes(response.into_body()).await?;
        let res = serde_json::from_slice::<serde_json::Value>(&body)
            .map_err(|e| Error::FailedToParseJSON(uri.to_string(), e))?;
        tracing::debug!("{res:#?}");
        if !request_successful {
            if let Some(detail) = res.get("detail").and_then(Value::as_str) {
                if detail.contains("account already funded to starting balance") {
                    // Don't error if friendbot indicated that the account is
                    // already fully funded to the starting balance, because the
                    // user's goal is to get funded, and the account is funded
                    // so it is success much the same.
                    tracing::debug!("already funded error ignored because account is funded");
                } else {
                    return Err(Error::FundingFailed(detail.to_string()));
                }
            } else {
                return Err(Error::FundingFailed("unknown cause".to_string()));
            }
        }
        Ok(())
    }

    pub fn rpc_uri(&self) -> Result<http::Uri, Error> {
        http::Uri::from_str(&self.rpc_url).map_err(|_| Error::InvalidUrl(self.rpc_url.to_string()))
    }
}

pub static DEFAULTS: phf::Map<&'static str, (&'static str, &'static str)> = phf_map! {
    "local" => (
        "http://localhost:8000/rpc",
        passphrase::LOCAL,
    ),
    "futurenet" => (
        "https://rpc-futurenet.stellar.org:443",
        passphrase::FUTURENET,
    ),
    "testnet" => (
        "https://soroban-testnet.stellar.org",
        passphrase::TESTNET,
    ),
    "mainnet" => (
        "Bring Your Own: https://developers.stellar.org/docs/data/rpc/rpc-providers",
        passphrase::MAINNET,
    ),
};

impl From<&(&str, &str)> for Network {
    /// Convert the return value of `DEFAULTS.get()` into a Network
    fn from(n: &(&str, &str)) -> Self {
        Self {
            rpc_url: n.0.to_string(),
            network_passphrase: n.1.to_string(),
            rpc_headers: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::network::parse_http_header;

    #[test]
    fn test_parse_valid_header() {
        let result = parse_http_header("User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36");
        assert!(result.is_ok());
        let (key, value) = result.unwrap();
        assert_eq!(key, "User-Agent");
        assert_eq!(value, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36");
    }

    #[test]
    fn test_parse_header_with_multiple_colons() {
        let result = parse_http_header("Authorization: Bearer abc:123:xyz");
        assert!(result.is_ok());
        let (key, value) = result.unwrap();
        assert_eq!(key, "Authorization");
        assert_eq!(value, "Bearer abc:123:xyz");
    }

    #[test]
    fn test_parse_header_with_spaces() {
        let result = parse_http_header("  User-Agent:  Mozilla/5.0  ");
        assert!(result.is_ok());
        let (key, value) = result.unwrap();
        assert_eq!(key, "User-Agent");
        assert_eq!(value, "Mozilla/5.0");
    }

    #[test]
    fn test_parse_header_missing_colon() {
        let result = parse_http_header("Invalid-Header");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing `:`"));
    }

    #[test]
    fn test_parse_header_invalid_key() {
        let result = parse_http_header("Invalid\nHeader: value");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid HTTP header key"));
    }

    #[test]
    fn test_parse_header_invalid_value() {
        let result = parse_http_header("X-Custom-Header: Invalid\nValue");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid HTTP header value"));
    }

    #[test]
    fn test_parse_header_empty_key() {
        let result = parse_http_header(": some-value");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid HTTP header key"));
    }

    #[test]
    fn test_parse_header_empty_value() {
        let result = parse_http_header("X-Empty:");
        assert!(result.is_ok());
        let (key, value) = result.unwrap();
        assert_eq!(key, "X-Empty");
        assert_eq!(value, "");
    }
}