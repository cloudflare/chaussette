//Copyright 2025 Cloudflare Inc.
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.

use chaussette::{start, Config, Http2KeepAliveConfig, HttpVersion};
use clap::Parser;
use std::time::Duration;
use url::Url;

#[derive(Debug, Parser)]
pub struct Opt {
    /// Bind on address address. eg. `127.0.0.1:1080`
    #[arg(short, long)]
    pub listen_addr: String,

    #[arg(short, long, default_value_t = Url::parse("https://masque-relay.cloudflare.com").unwrap())]
    pub proxy: Url,

    #[arg(short, long, default_value_t = String::from("xn76cvs0-JP"))]
    pub geohash: String,

    #[arg(long = "h2", alias = "http2", conflicts_with = "http3")]
    pub http2: bool,

    #[arg(long = "h3", alias = "http3", conflicts_with = "http2")]
    pub http3: bool,

    /// Request timeout
    #[arg(long = "timeout")]
    pub request_timeout: Option<u64>,

    /// Seconds between HTTP/2 PING frames. Defaults to 30.
    #[arg(
        long = "http2-keepalive-interval",
        conflicts_with = "http3",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub http2_keepalive_interval: Option<u64>,

    /// Seconds to wait for an HTTP/2 PING acknowledgement. Defaults to 10.
    #[arg(
        long = "http2-keepalive-timeout",
        conflicts_with = "http3",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub http2_keepalive_timeout: Option<u64>,

    /// Disable HTTP/2 PING frames while retaining eager connection recovery.
    #[arg(
        long = "disable-http2-keepalive",
        conflicts_with_all = ["http2_keepalive_interval", "http2_keepalive_timeout", "http3"]
    )]
    pub disable_http2_keepalive: bool,

    #[arg(env)]
    pub masque_preshared_key: Option<String>,

    #[arg(long)]
    pub proxy_ca: Option<String>,

    #[arg(env)]
    pub client_cert: Option<String>,

    #[arg(env)]
    pub client_key: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let opt = Opt::parse();

    let mut http2_keepalive = Http2KeepAliveConfig {
        enabled: !opt.disable_http2_keepalive && !opt.http3,
        ..Http2KeepAliveConfig::default()
    };

    if let Some(interval) = opt.http2_keepalive_interval {
        http2_keepalive.interval = Duration::from_secs(interval);
    }

    if let Some(timeout) = opt.http2_keepalive_timeout {
        http2_keepalive.timeout = Duration::from_secs(timeout);
    }

    let config = Config {
        proxy: opt.proxy,
        geohash: opt.geohash,
        request_timeout: opt.request_timeout,
        masque_preshared_key: opt.masque_preshared_key,
        proxy_ca: opt.proxy_ca,
        client_cert: opt.client_cert,
        client_key: opt.client_key,
        http_version: if opt.http3 {
            HttpVersion::H3
        } else {
            // h2 is the default so we don't actually need to check the flag
            // clap already errors if both are set to true
            HttpVersion::H2
        },
        http2_keepalive,
    };

    start(config, &opt.listen_addr).await?.await
}

#[cfg(test)]
mod tests {
    use super::Opt;
    use clap::Parser;

    #[test]
    fn parses_complete_http2_keepalive_configuration() {
        let options = Opt::try_parse_from([
            "chaussette",
            "--listen-addr",
            "127.0.0.1:1080",
            "--http2-keepalive-interval",
            "10",
            "--http2-keepalive-timeout",
            "5",
        ])
        .unwrap();

        assert_eq!(options.http2_keepalive_interval, Some(10));
        assert_eq!(options.http2_keepalive_timeout, Some(5));
    }

    #[test]
    fn parses_disabled_http2_keepalive_configuration() {
        let options = Opt::try_parse_from([
            "chaussette",
            "--listen-addr",
            "127.0.0.1:1080",
            "--disable-http2-keepalive",
        ])
        .unwrap();

        assert!(options.disable_http2_keepalive);
    }
}
