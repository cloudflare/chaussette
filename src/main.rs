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

use chaussette::{start, Config, HttpVersion};
use clap::Parser;
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

    #[arg(long = "4")]
    pub ipv4: bool,

    /// Request timeout
    #[arg(long = "timeout")]
    pub request_timeout: Option<u64>,

    #[arg(long = "happy-eyeballs-timeout")]
    pub happy_eyeballs_timeout: Option<u64>,

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

    let config = Config {
        proxy: opt.proxy,
        geohash: opt.geohash,
        request_timeout: opt.request_timeout,
        happy_eyeballs_timeout: opt.happy_eyeballs_timeout,
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
        ipv4: opt.ipv4,
    };

    start(config, &opt.listen_addr).await?.await
}
