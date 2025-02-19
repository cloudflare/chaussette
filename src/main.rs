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

use clap::Parser;
use chaussette::{start, Config};
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

    /// Request timeout
    #[arg(long = "timeout")]
    pub request_timeout: Option<u64>,

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
        masque_preshared_key: opt.masque_preshared_key,
        proxy_ca: opt.proxy_ca,
        client_cert: opt.client_cert,
        client_key: opt.client_key,
    };

    start(config, &opt.listen_addr).await?.await
}
