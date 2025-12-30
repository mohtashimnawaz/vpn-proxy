use anyhow::Result;
use clap::Parser;
use tracing_subscriber::fmt::init as tracing_init;

mod socks5;

#[derive(Parser, Debug)]
struct Opts {
    /// Listen address, e.g. 0.0.0.0:1080
    #[arg(short, long, default_value = "127.0.0.1:1080")]
    listen: String,

    /// Enable TLS for client->proxy (requires building with `--features tls`)
    #[arg(long, default_value_t = false)]
    tls: bool,

    /// TLS certificate (PEM) path (required with --tls)
    #[arg(long, requires = "tls")]
    cert: Option<String>,

    /// TLS private key (PEM) path (required with --tls)
    #[arg(long, requires = "tls")]
    key: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_init();

    let opts = Opts::parse();

    let tls = if opts.tls {
        let cert = opts.cert.expect("--cert is required when --tls is used");
        let key = opts.key.expect("--key is required when --tls is used");
        Some((cert, key))
    } else {
        None
    };

    socks5::run(&opts.listen, tls).await?;

    Ok(())
}
