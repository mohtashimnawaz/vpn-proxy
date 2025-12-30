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

    /// Username to require for username/password authentication (RFC 1929)
    #[arg(long, requires = "password")]
    username: Option<String>,

    /// Password to require for username/password authentication (RFC 1929)
    #[arg(long, requires = "username")]
    password: Option<String>,
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

    let auth = if let (Some(u), Some(p)) = (opts.username, opts.password) {
        Some((u, p))
    } else {
        None
    };

    socks5::run(&opts.listen, tls, auth).await?;

    Ok(())
}
