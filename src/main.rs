use anyhow::Result;
use clap::Parser;
use tracing_subscriber::fmt::init as tracing_init;

mod socks5;

#[derive(Parser, Debug)]
struct Opts {
    /// Listen address, e.g. 0.0.0.0:1080
    #[arg(short, long, default_value = "127.0.0.1:1080")]
    listen: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_init();

    let opts = Opts::parse();

    socks5::run(&opts.listen).await?;

    Ok(())
}
