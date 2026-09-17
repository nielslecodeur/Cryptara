use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cryptara", version, about = "CLI Cryptara")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    Generate(GenerateArgs),
    Verify(VerifyArgs),
    Root(RootArgs),
    Master(MasterArgs),
    Wallet(WalletArgs),
    Init(InitArgs),
    Child(ChildArgs),
    Derive(DeriveArgs),
}

#[derive(Args)]
pub(crate) struct GenerateArgs {
    #[arg(long)]
    pub(crate) mnemonic: bool,
}

#[derive(Args)]
pub(crate) struct VerifyArgs {
    #[arg(long)]
    pub(crate) mnemonic: Option<String>,
}

#[derive(Args)]
pub(crate) struct RootArgs {
    pub(crate) entropy_hex: Option<String>,

    #[arg(long)]
    pub(crate) mnemonic: Option<String>,

    #[arg(long, requires = "mnemonic")]
    pub(crate) passphrase: Option<String>,
}

#[derive(Args)]
pub(crate) struct MasterArgs {
    pub(crate) root_seed_hex: String,
}

#[derive(Args)]
pub(crate) struct WalletArgs {
    pub(crate) entropy_hex: Option<String>,

    #[arg(long)]
    pub(crate) mnemonic: Option<String>,

    #[arg(long, requires = "mnemonic")]
    pub(crate) passphrase: Option<String>,
}

#[derive(Args)]
pub(crate) struct InitArgs {
    #[arg(long)]
    pub(crate) passphrase: Option<String>,
}

#[derive(Args)]
pub(crate) struct ChildArgs {
    pub(crate) public_key: String,
    pub(crate) chain_code: String,
    #[arg(long)]
    pub(crate) index: u32,
}

#[derive(Args)]
pub(crate) struct DeriveArgs {
    pub(crate) public_key: String,
    pub(crate) chain_code: String,
    #[arg(long)]
    pub(crate) index: u32,
    #[arg(long)]
    pub(crate) level: u32,
}
