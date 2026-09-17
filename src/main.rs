mod cli;
mod ffi;
mod helpers;
mod key;
mod seed;

use clap::Parser;

use cli::{
    ChildArgs, Cli, Command, DeriveArgs, GenerateArgs, InitArgs, MasterArgs, RootArgs, VerifyArgs,
    WalletArgs,
};
use helpers::CliError;
use key::{MasterPrivateKey, MasterPublicKey};
use seed::Seed;

fn main() {
    let cli = Cli::parse();

    if let Err(err) = run(cli.command) {
        eprintln!("Erreur: {err}");
        std::process::exit(1);
    }
}

fn run(command: Command) -> Result<(), CliError> {
    match command {
        Command::Generate(args) => cmd_generate(args),
        Command::Verify(args) => cmd_verify(args),
        Command::Root(args) => cmd_root(args),
        Command::Master(args) => cmd_master(args),
        Command::Wallet(args) => cmd_wallet(args),
        Command::Init(args) => cmd_init(args),
        Command::Child(args) => cmd_child(args),
        Command::Derive(args) => cmd_derive(args),
    }
}

fn cmd_generate(args: GenerateArgs) -> Result<(), CliError> {
    let seed = Seed::generate();

    if args.mnemonic {
        println!("{}", seed.words()?.join(" "));
    } else {
        println!("{}", hex::encode(seed.as_bytes()));
    }

    Ok(())
}

fn cmd_verify(args: VerifyArgs) -> Result<(), CliError> {
    let phrase = args.mnemonic.as_deref().ok_or_else(|| {
        CliError::Unsupported("verify nécessite --mnemonic \"<12 mots>\"".to_string())
    })?;

    let words = helpers::parse_mnemonic(phrase)?;

    match Seed::from_words(&words) {
        Ok(_) => {
            println!("Mnemonic valide.");
            Ok(())
        }
        Err(reason) => {
            println!("Mnemonic invalide: {reason}");
            Err(CliError::from(reason))
        }
    }
}

fn cmd_root(args: RootArgs) -> Result<(), CliError> {
    helpers::require_exactly_one_source(&args.entropy_hex, &args.mnemonic)?;

    let seed = if let Some(hex_str) = args.entropy_hex.as_deref() {
        Seed::from_bytes(&helpers::parse_seed_bytes(hex_str)?)
    } else {
        let phrase = args.mnemonic.as_deref().unwrap();
        Seed::from_words(&helpers::parse_mnemonic(phrase)?)?
    };

    let passphrase = args.passphrase.as_deref().map(str::as_bytes);
    let root_seed = seed.root_seed(passphrase)?;

    println!("{}", hex::encode(root_seed));
    Ok(())
}

fn cmd_master(args: MasterArgs) -> Result<(), CliError> {
    let root_seed = helpers::parse_root_seed(&args.root_seed_hex)?;

    let (master_private_key, chain_code) = MasterPrivateKey::from_root_seed(&root_seed)?;
    let master_public_key = MasterPublicKey::try_from(&master_private_key)?;

    print_wallet_keys(&master_private_key, &master_public_key, chain_code.bytes());

    Ok(())
}

fn cmd_wallet(args: WalletArgs) -> Result<(), CliError> {
    helpers::require_exactly_one_source(&args.entropy_hex, &args.mnemonic)?;

    let seed = if let Some(hex_str) = args.entropy_hex.as_deref() {
        Seed::from_bytes(&helpers::parse_seed_bytes(hex_str)?)
    } else {
        let phrase = args.mnemonic.as_deref().unwrap();
        Seed::from_words(&helpers::parse_mnemonic(phrase)?)?
    };

    let passphrase = args.passphrase.as_deref().map(str::as_bytes);
    let root_seed = seed.root_seed(passphrase)?;

    let (master_private_key, chain_code) = MasterPrivateKey::from_root_seed(&root_seed)?;
    let master_public_key = MasterPublicKey::try_from(&master_private_key)?;

    println!("Mnemonic  : {}", seed.words()?.join(" "));
    println!("Root seed : {}", hex::encode(root_seed));
    print_wallet_keys(&master_private_key, &master_public_key, chain_code.bytes());

    Ok(())
}

fn cmd_init(args: InitArgs) -> Result<(), CliError> {
    let seed = Seed::generate();

    let passphrase = args.passphrase.as_deref().map(str::as_bytes);
    let root_seed = seed.root_seed(passphrase)?;

    let (master_private_key, chain_code) = MasterPrivateKey::from_root_seed(&root_seed)?;
    let master_public_key = MasterPublicKey::try_from(&master_private_key)?;

    println!("Mnemonic  : {}", seed.words()?.join(" "));
    println!("Root seed : {}", hex::encode(root_seed));
    print_wallet_keys(&master_private_key, &master_public_key, chain_code.bytes());

    Ok(())
}

fn cmd_child(args: ChildArgs) -> Result<(), CliError> {
    let public_key = helpers::parse_public_key(&args.public_key)?;
    let chain_code = helpers::parse_chain_code(&args.chain_code)?;

    let (child_key, child_chain_code) = public_key.generate_child_key(&chain_code, args.index)?;

    println!("Child public key: {}", hex::encode(child_key.bytes()));
    println!(
        "Child chain code: {}",
        hex::encode(child_chain_code.bytes())
    );

    Ok(())
}

fn cmd_derive(args: DeriveArgs) -> Result<(), CliError> {
    let public_key = helpers::parse_public_key(&args.public_key)?;
    let chain_code = helpers::parse_chain_code(&args.chain_code)?;

    let (derived_key, derived_chain_code) =
        public_key.generate_nth_mth_0_child_key(&chain_code, args.index, args.level)?;

    println!("Derived public key: {}", hex::encode(derived_key.bytes()));
    println!(
        "Derived chain code: {}",
        hex::encode(derived_chain_code.bytes())
    );

    Ok(())
}

fn print_wallet_keys(
    master_private_key: &MasterPrivateKey,
    master_public_key: &MasterPublicKey,
    chain_code_bytes: &[u8; 32],
) {
    println!("Master private key: {master_private_key:?}");
    println!(
        "Master public key : {}",
        hex::encode(master_public_key.bytes())
    );
    println!("Chain code        : {}", hex::encode(chain_code_bytes));
}
