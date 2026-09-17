use std::fmt;

use crate::key::{ChainCode, MasterPublicKey};

#[derive(Debug)]
pub(crate) enum CliError {
    Business(&'static str),
    InvalidHex {
        what: &'static str,
    },
    InvalidLength {
        what: &'static str,
        expected: usize,
        actual: usize,
    },
    Unsupported(String),
    Io(std::io::Error),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Business(msg) => write!(f, "{msg}"),
            CliError::InvalidHex { what } => {
                write!(f, "Invalid {what}: expected hexadecimal data")
            }
            CliError::InvalidLength {
                what,
                expected,
                actual,
            } => write!(f, "Invalid {what}: expected {expected} bytes, got {actual}"),
            CliError::Unsupported(msg) => write!(f, "{msg}"),
            CliError::Io(err) => write!(f, "I/O error: {err}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<&'static str> for CliError {
    fn from(value: &'static str) -> Self {
        CliError::Business(value)
    }
}

impl From<std::io::Error> for CliError {
    fn from(value: std::io::Error) -> Self {
        CliError::Io(value)
    }
}

fn parse_hex_fixed<const N: usize>(input: &str, what: &'static str) -> Result<[u8; N], CliError> {
    let bytes = hex::decode(input.trim()).map_err(|_| CliError::InvalidHex { what })?;

    bytes
        .as_slice()
        .try_into()
        .map_err(|_| CliError::InvalidLength {
            what,
            expected: N,
            actual: bytes.len(),
        })
}

pub(crate) fn parse_root_seed(input: &str) -> Result<[u8; 64], CliError> {
    parse_hex_fixed::<64>(input, "root seed")
}

pub(crate) fn parse_seed_bytes(input: &str) -> Result<[u8; 17], CliError> {
    parse_hex_fixed::<17>(input, "entropy")
}

pub(crate) fn parse_public_key(input: &str) -> Result<MasterPublicKey, CliError> {
    let bytes = parse_hex_fixed::<33>(input, "public key")?;
    MasterPublicKey::try_from(bytes.as_slice()).map_err(CliError::from)
}

pub(crate) fn parse_chain_code(input: &str) -> Result<ChainCode, CliError> {
    let bytes = parse_hex_fixed::<32>(input, "chain code")?;
    ChainCode::try_from(bytes.as_slice()).map_err(CliError::from)
}

pub(crate) fn parse_mnemonic(input: &str) -> Result<[String; 12], CliError> {
    let words: Vec<String> = input.split_whitespace().map(str::to_owned).collect();
    let count = words.len();

    words.try_into().map_err(|_| {
        CliError::Unsupported(format!("Invalid mnemonic: expected 12 words, got {count}"))
    })
}

pub(crate) fn require_exactly_one_source(
    entropy_hex: &Option<String>,
    mnemonic: &Option<String>,
) -> Result<(), CliError> {
    match (entropy_hex.is_some(), mnemonic.is_some()) {
        (true, true) => Err(CliError::Unsupported(
            "Invalid combination of arguments: specify either <ENTROPY_HEX> or --mnemonic, not both".to_string(),
        )),
        (false, false) => Err(CliError::Unsupported(
            "Invalid combination of arguments: specify either <ENTROPY_HEX> or --mnemonic".to_string(),
        )),
        _ => Ok(()),
    }
}
