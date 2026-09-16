use k256::{SecretKey, elliptic_curve::sec1::ToSec1Point};

#[derive(Debug)]
pub(crate) struct MasterPrivateKey {
    inner: [u8; 32],
}

impl From<&[u8]> for MasterPrivateKey {
    fn from(slice: &[u8]) -> Self {
        Self {
            inner: slice.try_into().expect("slice must be 32 bytes"),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ChainCode {
    inner: [u8; 32],
}

impl From<&[u8]> for ChainCode {
    fn from(slice: &[u8]) -> Self {
        Self {
            inner: slice.try_into().expect("slice must be 32 bytes"),
        }
    }
}

#[derive(Debug)]
pub(crate) struct MasterPublicKey {
    inner: [u8; 33],
}

impl From<&MasterPrivateKey> for MasterPublicKey {
    fn from(private_key: &MasterPrivateKey) -> Self {
        let secret_key =
            SecretKey::from_slice(&private_key.inner).expect("invalid master private key");

        let public_key = secret_key.public_key();
        let encoded = public_key.to_sec1_point(true);

        Self {
            inner: encoded.as_bytes().try_into().unwrap(),
        }
    }
}
