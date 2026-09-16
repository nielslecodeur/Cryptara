use hmac_sha512::HMAC;
use k256::{
    ProjectivePoint, PublicKey, Scalar, SecretKey,
    elliptic_curve::{PrimeField, sec1::ToSec1Point},
};

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

impl ChainCode {
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.inner
    }
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

impl MasterPublicKey {
    pub(crate) fn generate_child_key(&self, chaincode: ChainCode) -> (MasterPublicKey, ChainCode) {
        let mut data = [0u8; 37];

        data[..33].copy_from_slice(&self.inner);
        data[33..].copy_from_slice(&1u32.to_be_bytes());

        let mac = HMAC::mac(data, chaincode.bytes());

        let parent = PublicKey::from_sec1_bytes(&self.inner).unwrap();
        let tweak = Scalar::from_repr(mac[..32].try_into().unwrap()).unwrap();

        let child = parent.to_projective() + ProjectivePoint::GENERATOR * tweak;
        let child = PublicKey::from_affine(child.to_affine()).unwrap();

        (
            MasterPublicKey::from(child.to_sec1_bytes()),
            ChainCode::from(&mac[32..]),
        )
    }
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

impl From<Box<[u8]>> for MasterPublicKey {
    fn from(bytes: Box<[u8]>) -> Self {
        Self {
            inner: bytes.as_ref().try_into().unwrap(),
        }
    }
}
