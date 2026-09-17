use hmac_sha512::HMAC;
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{ProjectivePoint, PublicKey, Scalar, SecretKey};

#[allow(unused)]
#[derive(Debug)]
pub(crate) struct MasterPrivateKey {
    inner: [u8; 32],
}

impl MasterPrivateKey {
    #[allow(unused)]
    pub(crate) fn from_root_seed(root_seed: &[u8; 64]) -> Result<(Self, ChainCode), &'static str> {
        let mac = HMAC::mac(b"Bitcoin seed", root_seed);

        let master_private_key = MasterPrivateKey::try_from(&mac[..32])?;
        let chain_code = ChainCode::try_from(&mac[32..])?;

        Ok((master_private_key, chain_code))
    }
}

impl TryFrom<&[u8]> for MasterPrivateKey {
    type Error = &'static str;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        let inner = slice
            .try_into()
            .map_err(|_| "master private key must be 32 bytes")?;

        Ok(Self { inner })
    }
}

#[allow(unused)]
#[derive(Debug, Clone)]
pub(crate) struct ChainCode {
    inner: [u8; 32],
}

impl ChainCode {
    #[allow(unused)]
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.inner
    }
}

impl TryFrom<&[u8]> for ChainCode {
    type Error = &'static str;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        let inner = slice
            .try_into()
            .map_err(|_| "chain code must be 32 bytes")?;

        Ok(Self { inner })
    }
}

#[allow(unused)]
#[derive(Debug, Clone)]
pub(crate) struct MasterPublicKey {
    inner: [u8; 33],
}

impl MasterPublicKey {
    pub(crate) fn bytes(&self) -> &[u8; 33] {
        &self.inner
    }

    #[allow(unused)]
    pub(crate) fn generate_child_key(
        &self,
        chaincode: &ChainCode,
        index: u32,
    ) -> Result<(MasterPublicKey, ChainCode), &'static str> {
        let mut data = [0u8; 37];

        data[..33].copy_from_slice(&self.inner);
        data[33..].copy_from_slice(&index.to_be_bytes());

        let mac = HMAC::mac(data, chaincode.bytes());
        let parent =
            PublicKey::from_sec1_bytes(&self.inner).map_err(|_| "invalid parent public key")?;

        let tweak_bytes: [u8; 32] = mac[..32].try_into().map_err(|_| "invalid HMAC output")?;
        let tweak = Scalar::from_repr(tweak_bytes.into())
            .into_option()
            .ok_or("invalid scalar derived from HMAC")?;

        let child = parent.to_projective() + ProjectivePoint::GENERATOR * tweak;
        let child =
            PublicKey::from_affine(child.to_affine()).map_err(|_| "invalid child public key")?;

        let public_key: MasterPublicKey = child
            .to_sec1_bytes()
            .as_ref()
            .try_into()
            .map_err(|_| "invalid child public key length")?;
        let chain_code: ChainCode = mac[32..]
            .try_into()
            .map_err(|_| "invalid chain code length")?;

        Ok((public_key, chain_code))
    }

    #[allow(unused)]
    pub(crate) fn generate_mth_0_child_key(
        &self,
        chaincode: &ChainCode,
        level: u32,
    ) -> Result<(MasterPublicKey, ChainCode), &'static str> {
        if level == 0 {
            return Ok((self.clone(), chaincode.clone()));
        }

        let (mut current_key, mut current_chaincode) = self.generate_child_key(chaincode, 0)?;
        for _ in 1..level {
            let (next_key, next_chaincode) =
                current_key.generate_child_key(&current_chaincode, 0)?;

            current_key = next_key;
            current_chaincode = next_chaincode;
        }

        Ok((current_key, current_chaincode))
    }

    #[allow(unused)]
    pub(crate) fn generate_nth_mth_0_child_key(
        &self,
        chaincode: &ChainCode,
        index: u32,
        level: u32,
    ) -> Result<(MasterPublicKey, ChainCode), &'static str> {
        if level == 0 {
            return self.generate_child_key(chaincode, index);
        }

        let (mpk, cc) = self.generate_mth_0_child_key(chaincode, level - 1)?;
        mpk.generate_child_key(&cc, index)
    }
}

impl TryFrom<&MasterPrivateKey> for MasterPublicKey {
    type Error = &'static str;

    fn try_from(private_key: &MasterPrivateKey) -> Result<Self, Self::Error> {
        let secret_key =
            SecretKey::from_slice(&private_key.inner).map_err(|_| "invalid master private key")?;

        let public_key = secret_key.public_key();
        let encoded = public_key.to_sec1_point(true);

        let inner: [u8; 33] = encoded
            .as_bytes()
            .try_into()
            .map_err(|_| "invalid public key length")?;

        Ok(Self { inner })
    }
}

impl TryFrom<&[u8]> for MasterPublicKey {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let inner: [u8; 33] = bytes
            .as_ref()
            .try_into()
            .map_err(|_| "master public key must be 33 bytes")?;

        Ok(Self { inner })
    }
}
