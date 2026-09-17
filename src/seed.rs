use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;
use std::ffi::{CStr, CString, c_char};

use crate::ffi;

#[allow(unused)]
pub(crate) struct Seed {
    entropy: [u8; 16],
    checksum: [bool; 4],
}

impl Seed {
    #[allow(unused)]
    pub(crate) fn generate() -> Self {
        let mut bytes = [0u8; 17];
        unsafe {
            ffi::get_bytes_ptr(bytes.as_mut_ptr());
        }

        Self::from_bytes(&bytes)
    }

    #[allow(unused)]
    pub(crate) fn from_bytes(bytes: &[u8; 17]) -> Self {
        let entropy: [u8; 16] = bytes[..16].try_into().unwrap();

        let last = bytes[16];
        let checksum = [
            (last & 0b1000_0000) != 0,
            (last & 0b0100_0000) != 0,
            (last & 0b0010_0000) != 0,
            (last & 0b0001_0000) != 0,
        ];

        Self { entropy, checksum }
    }

    #[allow(unused)]
    pub(crate) fn as_bytes(&self) -> [u8; 17] {
        let mut bytes = [0u8; 17];

        bytes[..16].copy_from_slice(&self.entropy);
        bytes[16] = ((self.checksum[0] as u8) << 7)
            | ((self.checksum[1] as u8) << 6)
            | ((self.checksum[2] as u8) << 5)
            | ((self.checksum[3] as u8) << 4);

        bytes
    }

    #[allow(unused)]
    pub(crate) fn words(&self) -> Result<[String; 12], &'static str> {
        let mut raw_words: [*const c_char; 12] = [std::ptr::null(); 12];

        let success = unsafe { ffi::get_words(self.as_bytes().as_ptr(), raw_words.as_mut_ptr()) };
        if !success {
            return Err("Failed to get BIP-39 words");
        }

        let words = std::array::from_fn(|i| unsafe {
            if raw_words[i].is_null() {
                String::new()
            } else {
                CStr::from_ptr(raw_words[i]).to_string_lossy().into_owned()
            }
        });

        Ok(words)
    }

    #[allow(unused)]
    pub(crate) fn from_words(words: &[String; 12]) -> Result<Self, &'static str> {
        let c_words: Vec<CString> = words
            .iter()
            .map(|word| CString::new(word.as_str()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "Invalid BIP-39 word")?;

        let word_ptrs: [*const c_char; 12] = std::array::from_fn(|i| c_words[i].as_ptr());
        let mut bytes = [0u8; 17];

        let success = unsafe { ffi::get_bytes_from_words(word_ptrs.as_ptr(), bytes.as_mut_ptr()) };
        if !success {
            return Err("Failed to get bytes from BIP-39 words");
        }

        Ok(Self::from_bytes(&bytes))
    }

    #[allow(unused)]
    pub(crate) fn root_seed(&self, passphrase: Option<&[u8]>) -> Result<[u8; 64], &'static str> {
        let words = self.words()?;
        let mnemonic = words.join(" ");

        let passphrase = passphrase.unwrap_or(b"");

        let mut salt = Vec::with_capacity(8 + passphrase.len());
        salt.extend_from_slice(b"mnemonic");
        salt.extend_from_slice(passphrase);

        let mut seed = [0u8; 64];
        pbkdf2_hmac::<Sha512>(mnemonic.as_bytes(), &salt, 2048, &mut seed);

        Ok(seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip39_root_seed() {
        let words = [
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "abandon".to_string(),
            "about".to_string(),
        ];

        let seed = Seed::from_words(&words).unwrap();
        let root_seed = seed.root_seed(Some(b"TREZOR")).unwrap();

        let expected = hex::decode(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        ).unwrap();

        assert_eq!(root_seed.to_vec(), expected);
    }
}
