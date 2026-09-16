use std::ffi::{CStr, c_char};

unsafe extern "C" {
    fn get_bytes_ptr(out: *mut u8);
    fn get_words(bytes: *const u8, out: *mut *const c_char) -> bool;
}

pub(crate) struct Seed {
    inner: [u8; 17],
}

impl Seed {
    pub(crate) fn generate() -> Self {
        let mut bytes = [0u8; 17];

        unsafe {
            get_bytes_ptr(bytes.as_mut_ptr());
        }

        Self { inner: bytes }
    }

    pub(crate) fn as_words(&self) -> Result<[String; 12], &'static str> {
        let mut raw_words: [*const c_char; 12] = [std::ptr::null(); 12];

        let success = unsafe { get_words(self.inner.as_ptr(), raw_words.as_mut_ptr()) };
        if !success {
            return Err("Failed to get BIP-39 words");
        }

        let words = std::array::from_fn(|i| unsafe {
            CStr::from_ptr(raw_words[i]).to_string_lossy().into_owned()
        });

        Ok(words)
    }
}
