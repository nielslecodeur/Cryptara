use std::ffi::{CStr, CString, c_char};

unsafe extern "C" {
    fn get_bytes_ptr(out: *mut u8);
    fn get_words(bytes: *const u8, out: *mut *const c_char) -> bool;
    fn get_bytes_from_words(words: *const *const c_char, out: *mut u8) -> bool;
}

#[derive(Debug)]
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
            if raw_words[i].is_null() {
                String::new()
            } else {
                CStr::from_ptr(raw_words[i]).to_string_lossy().into_owned()
            }
        });

        Ok(words)
    }

    pub(crate) fn from_words(words: &[String; 12]) -> Result<Self, &'static str> {
        let c_words: Vec<CString> = words
            .iter()
            .map(|word| CString::new(word.as_str()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "Invalid BIP-39 word")?;

        let word_ptrs: [*const c_char; 12] = std::array::from_fn(|i| c_words[i].as_ptr());
        let mut bytes = [0u8; 17];

        let success = unsafe { get_bytes_from_words(word_ptrs.as_ptr(), bytes.as_mut_ptr()) };
        if !success {
            return Err("Failed to get bytes from BIP-39 words");
        }

        Ok(Self { inner: bytes })
    }
}

impl PartialEq for Seed {
    fn eq(&self, other: &Seed) -> bool {
        self.inner == other.inner
    }
}

impl Eq for Seed {}
