use std::ffi::c_char;

unsafe extern "C" {
    pub(crate) fn get_bytes_ptr(out: *mut u8);
    pub(crate) fn get_words(bytes: *const u8, out: *mut *const c_char) -> bool;
    pub(crate) fn get_bytes_from_words(words: *const *const c_char, out: *mut u8) -> bool;
}
