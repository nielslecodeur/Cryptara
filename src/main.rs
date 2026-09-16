mod seedforge;

use seedforge::Seed;

fn main() {
    let bytes = Seed::generate();
    let words = bytes.as_words().unwrap();
    let bytes_verif = Seed::from_words(&words).unwrap();

    assert!(
        bytes == bytes_verif,
        "bytes = {:?}, bytes_verif = {:?}",
        bytes,
        bytes_verif
    );
}
