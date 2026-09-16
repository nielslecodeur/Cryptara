mod key;
mod seedforge;

use seedforge::Seed;

use crate::key::MasterPublicKey;

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

    let (mpk, cc) = bytes.extract_keys();
    println!("Master Private Key: {mpk:?}, Chain Code: {cc:?}");

    let master_public_key = MasterPublicKey::from(&mpk);
    println!("Master Public Key: {master_public_key:?}");

    let (child_public_key, child_chain_code) = master_public_key.generate_child_key(cc);

    println!("Child Public Key: {child_public_key:?}");
    println!("Child Chain Code: {child_chain_code:?}");
}
