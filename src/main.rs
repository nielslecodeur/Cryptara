mod seedforge;

use seedforge::Seed;

fn main() {
    let bytes = Seed::generate();
    println!("{:?}", bytes.as_words().unwrap());
}
