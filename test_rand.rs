use rand::Rng;

fn main() {
    let mut rng = rand::rng();
    let n: [u8; 24] = rng.random();
    let port = rng.random_range(49154..65533);
}
