mod crypto_box;
mod crypto_secretbox;

fn main() {
    crypto_box::generate();
    crypto_secretbox::generate();
}
