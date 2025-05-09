//! Test vector generator for the `crypto_box` construction.

use hex_literal::hex;

// Alice's keypair
// const ALICE_SECRET_KEY: [u8; 32] =
//     hex!("68f208412d8dd5db9d0c6d18512e86f0ec75665ab841372d57b042b27ef89d4c");
const ALICE_PUBLIC_KEY: [u8; 32] =
    hex!("ac3a70ba35df3c3fae427a7c72021d68f2c1e044040b75f17313c0c8b5d4241d");

// Bob's keypair
const BOB_SECRET_KEY: [u8; 32] =
    hex!("b581fb5ae182a16f603f39270d4e3b95bc008310b727a11dd4e784a0044d461b");
// const BOB_PUBLIC_KEY: [u8; 32] =
//     hex!("e8980c86e032f1eb2975052e8d65bddd15c3b59641174ec9678a53789d92c754");

const NONCE: &[u8; 24] = &hex!("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37");

const PLAINTEXT: &[u8] = &[
    0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5, 0xcf, 0x14, 0x13, 0x16, 0xeb, 0xeb, 0x0c, 0x7b,
    0x52, 0x28, 0xc5, 0x2a, 0x4c, 0x62, 0xcb, 0xd4, 0x4b, 0x66, 0x84, 0x9b, 0x64, 0x24, 0x4f, 0xfc,
    0xe5, 0xec, 0xba, 0xaf, 0x33, 0xbd, 0x75, 0x1a, 0x1a, 0xc7, 0x28, 0xd4, 0x5e, 0x6c, 0x61, 0x29,
    0x6c, 0xdc, 0x3c, 0x01, 0x23, 0x35, 0x61, 0xf4, 0x1d, 0xb6, 0x6c, 0xce, 0x31, 0x4a, 0xdb, 0x31,
    0x0e, 0x3b, 0xe8, 0x25, 0x0c, 0x46, 0xf0, 0x6d, 0xce, 0xea, 0x3a, 0x7f, 0xa1, 0x34, 0x80, 0x57,
    0xe2, 0xf6, 0x55, 0x6a, 0xd6, 0xb1, 0x31, 0x8a, 0x02, 0x4a, 0x83, 0x8f, 0x21, 0xaf, 0x1f, 0xde,
    0x04, 0x89, 0x77, 0xeb, 0x48, 0xf5, 0x9f, 0xfd, 0x49, 0x24, 0xca, 0x1c, 0x60, 0x90, 0x2e, 0x52,
    0xf0, 0xa0, 0x89, 0xbc, 0x76, 0x89, 0x70, 0x40, 0xe0, 0x82, 0xf9, 0x37, 0x76, 0x38, 0x48, 0x64,
    0x5e, 0x07, 0x05,
];

const BOXZEROBYTES: usize = 16;

pub fn generate() {
    generate_xchacha20poly1305();
    generate_xchacha20poly1305_public_key_on_twist();
}

fn generate_xchacha20poly1305() {
    let mut ct = [42u8; BOXZEROBYTES + PLAINTEXT.len()];

    let ret = unsafe {
        libsodium_sys::crypto_box_curve25519xchacha20poly1305_easy(
            ct.as_mut_ptr(),
            PLAINTEXT.as_ptr(),
            PLAINTEXT.len() as u64,
            NONCE.as_ptr(),
            ALICE_PUBLIC_KEY.as_ptr(),
            BOB_SECRET_KEY.as_ptr(),
        )
    };
    assert_eq!(ret, 0);
    println!(
        "CHACHA20POLY1305_BOX_CIPHERTEXT: &[u8] = &hex!(\"{}\");",
        hex::encode(ct)
    );
}

fn generate_xchacha20poly1305_public_key_on_twist() {
    let alice_private_key: [u8; 32] =
        hex!("78d37f87f45e76aae3b61e0f0b69db96d117f8b5fd8edc73785b64918d2c9f47");
    let bob_public_key: [u8; 32] =
        hex!("9ec59406d5f9fde97a5c49acb935023ae40fae1499c05d3277cfb9100487e5b8");
    let nonce = hex!("979f38f433649e8aa1ad5a0334223f7c7dabc80231e8233a");
    const PLAINTEXT: [u8; 0] = [];
    let mut ct = [42u8; BOXZEROBYTES + PLAINTEXT.len()];

    let ret = unsafe {
        libsodium_sys::crypto_box_curve25519xchacha20poly1305_easy(
            ct.as_mut_ptr(),
            PLAINTEXT.as_ptr(),
            PLAINTEXT.len() as u64,
            nonce.as_ptr(),
            bob_public_key.as_ptr(),
            alice_private_key.as_ptr(),
        )
    };
    assert_eq!(ret, 0);
    println!(
        "CHACHA20POLY1305_BOX_CIPHERTEXT_PUBLIC_KEY_ON_TWIST: &[u8] = &hex!(\"{}\");",
        hex::encode(ct)
    );
}
