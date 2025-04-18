//! `crypto_box` test vectors
//!
//! Adapted from PHP Sodium Compat's test vectors:
//! <https://www.phpclasses.org/browse/file/122796.html>

#![cfg(all(
    any(feature = "chacha20", feature = "salsa20"),
    feature = "getrandom",
    feature = "std"
))]

use crypto_box::{
    aead::{generic_array::GenericArray, Aead, AeadInPlace, OsRng},
    PublicKey, SecretKey,
};
use curve25519_dalek::EdwardsPoint;
use hex_literal::hex;

// Alice's keypair
const ALICE_SECRET_KEY: [u8; 32] =
    hex!("68f208412d8dd5db9d0c6d18512e86f0ec75665ab841372d57b042b27ef89d4c");
const ALICE_PUBLIC_KEY: [u8; 32] =
    hex!("ac3a70ba35df3c3fae427a7c72021d68f2c1e044040b75f17313c0c8b5d4241d");

// Bob's keypair
const BOB_SECRET_KEY: [u8; 32] =
    hex!("b581fb5ae182a16f603f39270d4e3b95bc008310b727a11dd4e784a0044d461b");
const BOB_PUBLIC_KEY: [u8; 32] =
    hex!("e8980c86e032f1eb2975052e8d65bddd15c3b59641174ec9678a53789d92c754");

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

#[test]
fn generate_secret_key() {
    SecretKey::generate(&mut OsRng);
}

#[test]
fn secret_and_public_keys() {
    let secret_key = SecretKey::from(ALICE_SECRET_KEY);
    assert_eq!(secret_key.to_bytes(), ALICE_SECRET_KEY);

    // Ensure `Debug` impl on `SecretKey` is covered in tests
    dbg!(&secret_key);

    assert_eq!(secret_key.public_key().as_bytes(), &ALICE_PUBLIC_KEY);
}

#[test]
fn edwards_to_montgomery() {
    let secret_key = SecretKey::from(ALICE_SECRET_KEY);
    let scalar = secret_key.to_scalar();
    let point = EdwardsPoint::mul_base(&scalar);
    let public_key = PublicKey::from(point.to_montgomery());
    assert_eq!(secret_key.public_key(), public_key);
    assert_eq!(secret_key, SecretKey::from(scalar));
}

macro_rules! impl_tests {
    ($box:ty, $plaintext:expr, $ciphertext:expr) => {
        #[test]
        fn encrypt() {
            let secret_key = SecretKey::from(ALICE_SECRET_KEY);
            let public_key = PublicKey::from(BOB_PUBLIC_KEY);
            let nonce = GenericArray::from_slice(NONCE);

            let ciphertext = <$box>::new(&public_key, &secret_key)
                .encrypt(nonce, $plaintext)
                .unwrap();

            assert_eq!($ciphertext, &ciphertext[..]);
        }

        #[test]
        fn encrypt_in_place_detached() {
            let secret_key = SecretKey::from(ALICE_SECRET_KEY);
            let public_key = PublicKey::from(BOB_PUBLIC_KEY);
            let nonce = GenericArray::from_slice(NONCE);
            let mut buffer = $plaintext.to_vec();

            let tag = <$box>::new(&public_key, &secret_key)
                .encrypt_in_place_detached(nonce, b"", &mut buffer)
                .unwrap();

            let (expected_tag, expected_ciphertext) = $ciphertext.split_at(16);
            assert_eq!(expected_tag, &tag[..]);
            assert_eq!(expected_ciphertext, &buffer[..]);
        }

        #[test]
        fn decrypt() {
            let secret_key = SecretKey::from(BOB_SECRET_KEY);
            let public_key = PublicKey::from(ALICE_PUBLIC_KEY);
            let nonce = GenericArray::from_slice(NONCE);

            let plaintext = <$box>::new(&public_key, &secret_key)
                .decrypt(nonce, $ciphertext)
                .unwrap();

            assert_eq!($plaintext, &plaintext[..]);
        }

        #[test]
        fn decrypt_in_place_detached() {
            let secret_key = SecretKey::from(BOB_SECRET_KEY);
            let public_key = PublicKey::from(ALICE_PUBLIC_KEY);
            let nonce = GenericArray::from_slice(NONCE);
            let tag = GenericArray::clone_from_slice(&$ciphertext[..16]);
            let mut buffer = $ciphertext[16..].to_vec();

            <$box>::new(&public_key, &secret_key)
                .decrypt_in_place_detached(nonce, b"", &mut buffer, &tag)
                .unwrap();

            assert_eq!($plaintext, &buffer[..]);
        }
    };
}

#[cfg(feature = "salsa20")]
mod xsalsa20poly1305 {
    use super::*;
    use crypto_box::SalsaBox;
    const CIPHERTEXT: &[u8] = &[
        0xc0, 0x3f, 0x27, 0xd1, 0x88, 0xef, 0x65, 0xc, 0xd1, 0x29, 0x36, 0x91, 0x31, 0x37, 0xbb,
        0x17, 0xed, 0x4c, 0x98, 0xc2, 0x64, 0x89, 0x39, 0xe2, 0xe1, 0xd2, 0xe8, 0x55, 0x47, 0xa,
        0x7b, 0x8c, 0x63, 0x2c, 0xab, 0xfd, 0x5a, 0xb3, 0xb3, 0xc2, 0xd3, 0x13, 0xdc, 0x8c, 0x9e,
        0xcf, 0x5d, 0xa1, 0x73, 0xe1, 0xf9, 0xc3, 0x18, 0xcd, 0xef, 0x1d, 0xce, 0xd6, 0xd2, 0x51,
        0x9e, 0x69, 0x50, 0x85, 0xe6, 0xb5, 0xc4, 0x1, 0xa2, 0xbd, 0x53, 0x31, 0x44, 0x29, 0x86,
        0xc7, 0x7, 0x6d, 0x41, 0x26, 0x25, 0x49, 0x7c, 0x4c, 0xb2, 0xfd, 0x94, 0xc6, 0xf1, 0x3,
        0x96, 0x10, 0x33, 0xb2, 0xc9, 0x30, 0xd7, 0xe8, 0x2e, 0x3, 0x41, 0xf2, 0x9d, 0x38, 0x79,
        0xbd, 0x6a, 0xb9, 0xd8, 0x81, 0xea, 0x3a, 0x1f, 0x36, 0x5d, 0x63, 0x4e, 0x65, 0x3c, 0x6e,
        0x17, 0x1a, 0xac, 0x7f, 0xc1, 0xe7, 0x69, 0x34, 0xd2, 0x3b, 0xe6, 0xf0, 0x4a, 0x54, 0x1,
        0x8, 0x8, 0xdb, 0xf0, 0xf9, 0xbd, 0x30, 0xf6, 0x3b, 0x68, 0xd0, 0x26,
    ];

    impl_tests!(SalsaBox, PLAINTEXT, CIPHERTEXT);
}

#[cfg(feature = "chacha20")]
mod xchacha20poly1305 {
    use super::*;
    use aead::Nonce;
    use crypto_box::ChaChaBox;
    const CIPHERTEXT: &[u8] = &hex!(
        "0cd5ed093de698c8e410d0d451df2f5283057376b947b9b7392b956e5d675f309218acce8cf85f6c"
        "f6a9e2e09ef8c5b0f97c661ee21b1b3418be566692634056a92b4034d5d0cf14c52420a488b7f0da"
        "0c5740dfc6b85397d3a8f679e84303e8d3f8b048abdb2dd79183b0a62683a1bc2a527fc9b82c5ffa"
        "c4a684bcfeadfdcd28930b2dbe597f4716a658ccfca5b44049e06c"
    );

    impl_tests!(ChaChaBox, PLAINTEXT, CIPHERTEXT);

    /// Implement test against shared secret being all zero
    #[test]
    fn test_public_key_on_twist() {
        let alice_private_key: [u8; 32] =
            hex!("78d37f87f45e76aae3b61e0f0b69db96d117f8b5fd8edc73785b64918d2c9f47");
        let bob_public_key: [u8; 32] =
            hex!("9ec59406d5f9fde97a5c49acb935023ae40fae1499c05d3277cfb9100487e5b8");
        let nonce = hex!("979f38f433649e8aa1ad5a0334223f7c7dabc80231e8233a");
        let plaintext: &[u8] = &[];
        let ciphertext_expected = hex!("171e01986d83c429a2746212464d6782");

        let ciphertext_computed = ChaChaBox::new(&bob_public_key.into(), &alice_private_key.into())
            .encrypt(Nonce::<ChaChaBox>::from_slice(&nonce), plaintext)
            .expect("Encryption should work");

        assert_eq!(ciphertext_computed, ciphertext_expected)
    }
}

#[cfg(feature = "seal")]
#[test]
fn seal() {
    const SEAL_SECRET_KEY: [u8; 32] = [
        0x15, 0xb3, 0x6c, 0xb0, 0x02, 0x13, 0x37, 0x3f, 0xb3, 0xfb, 0x03, 0x95, 0x8f, 0xb0, 0xcc,
        0x00, 0x12, 0xec, 0xac, 0xa1, 0x12, 0xfd, 0x24, 0x9d, 0x3c, 0xf0, 0x96, 0x1e, 0x31, 0x1c,
        0xaa, 0xc9,
    ];

    const SEAL_PUBLIC_KEY: [u8; 32] = [
        0xfb, 0x4c, 0xb3, 0x4f, 0x74, 0xa9, 0x28, 0xb7, 0x91, 0x23, 0x33, 0x3c, 0x1e, 0x63, 0xd9,
        0x91, 0x06, 0x02, 0x44, 0xcd, 0xa9, 0x8a, 0xff, 0xee, 0x14, 0xc3, 0x39, 0x8c, 0x6d, 0x31,
        0x55, 0x74,
    ];

    const SEAL_PLAINTEXT: &[u8] =
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.".as_bytes();

    const SEAL_CIPHERTEXT: &[u8] = &[
        0x95, 0xeb, 0x5b, 0xf0, 0x5a, 0xda, 0x25, 0xee, 0x51, 0xf4, 0x15, 0x82, 0x01, 0xc2, 0x61,
        0xa0, 0x0b, 0xfb, 0x19, 0x55, 0xa9, 0x17, 0x6c, 0x8c, 0x7f, 0x1a, 0x62, 0xf2, 0x99, 0xa3,
        0x2e, 0x54, 0xf6, 0xeb, 0xcc, 0xc8, 0xab, 0x9d, 0x2c, 0xe1, 0xb1, 0xd3, 0x71, 0x0b, 0xa3,
        0x7d, 0x8d, 0xb1, 0x7a, 0xee, 0xec, 0x0b, 0x78, 0xfc, 0x3d, 0x32, 0xb3, 0x9b, 0x79, 0xed,
        0x96, 0xf1, 0x89, 0x48, 0xc5, 0xa5, 0x74, 0xb8, 0xe3, 0xf8, 0xec, 0xcc, 0x2f, 0x13, 0x24,
        0x08, 0xc2, 0x16, 0x46, 0xf3, 0xae, 0xda, 0xe4, 0xa6, 0x7f, 0xde, 0x4f, 0x77, 0x15, 0x3b,
        0x54, 0x58, 0xb8, 0xa6, 0xbd, 0x71, 0x2d, 0xd8, 0x36, 0x55, 0x34, 0xc5, 0x67, 0xec,
    ];

    let pk = PublicKey::from(SEAL_PUBLIC_KEY);
    let encrypted = pk.seal(&mut OsRng, SEAL_PLAINTEXT).unwrap();

    let sk = SecretKey::from(SEAL_SECRET_KEY);
    assert_eq!(SEAL_PLAINTEXT, sk.unseal(&encrypted).unwrap());
    assert_eq!(SEAL_PLAINTEXT, sk.unseal(SEAL_CIPHERTEXT).unwrap());
}
