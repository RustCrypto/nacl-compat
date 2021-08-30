use crypto_secretstream::*;
use rand_core::OsRng;

const PLAINTEXT: &[u8] = b"personal privacy is paramount";
const ASSOCIATED_DATA: &[u8] = b"beware of giving it away";

#[test]
#[cfg(feature = "heapless")]
fn two_pushstreams_dont_generate_same_ciphertext() {
    use aead::heapless::Vec;

    let key = Key::generate(&mut OsRng);

    let (_, mut first_stream) = PushStream::init(&mut rand_core::OsRng, &key);
    let (_, mut second_stream) = PushStream::init(&mut rand_core::OsRng, &key);

    let mut first_ciphertext = Vec::<u8, 256>::from_slice(PLAINTEXT).expect("create first vec");
    first_stream
        .push(&mut first_ciphertext, ASSOCIATED_DATA, Tag::Message)
        .expect("push in first stream");

    let mut second_ciphertext = Vec::<u8, 256>::from_slice(PLAINTEXT).expect("create second vec");
    second_stream
        .push(&mut second_ciphertext, ASSOCIATED_DATA, Tag::Message)
        .expect("push in second stream");

    assert_ne!(first_ciphertext, second_ciphertext);
}

#[test]
#[cfg(feature = "alloc")]
fn pushstream_doesnt_generate_same_ciphertext_for_same_plaintext() {
    let key = Key::generate(&mut OsRng);

    let (_, mut stream) = PushStream::init(&mut rand_core::OsRng, &key);

    let mut first_ciphertext = Vec::from(PLAINTEXT);
    stream
        .push(&mut first_ciphertext, ASSOCIATED_DATA, Tag::Message)
        .expect("first push");

    let mut second_ciphertext = Vec::from(PLAINTEXT);
    stream
        .push(&mut second_ciphertext, ASSOCIATED_DATA, Tag::Message)
        .expect("second push");

    assert_ne!(first_ciphertext, second_ciphertext);
}

#[test]
#[cfg(feature = "alloc")]
fn pushed_can_be_pulled() {
    let key = Key::generate(&mut OsRng);

    let (header, mut push_stream) = PushStream::init(&mut rand_core::OsRng, &key);
    let mut pull_stream = PullStream::init(header, &key);

    let mut message = Vec::from(PLAINTEXT);
    push_stream
        .push(&mut message, ASSOCIATED_DATA, Tag::Message)
        .expect("push in stream");
    let tag = pull_stream
        .pull(&mut message, ASSOCIATED_DATA)
        .expect("pull in stream");

    assert_eq!(Tag::Message, tag);
    assert_eq!(PLAINTEXT, message);
}
