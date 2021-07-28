use crypto_secretstream::*;
use rand_core::OsRng;

const PLAINTEXT: &[u8] = b"personal privacy is paramount";
const ASSOCIATED_DATA: &[u8] = b"beware of giving it away";

#[test]
fn two_pushstreams_dont_generate_same_ciphertext() {
    let key = Key::generate(&mut OsRng);

    let (_, mut first_stream) = PushStream::init(&mut rand_core::OsRng, &key);
    let (_, mut second_stream) = PushStream::init(&mut rand_core::OsRng, &key);

    let first_ciphertext = first_stream
        .push(PLAINTEXT, ASSOCIATED_DATA, Tag::Message)
        .expect("push in first stream");
    let second_ciphertext = second_stream
        .push(PLAINTEXT, ASSOCIATED_DATA, Tag::Message)
        .expect("push in second stream");

    assert_ne!(first_ciphertext, second_ciphertext);
}

#[test]
fn pushstream_doesnt_generate_same_ciphertext_for_same_plaintext() {
    let key = Key::generate(&mut OsRng);

    let (_, mut stream) = PushStream::init(&mut rand_core::OsRng, &key);

    let first_ciphertext = stream
        .push(PLAINTEXT, ASSOCIATED_DATA, Tag::Message)
        .expect("first push");
    let second_ciphertext = stream
        .push(PLAINTEXT, ASSOCIATED_DATA, Tag::Message)
        .expect("second push");

    assert_ne!(first_ciphertext, second_ciphertext);
}

#[test]
fn pushed_can_be_pulled() {
    let key = Key::generate(&mut OsRng);

    let (header, mut push_stream) = PushStream::init(&mut rand_core::OsRng, &key);
    let mut pull_stream = PullStream::init(header, &key);

    let ciphertext = push_stream
        .push(PLAINTEXT, ASSOCIATED_DATA, Tag::Message)
        .expect("push in stream");
    let (tag, plaintext) = pull_stream
        .pull(&ciphertext, ASSOCIATED_DATA)
        .expect("pull in stream");

    assert_eq!(Tag::Message, tag);
    assert_eq!(PLAINTEXT, plaintext);
}
