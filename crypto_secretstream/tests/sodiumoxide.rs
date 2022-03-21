#[cfg(feature = "alloc")]
use crypto_secretstream::*;
use sodiumoxide::crypto::secretstream as reference;

#[cfg(feature = "alloc")]
const MESSAGES: [(&[u8], Tag, &[u8]); 5] = [
    (b"you are", Tag::Message, &[1, 2, 3]),
    (b"a beautiful", Tag::Message, &[]),
    (b"human being", Tag::Rekey, &[4, 5, 6]),
    (b"you deserve", Tag::Message, &[7, 8, 9]),
    (b"love and affection", Tag::Final, &[]),
];

#[test]
#[cfg(feature = "alloc")]
fn pushed_can_be_pulled() {
    use rand_core::OsRng;

    let key = Key::generate(&mut OsRng);

    let (header, mut push_stream) = PushStream::init(&mut OsRng, &key);

    let header = reference::Header::from_slice(header.as_ref()).expect("create Header");
    let key = reference::Key::from_slice(key.as_ref()).expect("create Key");
    let mut pull_stream = reference::Stream::init_pull(&header, &key).expect("create Stream");

    MESSAGES.iter().for_each(|(message, tag, additional_data)| {
        let mut ciphertext = Vec::from(*message);
        push_stream
            .push(&mut ciphertext, additional_data, *tag)
            .expect("push in stream");

        let (cleartext, pulled_tag) = pull_stream
            .pull(&mut ciphertext, Some(additional_data))
            .expect("to pull from Stream");

        assert_eq!(*tag as u8, pulled_tag as u8);
        assert_eq!(*message, cleartext);
    });
}

#[test]
#[cfg(feature = "alloc")]
fn pulled_can_be_pushed() {
    let key = reference::gen_key();
    let (mut push_stream, header) = reference::Stream::init_push(&key).expect("create Stream");
    let header = Header::try_from(header.as_ref()).expect("same header size");
    let key = Key::try_from(key.as_ref()).expect("same key size");
    let mut pull_stream = PullStream::init(header, &key);

    MESSAGES.iter().for_each(|(message, tag, additional_data)| {
        let reference_tag = match *tag {
            Tag::Message => reference::Tag::Message,
            Tag::Rekey => reference::Tag::Rekey,
            Tag::Push => reference::Tag::Push,
            Tag::Final => reference::Tag::Final,
        };

        let mut ciphertext = push_stream
            .push(message, Some(additional_data), reference_tag)
            .expect("push in stream");

        let pulled_tag = pull_stream
            .pull(&mut ciphertext, additional_data)
            .expect("to pull from Stream");

        assert_eq!(*tag as u8, pulled_tag as u8);
        assert_eq!(*message, ciphertext);
    });
}
