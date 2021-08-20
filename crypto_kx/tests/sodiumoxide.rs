use std::convert::TryFrom;

use crypto_kx::*;
use rand_core::OsRng;
use sodiumoxide::crypto::kx as reference;

#[test]
fn same_publickey_constructed_from_secretkey() {
    let keypair = reference::gen_keypair();

    let reconstructed_keypair = KeyPair::from(
        SecretKey::try_from(keypair.1.as_ref()).expect("parse reference's secret key"),
    );

    assert_eq!(keypair.0.as_ref(), reconstructed_keypair.public().as_ref());
}

#[test]
fn same_client_keys() {
    let (client_pk, client_sk) = reference::gen_keypair();
    let server = KeyPair::generate(OsRng);
    let server_pk = server.public();

    let reference_keys = reference::client_session_keys(
        &client_pk,
        &client_sk,
        &reference::PublicKey(server_pk.as_ref().to_owned()),
    )
    .expect("generate reference's session's keys");

    let client = KeyPair::from(SecretKey::from(client_sk.0));
    let keys = client.session_keys_to(server_pk);

    assert_eq!(reference_keys.0.as_ref(), &keys.tx.as_ref()[..]);
    assert_eq!(reference_keys.1.as_ref(), &keys.rx.as_ref()[..]);
}

#[test]
fn same_server_keys() {
    let server = KeyPair::generate(OsRng);
    let (client_pk, _) = reference::gen_keypair();

    let reference_keys = reference::server_session_keys(
        &reference::PublicKey(server.public().as_ref().to_owned()),
        &reference::SecretKey(server.secret().to_bytes()),
        &client_pk,
    )
    .expect("generate reference's session's keys");

    let keys = server.session_keys_from(
        &PublicKey::try_from(client_pk.as_ref()).expect("parse reference's public key"),
    );

    assert_eq!(reference_keys.0.as_ref(), &keys.tx.as_ref()[..]);
    assert_eq!(reference_keys.1.as_ref(), &keys.rx.as_ref()[..]);
}
