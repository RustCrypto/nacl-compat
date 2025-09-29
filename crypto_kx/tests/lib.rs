use crypto_kx::*;
use rand_core::{OsRng, TryRngCore};

#[test]
fn client_keys_is_reverse_from_server_keys() {
    let client = Keypair::generate(&mut OsRng.unwrap_err());
    let server = Keypair::generate(&mut OsRng.unwrap_err());

    let client_keys = client.session_keys_to(server.public());
    let server_keys = server.session_keys_from(client.public());

    assert_eq!(client_keys.tx.as_ref(), server_keys.rx.as_ref());
    assert_eq!(client_keys.rx.as_ref(), server_keys.tx.as_ref());
}
