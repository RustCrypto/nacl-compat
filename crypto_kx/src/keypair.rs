use blake2::{digest::generic_array::sequence::Split, Blake2b512, Digest};
use rand_core::{CryptoRng, RngCore};

use crate::{ClientSessionKeys, PublicKey, SecretKey, ServerSessionKeys, SessionKey};

/// A [`SecretKey`] with its related [`PublicKey`].
#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(our_serde::Deserialize, our_serde::Serialize)
)]
#[cfg_attr(feature = "serde", serde(crate = "our_serde"))]
pub struct KeyPair {
    secret: SecretKey,
    public: PublicKey,
}

impl KeyPair {
    /// Generate a new random [`KeyPair`].
    pub fn generate(csprng: impl RngCore + CryptoRng) -> Self {
        let secret = SecretKey::generate(csprng);

        Self::from(secret)
    }

    /// Get the contained [`PublicKey`].
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// Get the contained [`SecretKey`].
    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    /// Consume the [`KeyPair`] to extract the contained [`SecretKey`] & [`PublicKey`].
    pub fn split(self) -> (PublicKey, SecretKey) {
        (self.public, self.secret)
    }

    /// Compute the keys for the one opening the connection.
    ///
    /// It's the implementation of libsodium's `crypto_kx_client_session_keys`.
    pub fn session_keys_to(&self, server_pk: &PublicKey) -> ClientSessionKeys {
        let (tx, rx) = self.gen_session_keys(server_pk, &self.public, server_pk);

        ClientSessionKeys { tx, rx }
    }

    /// Compute the keys for the one receiving the connection.
    ///
    /// It's the implementation of libsodium's `crypto_kx_server_session_keys`.
    pub fn session_keys_from(&self, client_pk: &PublicKey) -> ServerSessionKeys {
        let (rx, tx) = self.gen_session_keys(client_pk, client_pk, &self.public);

        ServerSessionKeys { tx, rx }
    }

    fn gen_session_keys(
        &self,
        other_pubkey: &PublicKey,
        client_pk: &PublicKey,
        server_pk: &PublicKey,
    ) -> (SessionKey, SessionKey) {
        debug_assert!(other_pubkey == client_pk || other_pubkey == server_pk);

        let shared_secret = self
            .secret
            .as_dalek()
            .diffie_hellman(other_pubkey.as_dalek());

        let mut hasher = Blake2b512::new();

        hasher.update(shared_secret.as_bytes());
        hasher.update(client_pk.as_ref());
        hasher.update(server_pk.as_ref());

        let (rx, tx) = hasher.finalize().split();
        let (rx, tx): ([u8; SessionKey::BYTES], [u8; SessionKey::BYTES]) = (rx.into(), tx.into());
        (SessionKey::from(rx), SessionKey::from(tx))
    }
}

impl From<SecretKey> for KeyPair {
    fn from(secret: SecretKey) -> Self {
        let public_dalek = x25519_dalek::PublicKey::from(secret.as_dalek());
        let public = PublicKey::from(public_dalek.to_bytes());

        Self { secret, public }
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn from_secretkey_yield_same() {
        let keypair = KeyPair::generate(&mut OsRng);

        let reconstructed_keypair =
            KeyPair::from(SecretKey::from(keypair.secret().as_dalek().to_bytes()));

        assert_eq!(
            keypair.public().as_ref(),
            reconstructed_keypair.public().as_ref(),
        );
        assert_eq!(
            keypair.secret().as_dalek().to_bytes(),
            reconstructed_keypair.secret().as_dalek().to_bytes(),
        );
    }
}
