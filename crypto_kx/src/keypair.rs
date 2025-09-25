use blake2::{digest::generic_array::sequence::Split, Blake2b512, Digest};
use rand_core::CryptoRng;

use crate::{ClientSessionKeys, PublicKey, SecretKey, ServerSessionKeys, SessionKey};

/// A [`SecretKey`] with its related [`PublicKey`].
pub struct Keypair {
    secret: SecretKey,
    public: PublicKey,
}

impl Keypair {
    /// Generate a new random [`Keypair`].
    pub fn generate(csprng: &mut impl CryptoRng) -> Self {
        SecretKey::generate(csprng).into()
    }

    /// Get the contained [`PublicKey`].
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// Get the contained [`SecretKey`].
    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    /// Consume the [`Keypair`] to extract the contained [`SecretKey`] & [`PublicKey`].
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

        // Elliptic Curve Diffie-Hellman
        let shared_secret = other_pubkey.0.mul_clamped(self.secret.0);

        let mut hasher = Blake2b512::new();

        hasher.update(shared_secret.as_bytes());
        hasher.update(client_pk.as_ref());
        hasher.update(server_pk.as_ref());

        let (rx, tx) = hasher.finalize().split();
        let (rx, tx): ([u8; SessionKey::BYTES], [u8; SessionKey::BYTES]) = (rx.into(), tx.into());
        (SessionKey::from(rx), SessionKey::from(tx))
    }
}

impl From<SecretKey> for Keypair {
    fn from(secret: SecretKey) -> Self {
        let public = secret.public_key();
        Self { secret, public }
    }
}

#[cfg(test)]
mod tests {
    use rand_core::{OsRng, TryRngCore};

    use super::*;

    #[test]
    fn from_secretkey_yield_same() {
        let keypair = Keypair::generate(&mut OsRng.unwrap_err());
        let reconstructed_keypair = Keypair::from(SecretKey::from(keypair.secret().to_bytes()));

        assert_eq!(
            keypair.public().as_ref(),
            reconstructed_keypair.public().as_ref(),
        );
        assert_eq!(
            keypair.secret().to_bytes(),
            reconstructed_keypair.secret().to_bytes(),
        );
    }
}
