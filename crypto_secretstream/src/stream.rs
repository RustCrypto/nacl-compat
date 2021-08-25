use std::convert::TryFrom;

use aead::{AeadCore, AeadInPlace};
use chacha20::{
    cipher::{
        consts::U16,
        generic_array::{
            functional::FunctionalSequence,
            sequence::{Concat, Split},
            GenericArray,
        },
        NewCipher, StreamCipher, StreamCipherSeek,
    },
    hchacha, ChaCha20, R20,
};
use poly1305::{
    universal_hash::{NewUniversalHash, Output, UniversalHash},
    Poly1305,
};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

use super::nonce::Nonce;
use crate::{header::Header, Key, Tag};

const MAC_BLOCK_SIZE: usize = 16;
const TAG_BLOCK_SIZE: usize = 16 * 4;

type Result<T> = std::result::Result<T, aead::Error>;

/// AEAD for libsodium's secretstream. Better to use [`PushStream`] & [`PullStream`] as theses
/// take care of rekeying and computing the next nonce.
pub struct Stream {
    key: chacha20::Key,
    nonce: Nonce,
    counter: u32,
}

impl Stream {
    /// Create a new [`Stream`].
    pub fn init(key: &Key, header: Header) -> Self {
        let (hchacha20_nonce, nonce) = header.split();

        Self {
            key: hchacha::<R20>(key.as_array(), &hchacha20_nonce),
            nonce,
            counter: 1,
        }
    }

    /// Create a cipher and its related MAC key for the current round.
    fn get_cipher_and_mac(
        &self,
        cipher_nonce: &chacha20::Nonce,
    ) -> Result<(ChaCha20, poly1305::Key)> {
        let mut cipher = ChaCha20::new(&self.key, cipher_nonce);

        let mut mac_key = poly1305::Key::from([0u8; 32]);
        cipher
            .try_apply_keystream(mac_key.as_mut())
            .map_err(|_| aead::Error)?;

        Ok((cipher, mac_key))
    }

    /// XOR nonce, increment counter and rekey if need be
    fn update_state(&mut self, mac_output: GenericArray<u8, U16>, tag: Tag) -> Result<()> {
        // xor nonce
        let (reduced_mac, _) = mac_output.split();
        self.nonce = self.nonce.zip(reduced_mac, |l, r| l ^ r);

        // increment counter and rekey as needed
        let incremented_counter = self.counter.checked_add(1);
        match incremented_counter {
            Some(increment) if tag != Tag::Rekey => self.counter = increment,
            _ => {
                self.counter = incremented_counter.unwrap_or(0); // wrap anyway
                self.rekey()?;
            }
        }

        Ok(())
    }

    /// Compute the MAC of the message, with all the libsodium quirks.
    fn compute_mac(
        mac_key: &poly1305::Key,
        associated_data: &[u8],
        tag_block: [u8; TAG_BLOCK_SIZE],
        ciphertext: &[u8],
    ) -> Result<Output<Poly1305>> {
        let mut mac = Poly1305::new(mac_key);

        // blind with associated data
        mac.update_padded(associated_data);

        // pad block error in libsodium, see 290197ba
        let mac_padding_error_size = ((0x10 - 64 + ciphertext.len() as i64) & 0xf) as usize;
        let mac_padding_error = vec![0u8; mac_padding_error_size];

        // compute size block
        let mut size_block = [0u8; MAC_BLOCK_SIZE];
        size_block[..8].copy_from_slice(&associated_data.len().to_le_bytes());
        size_block[8..].copy_from_slice(&(TAG_BLOCK_SIZE + ciphertext.len()).to_le_bytes());

        let rest = tag_block
            .iter()
            .chain(
                ciphertext, // skip tag block
            )
            .copied()
            .chain(mac_padding_error.into_iter())
            .chain(size_block.iter().copied())
            .collect::<Vec<_>>();

        Ok(mac.compute_unpadded(&rest))
    }

    /// Rekey the stream, used internally in `update_state`.
    fn rekey(&mut self) -> Result<()> {
        let cipher_nonce = self.get_cipher_nonce();
        let mut cipher = ChaCha20::new(&self.key, &cipher_nonce);

        cipher
            .try_apply_keystream(&mut self.key)
            .map_err(|_| aead::Error)?;
        cipher
            .try_apply_keystream(&mut self.nonce)
            .map_err(|_| aead::Error)?;

        self.counter = 1;

        Ok(())
    }

    /// Expand the nonce & counter to a valid [`chacha20::Nonce`].
    ///
    /// Used internally.
    fn get_cipher_nonce(&self) -> chacha20::Nonce {
        GenericArray::from(self.counter.to_le_bytes()).concat(self.nonce)
    }
}

/// Stream that can encrypt messages to be decrypted by [`crate::PullStream`]
pub struct PushStream(Stream);

impl PushStream {
    /// Create a new stream for sending messages with a preshared key.
    ///
    /// The RNG is needed to generate the header.
    pub fn init<T>(csprng: &mut T, key: &Key) -> (Header, Self)
    where
        T: RngCore + CryptoRng,
    {
        let header = Header::generate(csprng);
        let stream = Stream::init(key, header);

        (header, Self(stream))
    }

    /// Encrypt a message and its associated data.
    pub fn push(&mut self, message: &[u8], associated_data: &[u8], tag: Tag) -> Result<Vec<u8>> {
        let cipher_nonce = self.0.get_cipher_nonce();

        let mut ciphertext = Vec::with_capacity(1 + message.len() + MAC_BLOCK_SIZE);
        ciphertext.push(tag as u8);
        ciphertext.extend_from_slice(message);
        let mac =
            self.0
                .encrypt_in_place_detached(&cipher_nonce, associated_data, &mut ciphertext)?;
        ciphertext.extend_from_slice(&mac);

        self.0.update_state(mac, tag)?;

        Ok(ciphertext)
    }
}

/// Stream that can decrypt messages encrypted by [`crate::PushStream`]
pub struct PullStream(Stream);

impl PullStream {
    /// Create new stream for receiving messages with a preshared key
    pub fn init(header: Header, key: &Key) -> Self {
        Self(Stream::init(key, header))
    }

    /// Decrypt a pushed message with its associated data.
    pub fn pull(&mut self, ciphertext: &[u8], associated_data: &[u8]) -> Result<(Tag, Vec<u8>)> {
        let cipher_nonce = self.0.get_cipher_nonce();

        if ciphertext.len() < MAC_BLOCK_SIZE {
            return Err(aead::Error);
        }
        let (message, mac) = ciphertext.split_at(ciphertext.len() - MAC_BLOCK_SIZE);
        let mut message = Vec::from(message);
        let mac = *poly1305::Block::from_slice(mac);

        self.0
            .decrypt_in_place_detached(&cipher_nonce, associated_data, &mut message, &mac)?;
        let tag = Tag::try_from(message[0]).map_err(|_| aead::Error)?;

        self.0.update_state(mac, tag)?;

        Ok((tag, Vec::from(&message[1..])))
    }
}

impl AeadCore for Stream {
    type NonceSize = <ChaCha20 as NewCipher>::NonceSize;
    type TagSize = <Poly1305 as UniversalHash>::BlockSize;
    type CiphertextOverhead = <Poly1305 as UniversalHash>::BlockSize;
}

// here, `buffer` is understood as already containing the message's tag
impl AeadInPlace for Stream {
    fn encrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> std::result::Result<aead::Tag<Self>, aead::Error> {
        if buffer.is_empty() {
            return Err(aead::Error);
        }
        let tag = Tag::try_from(buffer[0]).map_err(|_| aead::Error)?;

        if buffer.len() as u64 > u64::MAX - (TAG_BLOCK_SIZE as u64) {
            return Err(aead::Error);
        }

        let (mut cipher, mac_key) = self.get_cipher_and_mac(nonce)?;

        // create tag block
        let mut tag_block = [0u8; TAG_BLOCK_SIZE];
        tag_block[0] = tag as u8;
        cipher.try_seek(64).map_err(|_| aead::Error)?;
        cipher
            .try_apply_keystream(&mut tag_block)
            .map_err(|_| aead::Error)?;
        buffer[0] = tag_block[0];

        // encrypt ciphertext
        cipher.try_seek(128).map_err(|_| aead::Error)?;
        cipher
            .try_apply_keystream(&mut buffer[1..]) // skip tag
            .map_err(|_| aead::Error)?;

        // compute and append mac
        let mac_output =
            Stream::compute_mac(&mac_key, associated_data, tag_block, &buffer[1..])?.into_bytes();

        Ok(mac_output)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        mac: &aead::Tag<Self>,
    ) -> std::result::Result<(), aead::Error> {
        let (mut cipher, mac_key) = self.get_cipher_and_mac(nonce)?;

        // decrypt tag
        if buffer.is_empty() {
            return Err(aead::Error);
        }
        let mut tag_block = [0u8; TAG_BLOCK_SIZE];
        tag_block[0] = buffer[0];
        cipher.try_seek(64).map_err(|_| aead::Error)?;
        cipher
            .try_apply_keystream(&mut tag_block)
            .map_err(|_| aead::Error)?;
        let tag = tag_block[0];
        tag_block[0] = buffer[0];
        buffer[0] = tag;

        // compute mac and reject if not matching
        let mac_output =
            Stream::compute_mac(&mac_key, associated_data, tag_block, &buffer[1..])?.into_bytes();
        if bool::from(!mac_output.ct_eq(mac)) {
            return Err(aead::Error);
        }

        // decrypt ciphertext
        cipher.try_seek(128).map_err(|_| aead::Error)?;
        cipher
            .try_apply_keystream(&mut buffer[1..])
            .map_err(|_| aead::Error)?;

        Ok(())
    }
}
