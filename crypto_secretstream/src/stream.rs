use std::convert::TryFrom;

use chacha20::{
    cipher::{
        consts::U16,
        generic_array::{functional::FunctionalSequence, sequence::Split, GenericArray},
        NewCipher, StreamCipher, StreamCipherSeek,
    },
    hchacha, ChaCha20, R20,
};
use poly1305::{
    universal_hash::{NewUniversalHash, Output, UniversalHash},
    Poly1305,
};
use rand_core::{CryptoRng, RngCore};
use snafu::{ensure, OptionExt};

use super::nonce::Nonce;
use crate::{header::Header, Key, Tag};

const MAC_BLOCK_SIZE: usize = 16;
const TAG_BLOCK_SIZE: usize = 16 * 4;

#[derive(Debug, snafu::Snafu)]
pub enum Error {
    Crypto,
}

type Result<T> = std::result::Result<T, Error>;

/// Base struct for [`PushStream`] & [`PullStream`].
///
/// Mainly existing to avoid some code duplication.
struct Stream {
    key: chacha20::Key,
    nonce: Nonce,
    counter: u32,
}

impl Stream {
    fn init(key: &Key, header: Header) -> Self {
        let (hchacha20_nonce, nonce) = header.split();

        Self {
            key: hchacha::<R20>(key.as_array(), &hchacha20_nonce),
            nonce,
            counter: 1,
        }
    }

    /// Create a cipher and its related MAC key for the current round.
    fn get_cipher_and_mac(&self) -> Result<(ChaCha20, poly1305::Key)> {
        let mut cipher = ChaCha20::new(&self.key, &self.get_cipher_nonce());

        let mut mac_key = poly1305::Key::from([0u8; 32]);
        cipher
            .try_apply_keystream(mac_key.as_mut())
            .ok()
            .context(Crypto)?;

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
            .ok()
            .context(Crypto)?;
        cipher
            .try_apply_keystream(&mut self.nonce)
            .ok()
            .context(Crypto)?;

        self.counter = 1;

        Ok(())
    }

    /// Expand the nonce & counter to a valid [`chacha20::Nonce`].
    ///
    /// Used internally.
    fn get_cipher_nonce(&self) -> chacha20::Nonce {
        debug_assert_eq!(
            self.counter.to_le_bytes().len() + self.nonce.len(),
            chacha20::Nonce::default().len()
        );

        chacha20::Nonce::from_exact_iter(
            self.counter
                .to_le_bytes()
                .iter()
                .copied()
                .chain(self.nonce.into_iter()),
        )
        .unwrap()
    }
}

/// Stream that can encrypt messages to be decrypted by [`crate::PullStream`]
pub struct PushStream(Stream);

impl PushStream {
    /// Create a new stream for sending messages with a preshared key.
    ///
    /// The RNG is needed to generate a nonce.
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
        ensure!(associated_data.len() as u64 <= u64::MAX, Crypto);
        ensure!(
            message.len() as u64 <= u64::MAX - (TAG_BLOCK_SIZE as u64),
            Crypto
        );

        let mut ciphertext = Vec::<u8>::with_capacity(1 + message.len() + MAC_BLOCK_SIZE);

        let (mut cipher, mac_key) = self.0.get_cipher_and_mac()?;

        // create tag block
        let mut tag_block = [0u8; TAG_BLOCK_SIZE];
        tag_block[0] = tag as u8;
        cipher.try_seek(64).ok().context(Crypto)?;
        cipher
            .try_apply_keystream(&mut tag_block)
            .ok()
            .context(Crypto)?;
        ciphertext.push(tag_block[0]);

        // encrypt ciphertext
        ciphertext.extend_from_slice(message);
        cipher.try_seek(128).ok().context(Crypto)?;
        cipher
            .try_apply_keystream(&mut ciphertext[1..]) // skip tag block
            .ok()
            .context(Crypto)?;

        // compute and append mac
        let mac_output =
            Stream::compute_mac(&mac_key, associated_data, tag_block, &ciphertext[1..])?
                .into_bytes();
        ciphertext.extend_from_slice(&mac_output);

        // get ready for next round
        self.0.update_state(mac_output, tag)?;

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
        let (mut cipher, mac_key) = self.0.get_cipher_and_mac()?;

        // decrypt tag
        let mut tag_block = [0u8; TAG_BLOCK_SIZE];
        tag_block[0] = ciphertext[0];
        cipher.try_seek(64).ok().context(Crypto)?;
        cipher
            .try_apply_keystream(&mut tag_block)
            .ok()
            .context(Crypto)?;
        let tag = Tag::try_from(tag_block[0]).ok().context(Crypto)?;
        tag_block[0] = ciphertext[0];

        // decrypt ciphertext
        let mut message = Vec::<u8>::with_capacity(ciphertext.len() - MAC_BLOCK_SIZE - 1);
        message.extend_from_slice(&ciphertext[1..ciphertext.len() - MAC_BLOCK_SIZE]);
        cipher.try_seek(128).ok().context(Crypto)?;
        cipher
            .try_apply_keystream(&mut message)
            .ok()
            .context(Crypto)?;

        // compute mac and reject if not matching
        let mac_output = Stream::compute_mac(
            &mac_key,
            associated_data,
            tag_block,
            &ciphertext[1..ciphertext.len() - MAC_BLOCK_SIZE],
        )?
        .into_bytes();
        ensure!(
            mac_output
                .as_slice()
                .eq(&ciphertext[ciphertext.len() - MAC_BLOCK_SIZE..]),
            Crypto
        );

        // get ready for next round
        self.0.update_state(mac_output, tag)?;

        Ok((tag, message))
    }
}
