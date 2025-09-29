//! Core `crypto_secretstream` construction.

use aead::{
    consts::{U12, U4, U8},
    AeadCore, AeadInOut, Buffer, KeyInit, Result,
};
use chacha20::{
    cipher::{array::Array, consts::U16, KeyIvInit, StreamCipher, StreamCipherSeek},
    hchacha, ChaCha20, R20,
};
use core::{mem, slice};
use poly1305::{
    universal_hash::{
        crypto_common::{BlockSizeUser, IvSizeUser},
        UniversalHash,
    },
    Poly1305,
};
#[cfg(feature = "rand_core")]
use rand_core::CryptoRng;
use subtle::ConstantTimeEq;

use super::nonce::Nonce;
use crate::{header::Header, Key, Tag};

const MAC_BLOCK_SIZE: usize = 16;
const TAG_BLOCK_SIZE: usize = 16 * 4;

/// AEAD for libsodium's secretstream. Better to use [`PushStream`] & [`PullStream`] as these
/// take care of rekeying and computing the next nonce.
pub struct Stream {
    key: chacha20::Key,
    nonce: Nonce,
    counter: u32,
}

impl Stream {
    /// Extra bytes per message compared to the plaintext
    pub const ABYTES: usize = MAC_BLOCK_SIZE + 1;

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
        cipher_nonce: &aead::Nonce<Self>,
    ) -> Result<(ChaCha20, poly1305::Key)> {
        let mut cipher = ChaCha20::new(&self.key, cipher_nonce);

        let mut mac_key = poly1305::Key::from([0u8; 32]);
        cipher
            .try_apply_keystream(mac_key.as_mut())
            .map_err(|_| aead::Error)?;

        Ok((cipher, mac_key))
    }

    /// XOR nonce, increment counter and rekey if need be
    fn update_state(&mut self, mac_output: Array<u8, U16>, tag: Tag) -> Result<()> {
        // xor nonce
        let (reduced_mac, _) = mac_output.split::<U8>();
        for (l, r) in self.nonce.iter_mut().zip(reduced_mac) {
            *l ^= r;
        }

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
    ) -> poly1305::Tag {
        let mut mac = Poly1305::new(mac_key);

        // pad block error in libsodium, see 290197ba
        let mac_padding_error_size = ((0x10 - 64 + ciphertext.len() as i64) & 0xf) as usize;

        // compute size block
        let mut size_block = [0u8; MAC_BLOCK_SIZE];
        size_block[..8].copy_from_slice(&(associated_data.len() as u64).to_le_bytes());
        size_block[8..]
            .copy_from_slice(&(TAG_BLOCK_SIZE as u64 + ciphertext.len() as u64).to_le_bytes());

        mac.update_padded(associated_data); // blind with associated data
        mac.update_padded(&tag_block); // do not any add padding

        // add all full blocks from ciphertext
        let chunks = ciphertext.chunks_exact(MAC_BLOCK_SIZE);
        let remaining_ciphertext = chunks.remainder();
        for block in chunks {
            mac.update(slice::from_ref(
                &poly1305::Block::try_from(block).expect("known size"),
            ))
        }

        // compute the last blocks: remaining_ciphertext + padding error + size_block
        let mut last_blocks = [0u8; 3 * MAC_BLOCK_SIZE];
        last_blocks[..remaining_ciphertext.len()].clone_from_slice(remaining_ciphertext);
        let size_block_offset = remaining_ciphertext.len() + mac_padding_error_size;
        last_blocks[size_block_offset..size_block_offset + MAC_BLOCK_SIZE]
            .copy_from_slice(&size_block);

        mac.compute_unpadded(&last_blocks[..size_block_offset + MAC_BLOCK_SIZE])
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
    fn get_cipher_nonce(&self) -> Array<u8, U12> {
        let a: Array<u8, U4> = Array::from(self.counter.to_le_bytes());
        a.concat(self.nonce)
    }
}

/// Stream that can encrypt messages to be decrypted by [`crate::PullStream`]
pub struct PushStream(Stream);

impl PushStream {
    /// Create a new stream for sending messages with a preshared key.
    ///
    /// The RNG is needed to generate the header.
    #[cfg(feature = "rand_core")]
    pub fn init(csprng: impl CryptoRng, key: &Key) -> (Header, Self) {
        let header = Header::generate(csprng);
        let stream = Stream::init(key, header);

        (header, Self(stream))
    }

    /// Encrypt a message and its associated data.
    pub fn push(
        &mut self,
        buffer: &mut impl aead::Buffer,
        associated_data: &[u8],
        tag: Tag,
    ) -> Result<()> {
        let cipher_nonce = self.0.get_cipher_nonce();

        buffer
            .extend_from_slice(&[tag as u8])
            .map_err(|_| aead::Error)?;
        buffer.as_mut().rotate_right(1);

        let inout = aead::inout::InOutBuf::<u8>::from(buffer.as_mut());
        let mac = self
            .0
            .encrypt_inout_detached(&cipher_nonce, associated_data, inout)?;
        buffer.extend_from_slice(&mac).map_err(|_| aead::Error)?;

        self.0.update_state(mac, tag)?;

        Ok(())
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
    pub fn pull(&mut self, buffer: &mut impl Buffer, associated_data: &[u8]) -> Result<Tag> {
        let cipher_nonce = self.0.get_cipher_nonce();

        if buffer.len() < MAC_BLOCK_SIZE + 1 {
            return Err(aead::Error);
        }
        let mac = poly1305::Block::try_from(&buffer.as_ref()[buffer.len() - MAC_BLOCK_SIZE..])
            .expect("known size");
        buffer.truncate(buffer.len() - MAC_BLOCK_SIZE);

        let inout = aead::inout::InOutBuf::<u8>::from(buffer.as_mut());
        self.0
            .decrypt_inout_detached(&cipher_nonce, associated_data, inout, &mac)?;
        let tag = Tag::try_from(buffer.as_ref()[0]).map_err(|_| aead::Error)?;
        buffer.as_mut().rotate_left(1);
        buffer.truncate(buffer.len() - 1);

        self.0.update_state(mac, tag)?;

        Ok(tag)
    }
}

impl AeadCore for Stream {
    type NonceSize = <ChaCha20 as IvSizeUser>::IvSize;
    type TagSize = <Poly1305 as BlockSizeUser>::BlockSize;

    const TAG_POSITION: aead::TagPosition = aead::TagPosition::Postfix;
}

// here, `buffer` is understood as already containing the message's tag
impl AeadInOut for Stream {
    fn encrypt_inout_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        mut buffer: aead::inout::InOutBuf<'_, '_, u8>,
    ) -> Result<aead::Tag<Self>> {
        if buffer.is_empty() {
            return Err(aead::Error);
        }
        let tag = Tag::try_from(buffer.get_out()[0]).map_err(|_| aead::Error)?;

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
        buffer.get_out()[0] = tag_block[0];

        // encrypt ciphertext
        cipher.try_seek(128).map_err(|_| aead::Error)?;
        cipher
            .try_apply_keystream(&mut buffer.get_out()[1..]) // skip tag
            .map_err(|_| aead::Error)?;

        // compute and append mac
        let mac_output =
            Stream::compute_mac(&mac_key, associated_data, tag_block, &buffer.get_out()[1..]);

        Ok(mac_output)
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        mut buffer: aead::inout::InOutBuf<'_, '_, u8>,
        tag: &aead::Tag<Self>,
    ) -> Result<()> {
        let (mut cipher, mac_key) = self.get_cipher_and_mac(nonce)?;

        // decrypt tag
        if buffer.is_empty() {
            return Err(aead::Error);
        }
        let mut tag_block = [0u8; TAG_BLOCK_SIZE];
        tag_block[0] = buffer.get_out()[0];
        cipher.try_seek(64).map_err(|_| aead::Error)?;
        cipher
            .try_apply_keystream(&mut tag_block)
            .map_err(|_| aead::Error)?;
        mem::swap(&mut tag_block[0], &mut buffer.get_out()[0]);

        // compute mac and reject if not matching
        let mac_output =
            Stream::compute_mac(&mac_key, associated_data, tag_block, &buffer.get_out()[1..]);
        if bool::from(!mac_output.ct_eq(tag)) {
            return Err(aead::Error);
        }

        // decrypt ciphertext
        cipher.try_seek(128).map_err(|_| aead::Error)?;
        cipher
            .try_apply_keystream(&mut buffer.get_out()[1..])
            .map_err(|_| aead::Error)?;

        Ok(())
    }
}
