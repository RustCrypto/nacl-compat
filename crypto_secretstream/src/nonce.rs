use chacha20::cipher::{
    array::Array,
    consts::{U16, U8},
};

pub type Nonce = Array<u8, U8>;

pub type HChaCha20Nonce = Array<u8, U16>;
