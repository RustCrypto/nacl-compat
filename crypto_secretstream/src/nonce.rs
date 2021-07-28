use chacha20::cipher::{
    consts::{U16, U8},
    generic_array::GenericArray,
};

pub type Nonce = GenericArray<u8, U8>;

pub type HChaCha20Nonce = GenericArray<u8, U16>;
