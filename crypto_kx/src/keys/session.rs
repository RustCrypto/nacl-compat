/// [`Key`] used in a session.
pub struct Key([u8; Key::BYTES]);

impl Key {
    /// Size in bytes of the [`Key`].
    pub const BYTES: usize = 32;
}

impl AsRef<[u8; Key::BYTES]> for Key {
    fn as_ref(&self) -> &[u8; Key::BYTES] {
        &self.0
    }
}

impl From<[u8; Key::BYTES]> for Key {
    fn from(value: [u8; Key::BYTES]) -> Self {
        Self(value)
    }
}

/// Tuple of keys for the client, the one opening the connection.
///
/// The [`ServerKeys`] computed on the server has the inversed content, so that `here.tx == there.rx`
/// and `here.rx == there.tx`.
pub struct ClientKeys {
    /// [`Key`] to send data with.
    pub tx: Key,
    /// [`Key`] to receive data with.
    pub rx: Key,
}

/// Tuple of keys for the server, the one receiving the connection.
///
/// The [`ClientKeys`] computed on the server has the inversed content, so that `here.tx == there.rx`
/// and `here.rx == there.tx`.
pub struct ServerKeys {
    /// [`Key`] to send data with.
    pub tx: Key,
    /// [`Key`] to receive data with.
    pub rx: Key,
}
