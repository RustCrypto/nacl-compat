/// [`SessionKey`] used in a session.
pub struct SessionKey([u8; SessionKey::BYTES]);

impl SessionKey {
    /// Size in bytes of the [`SessionKey`].
    pub const BYTES: usize = 32;
}

impl AsRef<[u8; SessionKey::BYTES]> for SessionKey {
    fn as_ref(&self) -> &[u8; SessionKey::BYTES] {
        &self.0
    }
}

impl From<[u8; SessionKey::BYTES]> for SessionKey {
    fn from(value: [u8; SessionKey::BYTES]) -> Self {
        Self(value)
    }
}

/// Tuple of keys for the client, the one opening the connection.
///
/// The [`ClientSessionKeys`] computed on the server has the inversed content, so that `here.tx == there.rx`
/// and `here.rx == there.tx`.
pub struct ClientSessionKeys {
    /// [`SessionKey`] to send data with.
    pub tx: SessionKey,
    /// [`SessionKey`] to receive data with.
    pub rx: SessionKey,
}

/// Tuple of keys for the server, the one receiving the connection.
///
/// The [`ServerSessionKeys`] computed on the server has the inversed content, so that `here.tx == there.rx`
/// and `here.rx == there.tx`.
pub struct ServerSessionKeys {
    /// [`SessionKey`] to send data with.
    pub tx: SessionKey,
    /// [`SessionKey`] to receive data with.
    pub rx: SessionKey,
}
