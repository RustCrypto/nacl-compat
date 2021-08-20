mod public;
mod secret;
mod session;

use core::fmt;

pub use public::Key as Public;
pub use secret::Key as Secret;
pub use session::{ClientKeys as ClientSession, Key as Session, ServerKeys as ServerSession};

// TODO copied from secretstream, consider having a subcrate

/// Given object is of an unexpected length.
#[derive(Debug)]
pub struct InvalidLength {
    expected: usize,
    got: usize,
}

impl InvalidLength {
    /// Build the error.
    ///
    /// Panic if the value is actually what we got.
    pub(super) fn new(expected: usize, got: usize) -> Self {
        assert!(expected != got);

        Self { expected, got }
    }
}

impl fmt::Display for InvalidLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "invalid length: expected {} but got {}",
            self.expected, self.got,
        ))
    }
}
