use core::{
    fmt::{self, Display},
    ops::Range,
};

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

impl Display for InvalidLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "invalid length: expected {} but got {}",
            self.expected, self.got,
        ))
    }
}

/// Expected value is not in range.
#[derive(Debug)]
pub struct InvalidRange<Idx: fmt::Debug> {
    expected: Range<Idx>,
    got: Idx,
}

impl<Idx: fmt::Debug + PartialOrd<Idx>> InvalidRange<Idx> {
    /// Build the error.
    ///
    /// Panic if the value is actually included in the range.
    pub(super) fn new(expected: Range<Idx>, got: Idx) -> Self {
        assert!(!expected.contains(&got));

        Self { expected, got }
    }
}

impl<Idx: fmt::Debug + Display> Display for InvalidRange<Idx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "invalid range: expected a value between {} and {} but got {}",
            self.expected.start, self.expected.end, self.got,
        ))
    }
}
