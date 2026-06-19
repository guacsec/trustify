use std::fmt::{self, Debug, Display};

/// Wrapper for displaying an iterable truncated to the first 10 elements.
///
/// Renders items via `Debug`, appending `(+N)` if there are more.
/// Works with any `&T` that implements `IntoIterator` (e.g. `Vec`, `HashSet`, slices).
pub struct TruncatedIter<'a, T: ?Sized>(pub &'a T);

impl<'a, T> TruncatedIter<'a, T>
where
    T: ?Sized,
    &'a T: IntoIterator,
    <&'a T as IntoIterator>::Item: Debug,
{
    /// Writes at most 10 items, appending `(+N)` if there are more.
    fn fmt_truncated(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const MAX: usize = 10;
        let mut iter = self.0.into_iter();
        f.write_str("[")?;
        for (i, item) in (&mut iter).take(MAX).enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            Debug::fmt(&item, f)?;
        }
        let remaining = iter.count();
        if remaining > 0 {
            write!(f, ", (+{remaining})")?;
        }
        f.write_str("]")
    }
}

impl<'a, T> Debug for TruncatedIter<'a, T>
where
    T: ?Sized,
    &'a T: IntoIterator,
    <&'a T as IntoIterator>::Item: Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_truncated(f)
    }
}

impl<'a, T> Display for TruncatedIter<'a, T>
where
    T: ?Sized,
    &'a T: IntoIterator,
    <&'a T as IntoIterator>::Item: Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_truncated(f)
    }
}
