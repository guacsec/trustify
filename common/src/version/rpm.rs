/// RPM version comparison, ported from the PL/pgSQL `rpmver_cmp`.
///
/// Tokenizes into segments: runs of digits, runs of alpha characters,
/// or special characters `~` and `^`. Segments are compared pairwise:
/// - `~` sorts before everything (pre-release indicator)
/// - `^` sorts after everything (snapshot indicator)
/// - Numeric segments are compared by magnitude (strip leading zeros)
/// - Alpha segments are compared lexicographically
/// - Numeric > alpha when types differ
use std::cmp::Ordering;

/// Compare two RPM version strings.
///
/// Returns `None` only if inputs are truly degenerate (empty after
/// tokenization). The PL/pgSQL version never returns NULL for RPM.
pub fn rpmver_cmp(left: &str, right: &str) -> Option<Ordering> {
    if left == right {
        return Some(Ordering::Equal);
    }

    let left_segs = tokenize(left);
    let right_segs = tokenize(right);

    let min_len = left_segs.len().min(right_segs.len());

    for i in 0..min_len {
        let l = &left_segs[i];
        let r = &right_segs[i];

        if let Some(ord) = compare_segments(l, r)
            && ord != Ordering::Equal
        {
            return Some(ord);
        }
    }

    // Handle trailing segments
    if let Some(seg) = right_segs.get(left_segs.len()) {
        if seg == "~" {
            return Some(Ordering::Greater);
        }
        if seg == "^" {
            return Some(Ordering::Less);
        }
    }
    if let Some(seg) = left_segs.get(right_segs.len()) {
        if seg == "~" {
            return Some(Ordering::Less);
        }
        if seg == "^" {
            return Some(Ordering::Greater);
        }
    }

    Some(left_segs.len().cmp(&right_segs.len()))
}

/// Tokenize an RPM version string into segments.
///
/// Each segment is either a run of digits, a run of alphabetic
/// characters, or a single `~` or `^` character. All other characters
/// (`.`, `-`, `_`) are separators and discarded.
fn tokenize(s: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut chars = s.chars().peekable();

    while let Some(&c) = chars.peek() {
        if c == '~' || c == '^' {
            segments.push(c.to_string());
            chars.next();
        } else if c.is_ascii_digit() {
            let mut seg = String::new();
            while let Some(&d) = chars.peek() {
                if d.is_ascii_digit() {
                    seg.push(d);
                    chars.next();
                } else {
                    break;
                }
            }
            segments.push(seg);
        } else if c.is_ascii_alphabetic() {
            let mut seg = String::new();
            while let Some(&d) = chars.peek() {
                if d.is_ascii_alphabetic() {
                    seg.push(d);
                    chars.next();
                } else {
                    break;
                }
            }
            segments.push(seg);
        } else {
            // Separator character — skip
            chars.next();
        }
    }

    segments
}

/// Compare two RPM segments.
fn compare_segments(left: &str, right: &str) -> Option<Ordering> {
    let l_is_digit = left.starts_with(|c: char| c.is_ascii_digit());
    let r_is_digit = right.starts_with(|c: char| c.is_ascii_digit());

    // Handle tilde (sorts before everything)
    if left == "~" && right != "~" {
        return Some(Ordering::Less);
    }
    if right == "~" && left != "~" {
        return Some(Ordering::Greater);
    }
    if left == "~" && right == "~" {
        return Some(Ordering::Equal);
    }

    // Handle caret (sorts after everything except when comparing to ~)
    if left == "^" && right != "^" {
        return Some(Ordering::Greater);
    }
    if right == "^" && left != "^" {
        return Some(Ordering::Less);
    }
    if left == "^" && right == "^" {
        return Some(Ordering::Equal);
    }

    if l_is_digit && r_is_digit {
        // Numeric comparison: strip leading zeros, compare by length then value
        let l_trimmed = left.trim_start_matches('0');
        let r_trimmed = right.trim_start_matches('0');
        match l_trimmed.len().cmp(&r_trimmed.len()) {
            Ordering::Equal => Some(l_trimmed.cmp(r_trimmed)),
            other => Some(other),
        }
    } else if l_is_digit {
        // Numeric > alpha
        Some(Ordering::Greater)
    } else if r_is_digit {
        Some(Ordering::Less)
    } else {
        // Alpha comparison: lexicographic
        Some(left.cmp(right))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_ordering() {
        assert_eq!(rpmver_cmp("1.0", "1.0"), Some(Ordering::Equal));
        assert_eq!(rpmver_cmp("1.1", "1.0"), Some(Ordering::Greater));
        assert_eq!(rpmver_cmp("1.0", "1.1"), Some(Ordering::Less));
    }

    #[test]
    fn numeric_vs_alpha() {
        assert_eq!(rpmver_cmp("1.0.1", "1.0.a"), Some(Ordering::Greater));
    }

    #[test]
    fn tilde_sorts_before() {
        assert_eq!(rpmver_cmp("1.0~rc1", "1.0"), Some(Ordering::Less));
    }

    #[test]
    fn caret_sorts_after() {
        assert_eq!(rpmver_cmp("1.0^git1", "1.0"), Some(Ordering::Greater));
    }

    #[test]
    fn leading_zeros() {
        assert_eq!(rpmver_cmp("01", "1"), Some(Ordering::Equal));
        assert_eq!(rpmver_cmp("001", "1"), Some(Ordering::Equal));
    }

    #[test]
    fn complex_rpm_version() {
        assert_eq!(
            rpmver_cmp("1.0.0-1.el8", "1.0.0-2.el8"),
            Some(Ordering::Less)
        );
    }
}
