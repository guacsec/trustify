/// Python (PEP 440) version comparison, ported from PL/pgSQL `pythonver_cmp`.
///
/// Ordering: `major.minor.patch`, then pre-release (`a` < `b` < `rc`,
/// pre-release < release), then post-release (`post` > release), then
/// dev-release (`dev` < release).
use std::cmp::Ordering;

/// Compare two PEP 440 version strings.
///
/// Returns `None` if either string cannot be parsed.
pub fn pythonver_cmp(left: &str, right: &str) -> Option<Ordering> {
    let lv = parse_python(left)?;
    let rv = parse_python(right)?;

    // Compare major.minor.patch
    for (l, r) in lv.release.iter().zip(rv.release.iter()) {
        match l.cmp(r) {
            Ordering::Equal => continue,
            other => return Some(other),
        }
    }

    // Pre-release: has pre < no pre
    match (&lv.pre, &rv.pre) {
        (Some(_), None) => return Some(Ordering::Less),
        (None, Some(_)) => return Some(Ordering::Greater),
        (Some(l), Some(r)) => {
            let ord = compare_pre_tag(&l.tag, &r.tag);
            if ord != Ordering::Equal {
                return Some(ord);
            }
            match l.num.cmp(&r.num) {
                Ordering::Equal => {}
                other => return Some(other),
            }
        }
        (None, None) => {}
    }

    // Post-release: has post > no post
    match (lv.post, rv.post) {
        (Some(_), None) => return Some(Ordering::Greater),
        (None, Some(_)) => return Some(Ordering::Less),
        (Some(l), Some(r)) => {
            match l.cmp(&r) {
                Ordering::Equal => {}
                other => return Some(other),
            }
        }
        (None, None) => {}
    }

    // Dev-release: has dev < no dev
    match (lv.dev, rv.dev) {
        (Some(_), None) => return Some(Ordering::Less),
        (None, Some(_)) => return Some(Ordering::Greater),
        (Some(l), Some(r)) => {
            match l.cmp(&r) {
                Ordering::Equal => {}
                other => return Some(other),
            }
        }
        (None, None) => {}
    }

    Some(Ordering::Equal)
}

/// Pre-release tag: `a` (alpha), `b` (beta), `rc` (release candidate).
#[derive(Debug, Clone, PartialEq, Eq)]
enum PreTag {
    Alpha,
    Beta,
    Rc,
}

fn compare_pre_tag(left: &PreTag, right: &PreTag) -> Ordering {
    fn tag_ord(t: &PreTag) -> u8 {
        match t {
            PreTag::Alpha => 0,
            PreTag::Beta => 1,
            PreTag::Rc => 2,
        }
    }
    tag_ord(left).cmp(&tag_ord(right))
}

#[derive(Debug, Clone)]
struct PreRelease {
    tag: PreTag,
    num: Option<u64>,
}

#[derive(Debug, Clone)]
struct PythonVersion {
    release: Vec<u64>,
    pre: Option<PreRelease>,
    post: Option<u64>,
    dev: Option<u64>,
}

/// Parse a PEP 440 version string.
fn parse_python(s: &str) -> Option<PythonVersion> {
    // Extract the numeric release prefix (everything before first alpha char)
    let release_end = s
        .find(|c: char| c.is_ascii_alphabetic())
        .unwrap_or(s.len());
    let release_str = &s[..release_end];
    let release_str = release_str.trim_end_matches('.');

    let parts: Vec<u64> = if release_str.is_empty() {
        return None;
    } else {
        release_str
            .split('.')
            .map(|p| p.parse::<u64>().ok())
            .collect::<Option<Vec<_>>>()?
    };

    if parts.is_empty() {
        return None;
    }

    // Pad to 3 parts
    let mut release = parts;
    while release.len() < 3 {
        release.push(0);
    }

    // Pre-release: a|b|rc followed by optional digits
    let pre = extract_pre(s);

    // Post-release: postN
    let post = extract_tagged_num(s, "post");

    // Dev-release: devN
    let dev = extract_tagged_num(s, "dev");

    Some(PythonVersion {
        release,
        pre,
        post,
        dev,
    })
}

/// Extract a pre-release tag (a, b, rc) and optional number.
fn extract_pre(s: &str) -> Option<PreRelease> {
    // Try rc first (longer match), then b, then a
    for (pattern, tag) in [("rc", PreTag::Rc), ("beta", PreTag::Beta), ("b", PreTag::Beta), ("alpha", PreTag::Alpha), ("a", PreTag::Alpha)] {
        if let Some(idx) = s.find(pattern) {
            // Ensure it's not part of another word (like "post" containing no pre-tags)
            let after = &s[idx + pattern.len()..];
            let num_str: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            let num = if num_str.is_empty() {
                None
            } else {
                num_str.parse::<u64>().ok()
            };

            // Verify it's preceded by a digit or start-of-string (not mid-word)
            if idx == 0 || s.as_bytes().get(idx - 1).is_some_and(|b| b.is_ascii_digit() || *b == b'.') {
                return Some(PreRelease { tag, num });
            }
        }
    }
    None
}

/// Extract a tagged numeric suffix like `postN` or `devN`.
fn extract_tagged_num(s: &str, tag: &str) -> Option<u64> {
    let idx = s.find(tag)?;
    let after = &s[idx + tag.len()..];
    let num_str: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    if num_str.is_empty() {
        None
    } else {
        num_str.parse::<u64>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_ordering() {
        assert_eq!(pythonver_cmp("1.0.0", "1.0.0"), Some(Ordering::Equal));
        assert_eq!(pythonver_cmp("1.0.1", "1.0.0"), Some(Ordering::Greater));
        assert_eq!(pythonver_cmp("2.0.0", "1.9.9"), Some(Ordering::Greater));
    }

    #[test]
    fn prerelease_ordering() {
        // a < b < rc < release
        assert_eq!(pythonver_cmp("1.0.0a1", "1.0.0b1"), Some(Ordering::Less));
        assert_eq!(pythonver_cmp("1.0.0b1", "1.0.0rc1"), Some(Ordering::Less));
        assert_eq!(pythonver_cmp("1.0.0rc1", "1.0.0"), Some(Ordering::Less));
    }

    #[test]
    fn prerelease_numbering() {
        assert_eq!(pythonver_cmp("1.0.0a1", "1.0.0a2"), Some(Ordering::Less));
    }

    #[test]
    fn post_release() {
        assert_eq!(
            pythonver_cmp("1.0.0post1", "1.0.0"),
            Some(Ordering::Greater)
        );
        assert_eq!(
            pythonver_cmp("1.0.0post1", "1.0.0post2"),
            Some(Ordering::Less)
        );
    }

    #[test]
    fn dev_release() {
        assert_eq!(pythonver_cmp("1.0.0dev1", "1.0.0"), Some(Ordering::Less));
        assert_eq!(
            pythonver_cmp("1.0.0dev1", "1.0.0dev2"),
            Some(Ordering::Less)
        );
    }

    #[test]
    fn lenient_parsing() {
        assert_eq!(pythonver_cmp("1.0", "1.0.0"), Some(Ordering::Equal));
    }
}
