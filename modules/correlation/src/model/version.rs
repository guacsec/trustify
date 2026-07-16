use crate::model::VersionRangeData;
use std::cmp::Ordering;
use trustify_entity::version_scheme::VersionScheme;

/// Checks whether a version string falls within the given version range,
/// using the range's version scheme for comparison. This is the Rust
/// equivalent of the PostgreSQL `version_matches()` PL/pgSQL function.
pub fn version_matches(candidate: &str, range: &VersionRangeData) -> bool {
    match range.version_scheme {
        VersionScheme::Semver
        | VersionScheme::Npm
        | VersionScheme::Gem
        | VersionScheme::NuGet
        | VersionScheme::Packagist
        | VersionScheme::Hex
        | VersionScheme::Swift
        | VersionScheme::Pub
        | VersionScheme::Cargo => range_check(semver_cmp, candidate, range),

        VersionScheme::Golang => {
            let normalized = candidate.strip_prefix('v').unwrap_or(candidate);
            range_check(semver_cmp, normalized, range)
        }

        VersionScheme::Rpm => range_check(rpm_cmp, candidate, range),
        VersionScheme::Maven => range_check(maven_cmp, candidate, range),
        VersionScheme::Python => range_check(python_cmp, candidate, range),

        VersionScheme::Generic | VersionScheme::Git => generic_version_matches(candidate, range),
    }
}

/// Applies low/high bound checks using the provided comparison function.
/// Returns false if no bounds are defined.
fn range_check(
    cmp_fn: fn(&str, &str) -> Option<Ordering>,
    candidate: &str,
    range: &VersionRangeData,
) -> bool {
    let low_cmp = range
        .low_version
        .as_deref()
        .and_then(|lv| cmp_fn(candidate, lv));

    if let Some(ord) = low_cmp {
        if range.low_inclusive {
            if ord == Ordering::Less {
                return false;
            }
        } else if ord != Ordering::Greater {
            return false;
        }
    }

    let high_cmp = range
        .high_version
        .as_deref()
        .and_then(|hv| cmp_fn(candidate, hv));

    if let Some(ord) = high_cmp {
        if range.high_inclusive {
            if ord == Ordering::Greater {
                return false;
            }
        } else if ord != Ordering::Less {
            return false;
        }
    }

    low_cmp.is_some() || high_cmp.is_some()
}

/// Generic/git: exact string equality only.
fn generic_version_matches(candidate: &str, range: &VersionRangeData) -> bool {
    if let Some(low) = &range.low_version
        && let Some(high) = &range.high_version
    {
        return candidate == low.as_str() && candidate == high.as_str();
    }
    false
}

// --- Semver comparison ---
// Ported from PL/pgSQL semver_cmp(). Uses lenient parsing to handle
// versions like "1.2" or versions with 4+ segments.

/// Compares two version strings using semver semantics with lenient parsing.
fn semver_cmp(left: &str, right: &str) -> Option<Ordering> {
    let left_v = lenient_semver::parse(left).ok()?;
    let right_v = lenient_semver::parse(right).ok()?;
    Some(left_v.cmp(&right_v))
}

// --- RPM comparison ---
// Ported from PL/pgSQL rpmver_cmp(). Segment-by-segment comparison with
// special handling for tilde (~) and caret (^) markers.

/// Compares two version strings using RPM versioning rules.
fn rpm_cmp(a: &str, b: &str) -> Option<Ordering> {
    if a == b {
        return Some(Ordering::Equal);
    }

    let a_segments = rpm_split_segments(a);
    let b_segments = rpm_split_segments(b);

    let min_len = a_segments.len().min(b_segments.len());

    for i in 0..min_len {
        let a_seg = &a_segments[i];
        let b_seg = &b_segments[i];

        let a_is_digit = a_seg.starts_with(|c: char| c.is_ascii_digit());
        let b_is_digit = b_seg.starts_with(|c: char| c.is_ascii_digit());

        if a_is_digit && b_is_digit {
            let a_trimmed = a_seg.trim_start_matches('0');
            let b_trimmed = b_seg.trim_start_matches('0');
            match a_trimmed.len().cmp(&b_trimmed.len()) {
                Ordering::Equal => {}
                ord => return Some(ord),
            }
        } else if a_is_digit {
            return Some(Ordering::Greater);
        } else if b_is_digit {
            return Some(Ordering::Less);
        } else if *a_seg == "~" {
            if *b_seg != "~" {
                return Some(Ordering::Less);
            }
        } else if *b_seg == "~" {
            return Some(Ordering::Greater);
        } else if *a_seg == "^" {
            if *b_seg != "^" {
                return Some(Ordering::Greater);
            }
        } else if *b_seg == "^" {
            return Some(Ordering::Less);
        }

        if a_seg != b_seg {
            return Some(a_seg.cmp(b_seg));
        }
    }

    // Check trailing segments
    if let Some(seg) = b_segments.get(a_segments.len()) {
        if *seg == "~" {
            return Some(Ordering::Greater);
        }
        if *seg == "^" {
            return Some(Ordering::Less);
        }
    }
    if let Some(seg) = a_segments.get(b_segments.len()) {
        if *seg == "~" {
            return Some(Ordering::Less);
        }
        if *seg == "^" {
            return Some(Ordering::Greater);
        }
    }

    Some(a_segments.len().cmp(&b_segments.len()))
}

/// Splits an RPM version string into segments (digit runs, alpha runs,
/// or special characters ~ and ^).
fn rpm_split_segments(s: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut chars = s.char_indices().peekable();

    while let Some(&(start, c)) = chars.peek() {
        if c == '~' || c == '^' {
            segments.push(&s[start..start + 1]);
            chars.next();
        } else if c.is_ascii_digit() {
            while let Some(&(_, nc)) = chars.peek() {
                if nc.is_ascii_digit() {
                    chars.next();
                } else {
                    break;
                }
            }
            let end = chars.peek().map_or(s.len(), |&(i, _)| i);
            segments.push(&s[start..end]);
        } else if c.is_ascii_alphabetic() {
            while let Some(&(_, nc)) = chars.peek() {
                if nc.is_ascii_alphabetic() {
                    chars.next();
                } else {
                    break;
                }
            }
            let end = chars.peek().map_or(s.len(), |&(i, _)| i);
            segments.push(&s[start..end]);
        } else {
            // Skip separators (dots, dashes, etc.)
            chars.next();
        }
    }

    segments
}

// --- Maven comparison ---
// Ported from PL/pgSQL mavenver_cmp(). Parses major.minor.revision with
// an optional qualifier-or-build suffix after a hyphen.

/// Compares two version strings using Maven versioning rules.
fn maven_cmp(left: &str, right: &str) -> Option<Ordering> {
    let (left_base, left_suffix) = maven_split(left);
    let (right_base, right_suffix) = maven_split(right);

    let left_parts = maven_parse_base(left_base);
    let right_parts = maven_parse_base(right_base);

    // Compare major.minor.revision
    for (l, r) in left_parts.iter().zip(right_parts.iter()) {
        match l.cmp(r) {
            Ordering::Equal => continue,
            ord => return Some(ord),
        }
    }

    // Compare cardinality (more parts = greater, matching SQL behavior)
    match left_parts.len().cmp(&right_parts.len()) {
        Ordering::Equal => {}
        ord => return Some(ord),
    }

    // Compare qualifier/build suffix
    match (left_suffix, right_suffix) {
        (None, None) => Some(Ordering::Equal),
        (None, Some(_)) => Some(Ordering::Greater),
        (Some(_), None) => Some(Ordering::Less),
        (Some(l), Some(r)) => {
            // Both are numeric: compare as numbers
            if let (Ok(ln), Ok(rn)) = (l.parse::<i64>(), r.parse::<i64>()) {
                Some(ln.cmp(&rn))
            } else {
                // Compare as lowercase strings
                Some(l.to_lowercase().cmp(&r.to_lowercase()))
            }
        }
    }
}

/// Splits a Maven version into base part and optional suffix after '-'.
fn maven_split(s: &str) -> (&str, Option<&str>) {
    if let Some(pos) = s.find('-') {
        (&s[..pos], Some(&s[pos + 1..]))
    } else {
        (s, None)
    }
}

/// Parses the base part of a Maven version (e.g., "1.2.3") into numeric parts.
fn maven_parse_base(base: &str) -> Vec<i64> {
    base.split('.')
        .map(|p| p.parse::<i64>().unwrap_or(0))
        .collect()
}

// --- Python comparison ---
// Ported from PL/pgSQL pythonver_cmp(). Handles PEP 440 with pre-release
// (a/b/rc), post-release, dev-release, and local version segments.

/// Compares two version strings using Python PEP 440 versioning rules.
fn python_cmp(left: &str, right: &str) -> Option<Ordering> {
    let left_v = PythonVersion::parse(left)?;
    let right_v = PythonVersion::parse(right)?;
    Some(left_v.cmp(&right_v))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PythonVersion {
    major: i64,
    minor: i64,
    patch: i64,
    pre: Option<(String, i64)>,
    post: Option<i64>,
    dev: Option<i64>,
    local: Option<String>,
}

impl PythonVersion {
    /// Parses a PEP 440 version string.
    fn parse(s: &str) -> Option<Self> {
        let base_end = find_base_end(s);

        let base = &s[..base_end];
        let rest = &s[base_end..];

        let parts: Vec<&str> = base.split('.').collect();
        let major = parts.first().and_then(|p| p.parse().ok()).unwrap_or(0);
        let minor = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0);
        let patch = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);

        // Strip optional separator before pre-release
        let rest = rest
            .strip_prefix('-')
            .or_else(|| rest.strip_prefix('_'))
            .or_else(|| rest.strip_prefix('.'))
            .unwrap_or(rest);

        let pre = extract_pre(rest);
        let post = extract_post(s);
        let dev = extract_dev(s);
        let local = extract_local(s);

        Some(PythonVersion {
            major,
            minor,
            patch,
            pre,
            post,
            dev,
            local,
        })
    }
}

impl Ord for PythonVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare major.minor.patch
        match self.major.cmp(&other.major) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.minor.cmp(&other.minor) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.patch.cmp(&other.patch) {
            Ordering::Equal => {}
            ord => return ord,
        }

        // Pre-release: present < absent
        match (&self.pre, &other.pre) {
            (Some(_), None) => return Ordering::Less,
            (None, Some(_)) => return Ordering::Greater,
            (Some((lp, ln)), Some((rp, rn))) => {
                match lp.cmp(rp) {
                    Ordering::Equal => {}
                    ord => return ord,
                }
                match ln.cmp(rn) {
                    Ordering::Equal => {}
                    ord => return ord,
                }
            }
            (None, None) => {}
        }

        // Post-release: present > absent
        match (self.post, other.post) {
            (Some(_), None) => return Ordering::Greater,
            (None, Some(_)) => return Ordering::Less,
            (Some(l), Some(r)) => match l.cmp(&r) {
                Ordering::Equal => {}
                ord => return ord,
            },
            (None, None) => {}
        }

        // Dev-release: present < absent
        match (self.dev, other.dev) {
            (Some(_), None) => return Ordering::Less,
            (None, Some(_)) => return Ordering::Greater,
            (Some(l), Some(r)) => match l.cmp(&r) {
                Ordering::Equal => {}
                ord => return ord,
            },
            (None, None) => {}
        }

        // Local: present > absent
        match (&self.local, &other.local) {
            (Some(_), None) => Ordering::Greater,
            (None, Some(_)) => Ordering::Less,
            (Some(l), Some(r)) => l.cmp(r),
            (None, None) => Ordering::Equal,
        }
    }
}

impl PartialOrd for PythonVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Finds where the numeric base portion of a PEP 440 version ends.
fn find_base_end(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_ascii_digit() || c == '.' {
            i += 1;
        } else {
            break;
        }
    }
    i
}

/// Extracts pre-release tag (a, b, rc) and optional number.
fn extract_pre(rest: &str) -> Option<(String, i64)> {
    for tag in &["rc", "b", "a"] {
        if let Some(pos) = rest.find(tag)
            && (pos == 0 || !rest.as_bytes()[pos - 1].is_ascii_alphabetic())
        {
            let after = &rest[pos + tag.len()..];
            let num_str: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            let num = num_str.parse::<i64>().unwrap_or(0);
            return Some((tag.to_string(), num));
        }
    }
    None
}

/// Extracts post-release number from a version string.
fn extract_post(s: &str) -> Option<i64> {
    if let Some(pos) = s.find("post") {
        let after = &s[pos + 4..];
        let num_str: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
        if num_str.is_empty() {
            return None;
        }
        return num_str.parse().ok();
    }
    None
}

/// Extracts dev-release number from a version string.
fn extract_dev(s: &str) -> Option<i64> {
    if let Some(pos) = s.find("dev") {
        let after = &s[pos + 3..];
        let num_str: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
        if num_str.is_empty() {
            return None;
        }
        return num_str.parse().ok();
    }
    None
}

/// Extracts local version segment (after +).
fn extract_local(s: &str) -> Option<String> {
    if let Some(pos) = s.find('+') {
        let local = &s[pos + 1..];
        if local.is_empty() {
            return None;
        }
        return Some(local.to_string());
    }
    None
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::model::VersionRangeData;
    use trustify_entity::version_scheme::VersionScheme;

    fn range(
        scheme: VersionScheme,
        low: Option<&str>,
        low_incl: bool,
        high: Option<&str>,
        high_incl: bool,
    ) -> VersionRangeData {
        VersionRangeData {
            version_scheme: scheme,
            low_version: low.map(String::from),
            low_inclusive: low_incl,
            high_version: high.map(String::from),
            high_inclusive: high_incl,
        }
    }

    // --- Semver tests ---

    #[test]
    fn semver_basic_cmp() {
        assert_eq!(semver_cmp("1.0.0", "1.0.0"), Some(Ordering::Equal));
        assert_eq!(semver_cmp("1.0.1", "1.0.0"), Some(Ordering::Greater));
        assert_eq!(semver_cmp("1.0.0", "1.0.1"), Some(Ordering::Less));
        assert_eq!(semver_cmp("2.0.0", "1.9.9"), Some(Ordering::Greater));
    }

    #[test]
    fn semver_prerelease() {
        assert_eq!(semver_cmp("1.0.0-alpha", "1.0.0"), Some(Ordering::Less));
        assert_eq!(
            semver_cmp("1.0.0-alpha", "1.0.0-beta"),
            Some(Ordering::Less)
        );
    }

    #[test]
    fn semver_range_inclusive() {
        let r = range(
            VersionScheme::Semver,
            Some("1.0.0"),
            true,
            Some("2.0.0"),
            true,
        );
        assert!(version_matches("1.0.0", &r));
        assert!(version_matches("1.5.0", &r));
        assert!(version_matches("2.0.0", &r));
        assert!(!version_matches("0.9.0", &r));
        assert!(!version_matches("2.0.1", &r));
    }

    #[test]
    fn semver_range_exclusive() {
        let r = range(
            VersionScheme::Semver,
            Some("1.0.0"),
            false,
            Some("2.0.0"),
            false,
        );
        assert!(!version_matches("1.0.0", &r));
        assert!(version_matches("1.5.0", &r));
        assert!(!version_matches("2.0.0", &r));
    }

    #[test]
    fn semver_open_upper() {
        let r = range(VersionScheme::Semver, Some("1.0.0"), true, None, false);
        assert!(version_matches("1.0.0", &r));
        assert!(version_matches("99.0.0", &r));
        assert!(!version_matches("0.9.0", &r));
    }

    #[test]
    fn semver_open_lower() {
        let r = range(VersionScheme::Semver, None, false, Some("2.0.0"), false);
        assert!(version_matches("1.0.0", &r));
        assert!(!version_matches("2.0.0", &r));
    }

    // --- Golang tests ---

    #[test]
    fn golang_strips_v_prefix() {
        let r = range(
            VersionScheme::Golang,
            Some("1.0.0"),
            true,
            Some("2.0.0"),
            false,
        );
        assert!(version_matches("v1.5.0", &r));
        assert!(version_matches("1.5.0", &r));
        assert!(!version_matches("v2.0.0", &r));
    }

    // --- RPM tests ---

    #[test]
    fn rpm_basic_cmp() {
        assert_eq!(rpm_cmp("1.0", "1.0"), Some(Ordering::Equal));
        assert_eq!(rpm_cmp("1.1", "1.0"), Some(Ordering::Greater));
        assert_eq!(rpm_cmp("1.0", "1.1"), Some(Ordering::Less));
    }

    #[test]
    fn rpm_tilde() {
        // Tilde sorts before anything, even empty
        assert_eq!(rpm_cmp("1.0~rc1", "1.0"), Some(Ordering::Less));
    }

    #[test]
    fn rpm_caret() {
        // Caret sorts after release
        assert_eq!(rpm_cmp("1.0^post1", "1.0"), Some(Ordering::Greater));
    }

    #[test]
    fn rpm_numeric_vs_alpha() {
        // Numeric segments sort after alphabetic
        assert_eq!(rpm_cmp("1.0.1", "1.0.a"), Some(Ordering::Greater));
    }

    #[test]
    fn rpm_range() {
        let r = range(VersionScheme::Rpm, Some("1.0"), true, Some("2.0"), false);
        assert!(version_matches("1.0", &r));
        assert!(version_matches("1.5", &r));
        assert!(!version_matches("2.0", &r));
        assert!(!version_matches("0.9", &r));
    }

    // --- Maven tests ---

    #[test]
    fn maven_basic_cmp() {
        assert_eq!(maven_cmp("1.0.0", "1.0.0"), Some(Ordering::Equal));
        assert_eq!(maven_cmp("2.0.0", "1.0.0"), Some(Ordering::Greater));
    }

    #[test]
    fn maven_qualifier() {
        // No qualifier > with qualifier (release > snapshot)
        assert_eq!(
            maven_cmp("1.0.0", "1.0.0-SNAPSHOT"),
            Some(Ordering::Greater)
        );
        assert_eq!(maven_cmp("1.0.0-alpha", "1.0.0-beta"), Some(Ordering::Less));
    }

    #[test]
    fn maven_range() {
        let r = range(
            VersionScheme::Maven,
            Some("1.0.0"),
            true,
            Some("2.0.0"),
            false,
        );
        assert!(version_matches("1.0.0", &r));
        assert!(version_matches("1.5.0", &r));
        assert!(!version_matches("2.0.0", &r));
    }

    // --- Python tests ---

    #[test]
    fn python_basic_cmp() {
        assert_eq!(python_cmp("1.0.0", "1.0.0"), Some(Ordering::Equal));
        assert_eq!(python_cmp("1.1.0", "1.0.0"), Some(Ordering::Greater));
    }

    #[test]
    fn python_prerelease() {
        assert_eq!(python_cmp("1.0.0a1", "1.0.0"), Some(Ordering::Less));
        assert_eq!(python_cmp("1.0.0b1", "1.0.0a1"), Some(Ordering::Greater));
        assert_eq!(python_cmp("1.0.0rc1", "1.0.0b1"), Some(Ordering::Greater));
    }

    #[test]
    fn python_post_release() {
        assert_eq!(python_cmp("1.0.0.post1", "1.0.0"), Some(Ordering::Greater));
    }

    #[test]
    fn python_dev_release() {
        assert_eq!(python_cmp("1.0.0.dev1", "1.0.0"), Some(Ordering::Less));
    }

    #[test]
    fn python_range() {
        let r = range(
            VersionScheme::Python,
            Some("1.0.0"),
            true,
            Some("2.0.0"),
            false,
        );
        assert!(version_matches("1.0.0", &r));
        assert!(version_matches("1.5.0", &r));
        assert!(!version_matches("2.0.0", &r));
        assert!(!version_matches("1.0.0a1", &r));
    }

    // --- Generic tests ---

    #[test]
    fn generic_exact_match() {
        let r = range(VersionScheme::Generic, Some("1.0"), true, Some("1.0"), true);
        assert!(version_matches("1.0", &r));
        assert!(!version_matches("1.1", &r));
    }
}
