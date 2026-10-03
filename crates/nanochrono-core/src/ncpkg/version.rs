// SPDX-License-Identifier: Apache-2.0
//! Semantic versions (SemVer 2.0.0) and the requirements packages state on
//! the libraries they use.
//!
//! A `.ncdyn` in `/usr/lib` is shared by every package that accepts its
//! version; a package that accepts none of the installed ones keeps its own
//! copy private. That decision is only as good as the comparison, so it is
//! exactly SemVer 2.0.0 — pre-release identifiers ordered numerically or
//! lexically, build metadata ignored — and requirements are Cargo's syntax,
//! which most of the people writing these packages already read daily:
//!
//! | Requirement | Accepts |
//! |---|---|
//! | `^1.2.3` or `1.2.3` | `>=1.2.3, <2.0.0` (`^0.2.3`: `<0.3.0`; `^0.0.3`: `=0.0.3`) |
//! | `~1.2.3` | `>=1.2.3, <1.3.0` |
//! | `=1.2.3` | exactly 1.2.3 |
//! | `>=1.2, <2` | each comparator, all of them |
//! | `*`, `1.*`, `1.2.*` | anything, 1.x.y, 1.2.x |
//!
//! A pre-release (`2.0.0-beta.1`) satisfies a requirement only if one of
//! its comparators names a pre-release of the same `major.minor.patch`: a
//! package asking for `^1.4` never gets an untested `1.5.0-rc.1`.
//!
//! `no_std`, allocation-free: a version borrows its identifiers from the
//! text it was parsed from.

use core::cmp::Ordering;

/// The longest version or requirement text accepted.
pub const MAX_LEN: usize = 128;
/// The most comparators in one requirement.
pub const MAX_COMPARATORS: usize = 8;

/// A SemVer 2.0.0 version, borrowing its pre-release and build identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version<'a> {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    /// Dot-separated pre-release identifiers, `""` for a release.
    pub pre: &'a str,
    /// Build metadata, `""` if none. Ignored when comparing.
    pub build: &'a str,
}

/// A numeric component: digits, no leading zero unless it is `0`.
fn number(s: &str) -> Option<u64> {
    if s.is_empty() || (s.len() > 1 && s.starts_with('0')) || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut v = 0u64;
    for b in s.bytes() {
        v = v.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
    }
    Some(v)
}

/// Dot-separated identifiers of `[0-9A-Za-z-]`; numeric ones without a
/// leading zero when `strict_numeric` (pre-release, not build metadata).
fn identifiers(s: &str, strict_numeric: bool) -> bool {
    !s.is_empty()
        && s.split('.').all(|id| {
            !id.is_empty()
                && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !(strict_numeric && id.len() > 1 && id.starts_with('0') && id.bytes().all(|b| b.is_ascii_digit()))
        })
}

/// Compares two numeric identifiers of any length without converting them.
fn cmp_numeric(a: &str, b: &str) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

fn cmp_pre(a: &str, b: &str) -> Ordering {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => return Ordering::Equal,
        // A release outranks its pre-releases.
        (true, false) => return Ordering::Greater,
        (false, true) => return Ordering::Less,
        _ => {}
    }
    let mut x = a.split('.');
    let mut y = b.split('.');
    loop {
        match (x.next(), y.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(p), Some(q)) => {
                let pn = p.bytes().all(|c| c.is_ascii_digit());
                let qn = q.bytes().all(|c| c.is_ascii_digit());
                let o = match (pn, qn) {
                    (true, true) => cmp_numeric(p, q),
                    (true, false) => Ordering::Less,
                    (false, true) => Ordering::Greater,
                    (false, false) => p.cmp(q),
                };
                if o != Ordering::Equal {
                    return o;
                }
            }
        }
    }
}

impl<'a> Version<'a> {
    pub fn parse(text: &'a str) -> Option<Version<'a>> {
        if text.is_empty() || text.len() > MAX_LEN {
            return None;
        }
        let (rest, build) = match text.split_once('+') {
            Some((r, b)) => {
                if !identifiers(b, false) {
                    return None;
                }
                (r, b)
            }
            None => (text, ""),
        };
        let (core, pre) = match rest.split_once('-') {
            Some((c, p)) => {
                if !identifiers(p, true) {
                    return None;
                }
                (c, p)
            }
            None => (rest, ""),
        };
        let mut parts = core.split('.');
        let major = number(parts.next()?)?;
        let minor = number(parts.next()?)?;
        let patch = number(parts.next()?)?;
        if parts.next().is_some() {
            return None;
        }
        Some(Version { major, minor, patch, pre, build })
    }

    /// SemVer precedence: build metadata does not count.
    pub fn precedence(&self, other: &Version<'_>) -> Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
            .then_with(|| cmp_pre(self.pre, other.pre))
    }

    pub fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }
}

impl core::fmt::Display for Version<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if !self.pre.is_empty() {
            write!(f, "-{}", self.pre)?;
        }
        if !self.build.is_empty() {
            write!(f, "+{}", self.build)?;
        }
        Ok(())
    }
}

/// A comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Exact,
    Greater,
    GreaterEq,
    Less,
    LessEq,
    Tilde,
    Caret,
    /// `1.*`, `1.2.*`.
    Wildcard,
    /// `*`: every release.
    Any,
}

/// One comparator: an operator and a possibly partial version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Comparator<'a> {
    pub op: Op,
    pub major: u64,
    pub minor: Option<u64>,
    pub patch: Option<u64>,
    /// Only with a full version.
    pub pre: &'a str,
}

impl<'a> Comparator<'a> {
    fn parse(text: &'a str) -> Option<Comparator<'a>> {
        let text = text.trim();
        if text == "*" {
            return Some(Comparator { op: Op::Any, major: 0, minor: None, patch: None, pre: "" });
        }
        let (op, rest) = if let Some(r) = text.strip_prefix(">=") {
            (Op::GreaterEq, r)
        } else if let Some(r) = text.strip_prefix("<=") {
            (Op::LessEq, r)
        } else if let Some(r) = text.strip_prefix('>') {
            (Op::Greater, r)
        } else if let Some(r) = text.strip_prefix('<') {
            (Op::Less, r)
        } else if let Some(r) = text.strip_prefix('=') {
            (Op::Exact, r)
        } else if let Some(r) = text.strip_prefix('~') {
            (Op::Tilde, r)
        } else if let Some(r) = text.strip_prefix('^') {
            (Op::Caret, r)
        } else {
            (Op::Caret, text)
        };
        let rest = rest.trim_start();
        // Build metadata means nothing to a requirement; refuse rather than
        // pretend it was compared.
        if rest.contains('+') || rest.is_empty() {
            return None;
        }
        let (core, pre) = match rest.split_once('-') {
            Some((c, p)) => {
                if !identifiers(p, true) {
                    return None;
                }
                (c, p)
            }
            None => (rest, ""),
        };
        let mut parts = core.split('.');
        let major = number(parts.next()?)?;
        let wild = |s: &str| matches!(s, "*" | "x" | "X");
        let mut op = op;
        let minor = match parts.next() {
            None => None,
            Some(s) if wild(s) => {
                op = wildcard_op(op)?;
                None
            }
            Some(s) => Some(number(s)?),
        };
        let patch = match parts.next() {
            None => None,
            Some(_) if minor.is_none() => return None,
            Some(s) if wild(s) => {
                op = wildcard_op(op)?;
                None
            }
            Some(s) => Some(number(s)?),
        };
        if parts.next().is_some() {
            return None;
        }
        // A pre-release needs the full version it qualifies.
        if !pre.is_empty() && patch.is_none() {
            return None;
        }
        Some(Comparator { op, major, minor, patch, pre })
    }

    fn full(&self) -> Option<Version<'a>> {
        Some(Version { major: self.major, minor: self.minor?, patch: self.patch?, pre: self.pre, build: "" })
    }

    fn matches(&self, v: &Version<'_>) -> bool {
        let lower_ok = |full: &Version<'_>| v.precedence(full) != Ordering::Less;
        match self.op {
            Op::Any => true,
            Op::Wildcard => match self.minor {
                None => v.major == self.major,
                Some(m) => v.major == self.major && v.minor == m,
            },
            Op::Exact => match (self.minor, self.full()) {
                (_, Some(full)) => v.precedence(&full) == Ordering::Equal,
                (Some(m), None) => v.major == self.major && v.minor == m,
                (None, _) => v.major == self.major,
            },
            Op::Greater => match (self.minor, self.full()) {
                (_, Some(full)) => v.precedence(&full) == Ordering::Greater,
                (Some(m), None) => v.major > self.major || (v.major == self.major && v.minor > m),
                (None, _) => v.major > self.major,
            },
            Op::GreaterEq => match (self.minor, self.full()) {
                (_, Some(full)) => lower_ok(&full),
                (Some(m), None) => v.major > self.major || (v.major == self.major && v.minor >= m),
                (None, _) => v.major >= self.major,
            },
            Op::Less => match (self.minor, self.full()) {
                (_, Some(full)) => v.precedence(&full) == Ordering::Less,
                (Some(m), None) => v.major < self.major || (v.major == self.major && v.minor < m),
                (None, _) => v.major < self.major,
            },
            Op::LessEq => match (self.minor, self.full()) {
                (_, Some(full)) => v.precedence(&full) != Ordering::Greater,
                (Some(m), None) => v.major < self.major || (v.major == self.major && v.minor <= m),
                (None, _) => v.major <= self.major,
            },
            Op::Tilde => match (self.minor, self.full()) {
                (Some(m), Some(full)) => lower_ok(&full) && v.major == self.major && v.minor == m,
                (Some(m), None) => v.major == self.major && v.minor == m,
                (None, _) => v.major == self.major,
            },
            Op::Caret => match (self.minor, self.patch, self.full()) {
                (Some(m), Some(p), Some(full)) => {
                    lower_ok(&full)
                        && if self.major > 0 {
                            v.major == self.major
                        } else if m > 0 {
                            v.major == 0 && v.minor == m
                        } else {
                            v.major == 0 && v.minor == 0 && v.patch == p
                        }
                }
                (Some(m), _, _) => {
                    if self.major > 0 {
                        v.major == self.major && v.minor >= m
                    } else {
                        v.major == 0 && v.minor == m
                    }
                }
                (None, _, _) => v.major == self.major,
            },
        }
    }
}

/// `1.*` turns `^1`, `~1` or `=1` into a wildcard; with `<`/`>` it makes no
/// sense and is refused.
fn wildcard_op(op: Op) -> Option<Op> {
    match op {
        Op::Caret | Op::Tilde | Op::Exact | Op::Wildcard => Some(Op::Wildcard),
        _ => None,
    }
}

/// A requirement: comparators separated by commas, all of which must hold.
#[derive(Debug, Clone, Copy)]
pub struct Req<'a> {
    comparators: [Option<Comparator<'a>>; MAX_COMPARATORS],
}

impl<'a> Req<'a> {
    pub fn parse(text: &'a str) -> Option<Req<'a>> {
        if text.trim().is_empty() || text.len() > MAX_LEN {
            return None;
        }
        let mut comparators = [None; MAX_COMPARATORS];
        for (i, part) in text.split(',').enumerate() {
            *comparators.get_mut(i)? = Some(Comparator::parse(part)?);
        }
        Some(Req { comparators })
    }

    fn iter(&self) -> impl Iterator<Item = &Comparator<'a>> {
        self.comparators.iter().flatten()
    }

    /// Whether `v` satisfies every comparator (and the pre-release rule in
    /// the module docs).
    pub fn matches(&self, v: &Version<'_>) -> bool {
        if !self.iter().all(|c| c.matches(v)) {
            return false;
        }
        if v.is_prerelease() {
            return self.iter().any(|c| {
                !c.pre.is_empty() && c.major == v.major && c.minor == Some(v.minor) && c.patch == Some(v.patch)
            });
        }
        true
    }
}

/// Whether `version` satisfies `requirement`, both as text; `None` if
/// either does not parse.
pub fn satisfies(version: &str, requirement: &str) -> Option<bool> {
    Some(Req::parse(requirement)?.matches(&Version::parse(version)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version<'_> {
        Version::parse(s).unwrap_or_else(|| panic!("{s} does not parse"))
    }

    #[test]
    fn parses_semver_2() {
        let x = v("1.2.3-alpha.1+build.5");
        assert_eq!((x.major, x.minor, x.patch, x.pre, x.build), (1, 2, 3, "alpha.1", "build.5"));
        for good in ["0.0.0", "10.20.30", "1.0.0-0.3.7", "1.0.0-x.7.z.92", "1.0.0+20130313144700", "1.0.0-beta+exp.sha.5114f85", "1.0.0+001"] {
            v(good);
        }
        for bad in ["", "1", "1.2", "1.2.3.4", "01.2.3", "1.02.3", "1.2.03", "1.2.3-", "1.2.3-01", "1.2.3+", "1.2.3-a..b", "a.b.c", "1.2.3-é", " 1.2.3", "18446744073709551616.0.0"] {
            assert!(Version::parse(bad).is_none(), "{bad:?} parsed");
        }
    }

    #[test]
    fn precedence_follows_the_specification() {
        // The ordering example from SemVer 2.0.0 §11.
        let chain = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "2.0.0", "2.1.0", "2.1.1"];
        for w in chain.windows(2) {
            assert_eq!(v(w[0]).precedence(&v(w[1])), Ordering::Less, "{} < {}", w[0], w[1]);
            assert_eq!(v(w[1]).precedence(&v(w[0])), Ordering::Greater);
        }
        assert_eq!(v("1.0.0+a").precedence(&v("1.0.0+b")), Ordering::Equal);
        assert_eq!(v("1.0.0-99999999999999999999999").precedence(&v("1.0.0-100000000000000000000000")), Ordering::Less);
    }

    #[test]
    fn requirements_match_like_cargo() {
        let cases: &[(&str, &[&str], &[&str])] = &[
            ("^1.2.3", &["1.2.3", "1.9.0", "1.2.4"], &["1.2.2", "2.0.0", "0.9.0", "1.3.0-rc.1"]),
            ("1.2.3", &["1.2.3", "1.99.0"], &["2.0.0", "1.2.2"]),
            ("^0.2.3", &["0.2.3", "0.2.9"], &["0.3.0", "0.2.2"]),
            ("^0.0.3", &["0.0.3"], &["0.0.4", "0.0.2"]),
            ("^1.2", &["1.2.0", "1.5.1"], &["1.1.9", "2.0.0"]),
            ("^1", &["1.0.0", "1.9.9"], &["2.0.0", "0.9.0"]),
            ("^0", &["0.0.0", "0.9.9"], &["1.0.0"]),
            ("~1.2.3", &["1.2.3", "1.2.9"], &["1.3.0", "1.2.2"]),
            ("~1.2", &["1.2.0", "1.2.9"], &["1.3.0"]),
            ("~1", &["1.0.0", "1.9.0"], &["2.0.0"]),
            ("=1.2.3", &["1.2.3", "1.2.3+build"], &["1.2.4", "1.2.3-rc.1"]),
            ("=1.2", &["1.2.0", "1.2.7"], &["1.3.0"]),
            (">=1.2.0, <2.0.0", &["1.2.0", "1.9.9"], &["2.0.0", "1.1.0"]),
            (">1.2.3", &["1.2.4", "2.0.0"], &["1.2.3"]),
            (">1.2", &["1.3.0"], &["1.2.9"]),
            ("<=1.2", &["1.2.9", "0.1.0"], &["1.3.0"]),
            ("<1.2", &["1.1.9"], &["1.2.0"]),
            ("*", &["0.0.1", "99.0.0"], &["1.0.0-alpha"]),
            ("1.*", &["1.0.0", "1.99.1"], &["2.0.0"]),
            ("1.2.*", &["1.2.0", "1.2.99"], &["1.3.0"]),
            ("^2.0.0-beta.1", &["2.0.0-beta.1", "2.0.0-beta.2", "2.0.0", "2.5.0"], &["2.0.0-alpha", "2.1.0-beta.1", "3.0.0"]),
            (">=61.0.0, <62.0.0", &["61.3.100"], &["62.0.0", "60.31.102"]),
        ];
        for (req, yes, no) in cases {
            let r = Req::parse(req).unwrap_or_else(|| panic!("{req} does not parse"));
            for s in *yes {
                assert!(r.matches(&v(s)), "{req} should accept {s}");
            }
            for s in *no {
                assert!(!r.matches(&v(s)), "{req} should refuse {s}");
            }
        }
    }

    #[test]
    fn malformed_requirements_are_refused() {
        for bad in ["", " ", ",", "^", ">=", "1.2.3+build", "^1.2-rc", ">1.*", "<1.x", "1.*.3", "^01", "1,2,3,4,5,6,7,8,9", "~>1.2", "!1"] {
            assert!(Req::parse(bad).is_none(), "{bad:?} parsed");
        }
        assert_eq!(satisfies("1.2.3", "^1"), Some(true));
        assert_eq!(satisfies("1.2", "^1"), None);
    }
}
