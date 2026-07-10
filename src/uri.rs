//! URI-reference parsing, RFC 3986 §5 reference resolution, and
//! §6.2.2 / §6.2.3 normalization for the redirect engine.
//!
//! The driver owns its redirect semantics (RFC 9110 §15.4), and a
//! `Location` field value is a `URI-reference` (§10.2.2) that "when it
//! has the form of a relative reference ([URI], Section 4.2), the
//! final value is computed by resolving it against the target URI
//! ([URI], Section 5)". This module supplies exactly that machinery:
//!
//! * [`UriRef::parse`] — strict component split + character
//!   validation per the RFC 3986 Appendix A collected ABNF. Used for
//!   `Location` values, which arrive from an untrusted origin.
//! * [`UriRef::parse_lenient`] — the same first-match-wins component
//!   split with only structural validation (scheme grammar, bracket
//!   closure, digit-only port). Used for the caller's own request
//!   URI, where RFC 3986 Appendix B's "parse first, validate by
//!   scheme later" posture is friendlier to hand-typed URLs.
//! * [`UriRef::resolve`] — the §5.2.2 strict transform (including
//!   §5.2.3 `merge` and §5.2.4 `remove_dot_segments`), recomposed per
//!   §5.3.
//! * [`UriRef::normalized`] — syntax-based normalization (§6.2.2:
//!   case, percent-encoding, dot segments) plus the scheme-based
//!   rules RFC 9110 §4.2.3 adds for `http`/`https` (default-port
//!   elision, empty path → `/`). The redirect engine uses the normal
//!   form as its loop-detection key: two hops that are "equivalent
//!   after normalization ... can be assumed to identify the same
//!   resource" (RFC 9110 §4.2.3).
//!
//! Components are stored verbatim (no canonicalisation on parse), so
//! `parse` → [`std::fmt::Display`] round-trips byte-identically,
//! preserving the §5.3 distinction between an undefined component
//! (delimiter absent) and an empty one (delimiter present).

use std::fmt;

/// Error produced by [`UriRef::parse`] / [`UriRef::parse_lenient`] /
/// [`UriRef::resolve`], carrying a human-readable reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UriError(String);

impl fmt::Display for UriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UriError {}

fn err(msg: impl Into<String>) -> UriError {
    UriError(msg.into())
}

/// A parsed URI reference: the five components of RFC 3986 §3, each
/// stored verbatim as it appeared in the input.
///
/// `scheme`, `authority`, `query`, and `fragment` distinguish
/// undefined (`None` — the associated delimiter was absent) from
/// empty (`Some("")` — the delimiter was present with nothing after
/// it), exactly as §5.3 requires for faithful recomposition. The
/// `path` component "is never undefined, though it may be empty"
/// (§5.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UriRef {
    scheme: Option<String>,
    authority: Option<String>,
    path: String,
    query: Option<String>,
    fragment: Option<String>,
}

// ---------------------------------------------------------------------------
// Character classes (RFC 3986 §2 / Appendix A)
// ---------------------------------------------------------------------------

/// §2.3: `unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"`.
fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// §2.2: `sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+"
/// / "," / ";" / "="`.
fn is_sub_delim(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    )
}

/// Appendix A: `pchar = unreserved / pct-encoded / sub-delims / ":" /
/// "@"` — the pct-encoded alternative is handled by the walker, not
/// this predicate.
fn is_pchar_raw(b: u8) -> bool {
    is_unreserved(b) || is_sub_delim(b) || b == b':' || b == b'@'
}

/// Validate one component against a raw-character predicate, allowing
/// `pct-encoded = "%" HEXDIG HEXDIG` triplets everywhere (§2.1).
fn validate_component(what: &str, s: &str, allowed: impl Fn(u8) -> bool) -> Result<(), UriError> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            if i + 2 >= bytes.len()
                || !bytes[i + 1].is_ascii_hexdigit()
                || !bytes[i + 2].is_ascii_hexdigit()
            {
                return Err(err(format!(
                    "{what} contains an incomplete percent-encoding at byte {i} (RFC 3986 §2.1)"
                )));
            }
            i += 3;
            continue;
        }
        if !allowed(b) {
            return Err(err(format!(
                "{what} contains forbidden byte 0x{b:02x} at offset {i} (RFC 3986 Appendix A)"
            )));
        }
        i += 1;
    }
    Ok(())
}

/// Appendix A: `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`.
fn is_valid_scheme(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b[0].is_ascii_alphabetic()
        && b[1..]
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
}

// ---------------------------------------------------------------------------
// Parsing (RFC 3986 §3 component split, Appendix A grammar)
// ---------------------------------------------------------------------------

impl UriRef {
    /// Parse a URI reference with full character-level validation
    /// against the Appendix A collected ABNF. Use this for values
    /// received from an untrusted source (e.g. a `Location` field:
    /// RFC 9110 §10.2.2 permits but does not mandate recovery from
    /// invalid references — this driver refuses them).
    pub fn parse(s: &str) -> Result<Self, UriError> {
        let r = Self::split(s)?;
        r.validate_strict()?;
        Ok(r)
    }

    /// Parse a URI reference with structural validation only: the
    /// scheme grammar, authority sub-structure (bracket closure,
    /// digit-only port), and the absence of whitespace / control
    /// bytes are enforced, but the path / query / fragment character
    /// sets are not. Use this for the caller's own request URI.
    pub fn parse_lenient(s: &str) -> Result<Self, UriError> {
        let r = Self::split(s)?;
        // Control bytes and spaces break the component split itself
        // (they are excluded from every production, and a raw space
        // in a request target would smuggle through to the wire).
        if let Some(b) = s.bytes().find(|b| *b <= 0x20 || *b == 0x7f) {
            return Err(err(format!(
                "URI reference contains whitespace or control byte 0x{b:02x}"
            )));
        }
        // Authority sub-structure must still be unambiguous — the
        // redirect engine's host / port / userinfo checks depend on
        // it.
        let _ = r.authority_parts()?;
        Ok(r)
    }

    /// First-match-wins component split (§3; the disambiguation the
    /// Appendix B regular expression encodes).
    fn split(s: &str) -> Result<Self, UriError> {
        let mut rest = s;
        // scheme: everything before the first ":" — but only if that
        // ":" appears before any "/", "?" or "#", and the prefix
        // satisfies the scheme grammar. A relative reference whose
        // first path segment contains ":" is not expressible
        // (`path-noscheme` excludes it, Appendix A); "./x:y" is the
        // standard escape for such paths.
        let mut scheme = None;
        if let Some(idx) = rest.find([':', '/', '?', '#']) {
            if rest.as_bytes()[idx] == b':' {
                let candidate = &rest[..idx];
                if !is_valid_scheme(candidate) {
                    return Err(err(format!(
                        "first path segment of a relative reference cannot contain ':' \
                         and {candidate:?} is not a valid scheme (RFC 3986 Appendix A)"
                    )));
                }
                scheme = Some(candidate.to_owned());
                rest = &rest[idx + 1..];
            }
        }
        // authority: introduced by "//", runs to the next "/", "?"
        // or "#" (§3.2).
        let mut authority = None;
        if let Some(after) = rest.strip_prefix("//") {
            let end = after.find(['/', '?', '#']).unwrap_or(after.len());
            authority = Some(after[..end].to_owned());
            rest = &after[end..];
        }
        // path: up to the first "?" or "#" (§3.3).
        let path_end = rest.find(['?', '#']).unwrap_or(rest.len());
        let path = rest[..path_end].to_owned();
        rest = &rest[path_end..];
        // query: "?" up to "#" (§3.4).
        let mut query = None;
        if let Some(after) = rest.strip_prefix('?') {
            let end = after.find('#').unwrap_or(after.len());
            query = Some(after[..end].to_owned());
            rest = &after[end..];
        }
        // fragment: "#" to the end (§3.5).
        let fragment = rest.strip_prefix('#').map(str::to_owned);
        Ok(Self {
            scheme,
            authority,
            path,
            query,
            fragment,
        })
    }

    fn validate_strict(&self) -> Result<(), UriError> {
        let (userinfo, host, port) = self.authority_parts()?;
        if let Some(ui) = userinfo {
            // §3.2.1: userinfo = *( unreserved / pct-encoded /
            // sub-delims / ":" ).
            validate_component("userinfo", ui, |b| {
                is_unreserved(b) || is_sub_delim(b) || b == b':'
            })?;
        }
        if let Some(host) = host {
            if host.starts_with('[') {
                // IP-literal: bracket closure is checked by
                // authority_parts; validate the interior loosely —
                // IPv6address / IPvFuture character repertoire
                // (§3.2.2) without re-deriving the full address
                // grammar.
                let interior = &host[1..host.len() - 1];
                let ok = if let Some(vf) = interior.strip_prefix(['v', 'V']) {
                    // IPvFuture = "v" 1*HEXDIG "." 1*( unreserved /
                    // sub-delims / ":" )
                    match vf.split_once('.') {
                        Some((ver, tail)) => {
                            !ver.is_empty()
                                && ver.bytes().all(|b| b.is_ascii_hexdigit())
                                && !tail.is_empty()
                                && tail
                                    .bytes()
                                    .all(|b| is_unreserved(b) || is_sub_delim(b) || b == b':')
                        }
                        None => false,
                    }
                } else {
                    !interior.is_empty()
                        && interior
                            .bytes()
                            .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
                };
                if !ok {
                    return Err(err(format!(
                        "invalid IP-literal host {host:?} (RFC 3986 §3.2.2)"
                    )));
                }
            } else {
                // reg-name = *( unreserved / pct-encoded / sub-delims )
                // — IPv4address is a subset of reg-name characters.
                validate_component("host", host, |b| is_unreserved(b) || is_sub_delim(b))?;
            }
        }
        if let Some(port) = port {
            // port = *DIGIT — checked in authority_parts already, but
            // keep the strict path self-contained.
            if !port.bytes().all(|b| b.is_ascii_digit()) {
                return Err(err(format!(
                    "port {port:?} is not *DIGIT (RFC 3986 §3.2.3)"
                )));
            }
        }
        // path: segments of pchar, "/" separated (Appendix A path
        // productions).
        validate_component("path", &self.path, |b| is_pchar_raw(b) || b == b'/')?;
        if let Some(q) = &self.query {
            // query = *( pchar / "/" / "?" )
            validate_component("query", q, |b| is_pchar_raw(b) || b == b'/' || b == b'?')?;
        }
        if let Some(f) = &self.fragment {
            // fragment = *( pchar / "/" / "?" )
            validate_component("fragment", f, |b| is_pchar_raw(b) || b == b'/' || b == b'?')?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// The scheme component, if defined (never empty when defined).
    pub fn scheme(&self) -> Option<&str> {
        self.scheme.as_deref()
    }

    /// The raw authority component, if defined.
    pub fn authority(&self) -> Option<&str> {
        self.authority.as_deref()
    }

    /// The path component (always defined, possibly empty).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The query component, if defined.
    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }

    /// The fragment component, if defined.
    pub fn fragment(&self) -> Option<&str> {
        self.fragment.as_deref()
    }

    /// Split the authority into `(userinfo, host, port)` per §3.2:
    /// `authority = [ userinfo "@" ] host [ ":" port ]`. Every part
    /// is `None` when the authority itself is undefined; `host` is
    /// `Some` (possibly empty) whenever an authority is present.
    ///
    /// Errors on structural ambiguity: an unclosed `[` IP-literal,
    /// characters after the closing `]` other than `:port`, or a
    /// non-digit port.
    #[allow(clippy::type_complexity)]
    pub fn authority_parts(&self) -> Result<(Option<&str>, Option<&str>, Option<&str>), UriError> {
        let Some(auth) = self.authority.as_deref() else {
            return Ok((None, None, None));
        };
        // userinfo runs to the first "@" — its own charset excludes
        // "@" (§3.2.1), and so does every host form, so a second "@"
        // is caught by host validation downstream.
        let (userinfo, hostport) = match auth.split_once('@') {
            Some((ui, hp)) => (Some(ui), hp),
            None => (None, auth),
        };
        let (host, port) = if let Some(after) = hostport.strip_prefix('[') {
            // IP-literal = "[" ... "]" (§3.2.2).
            let Some(close) = after.find(']') else {
                return Err(err(format!(
                    "authority {auth:?} has an unterminated IP-literal (RFC 3986 §3.2.2)"
                )));
            };
            let host = &hostport[..close + 2];
            let tail = &after[close + 1..];
            let port = if tail.is_empty() {
                None
            } else if let Some(p) = tail.strip_prefix(':') {
                Some(p)
            } else {
                return Err(err(format!(
                    "authority {auth:?} carries bytes after the IP-literal that are not a \
                     ':port' (RFC 3986 §3.2)"
                )));
            };
            (host, port)
        } else {
            match hostport.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (hostport, None),
            }
        };
        if let Some(p) = port {
            if !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(err(format!("port {p:?} is not *DIGIT (RFC 3986 §3.2.3)")));
            }
        }
        Ok((userinfo, Some(host), port))
    }

    /// A copy of this reference with the fragment removed. Fragments
    /// are never transmitted in a request target (RFC 9110 §7.1), and
    /// a base URI must be "stripped of any fragment component prior
    /// to its use as a base URI" (RFC 3986 §5.1).
    pub fn without_fragment(&self) -> Self {
        Self {
            fragment: None,
            ..self.clone()
        }
    }

    // -----------------------------------------------------------------------
    // §5 Reference resolution
    // -----------------------------------------------------------------------

    /// Resolve the reference `r` against `self` as the base URI,
    /// using the strict §5.2.2 transform. The base must be absolute
    /// (§5.1: "a base URI must conform to the <absolute-URI> syntax
    /// rule"); any fragment on the base is ignored per §5.1.
    pub fn resolve(&self, r: &UriRef) -> Result<UriRef, UriError> {
        let Some(base_scheme) = self.scheme.as_deref() else {
            return Err(err(
                "base URI has no scheme — reference resolution requires an absolute base \
                 (RFC 3986 §5.1)",
            ));
        };
        // §5.2.2, strict variant (the non-strict scheme-elision
        // loophole "should be avoided").
        let (scheme, authority, path, query);
        if let Some(rs) = r.scheme.as_deref() {
            scheme = rs.to_owned();
            authority = r.authority.clone();
            path = remove_dot_segments(&r.path);
            query = r.query.clone();
        } else if r.authority.is_some() {
            scheme = base_scheme.to_owned();
            authority = r.authority.clone();
            path = remove_dot_segments(&r.path);
            query = r.query.clone();
        } else if r.path.is_empty() {
            scheme = base_scheme.to_owned();
            authority = self.authority.clone();
            path = self.path.clone();
            query = if r.query.is_some() {
                r.query.clone()
            } else {
                self.query.clone()
            };
        } else {
            scheme = base_scheme.to_owned();
            authority = self.authority.clone();
            path = if r.path.starts_with('/') {
                remove_dot_segments(&r.path)
            } else {
                // §5.2.3 merge, then §5.2.4.
                remove_dot_segments(&merge(self.authority.is_some(), &self.path, &r.path))
            };
            query = r.query.clone();
        }
        Ok(UriRef {
            scheme: Some(scheme),
            authority,
            path,
            query,
            // §5.2.2: "T.fragment = R.fragment;" — the base fragment
            // never propagates here. (RFC 9110 §10.2.2's redirect
            // fragment-inheritance rule is layered on top by the
            // redirect engine, not by generic resolution.)
            fragment: r.fragment.clone(),
        })
    }

    // -----------------------------------------------------------------------
    // §6 Normalization
    // -----------------------------------------------------------------------

    /// Render the syntax-normalized form (§6.2.2: case normalization,
    /// percent-encoding normalization, dot-segment removal), plus the
    /// scheme-based rules of §6.2.3 as profiled for `http`/`https` by
    /// RFC 9110 §4.2.3: elide a default port, and use `/` for an
    /// empty path when an authority is present.
    ///
    /// The output is a comparison key: "two HTTP URIs that are
    /// equivalent after normalization ... can be assumed to identify
    /// the same resource" (RFC 9110 §4.2.3). The fragment is carried
    /// through when present; strip it first (see
    /// [`UriRef::without_fragment`]) for request-identity keys.
    pub fn normalized(&self) -> String {
        let mut out = UriRef {
            scheme: self.scheme.as_deref().map(|s| s.to_ascii_lowercase()),
            authority: None,
            path: normalize_pct(&self.path, false),
            query: self.query.as_deref().map(|q| normalize_pct(q, false)),
            fragment: self.fragment.as_deref().map(|f| normalize_pct(f, false)),
        };
        out.path = remove_dot_segments(&out.path);
        let scheme = out.scheme.as_deref().unwrap_or("");
        let default_port: Option<u32> = match scheme {
            "http" => Some(80),
            "https" => Some(443),
            _ => None,
        };
        if self.authority.is_some() {
            let mut auth = String::new();
            if let Ok((ui, host, port)) = self.authority_parts() {
                if let Some(ui) = ui {
                    auth.push_str(&normalize_pct(ui, false));
                    auth.push('@');
                }
                // §6.2.2.1: host is case-insensitive → lowercase.
                auth.push_str(&normalize_pct(host.unwrap_or(""), true));
                match port {
                    // §6.2.3 / RFC 9110 §4.2.3: an empty or default
                    // port is elided in the normal form.
                    None | Some("") => {}
                    Some(p) if p.parse::<u32>().ok() == default_port => {}
                    Some(p) => {
                        auth.push(':');
                        auth.push_str(p);
                    }
                }
            } else {
                // Structurally ambiguous authority — normalize
                // conservatively (verbatim, lowercased).
                auth = self.authority.as_deref().unwrap_or("").to_ascii_lowercase();
            }
            out.authority = Some(auth);
            // RFC 9110 §4.2.3: "an empty path component is equivalent
            // to an absolute path of '/'".
            if out.path.is_empty() && default_port.is_some() {
                out.path.push('/');
            }
        }
        out.to_string()
    }
}

/// §6.2.2.1 + §6.2.2.2 percent-encoding normalization over one
/// component: uppercase the HEXDIGs of retained triplets, decode
/// triplets whose octet is unreserved, and (when `lower` — for the
/// case-insensitive host) lowercase the raw characters.
fn normalize_pct(s: &str, lower: bool) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' && i + 2 < bytes.len() {
            let (h, l) = (bytes[i + 1], bytes[i + 2]);
            if h.is_ascii_hexdigit() && l.is_ascii_hexdigit() {
                let val = (hex_val(h) << 4) | hex_val(l);
                if is_unreserved(val) {
                    let c = if lower { val.to_ascii_lowercase() } else { val };
                    out.push(c as char);
                } else {
                    out.push('%');
                    out.push(h.to_ascii_uppercase() as char);
                    out.push(l.to_ascii_uppercase() as char);
                }
                i += 3;
                continue;
            }
        }
        let c = if lower { b.to_ascii_lowercase() } else { b };
        // Non-ASCII bytes only appear here on the lenient-parse path;
        // push the raw byte through unchanged via the original str
        // slice to stay valid UTF-8.
        if c.is_ascii() {
            out.push(c as char);
            i += 1;
        } else {
            let ch_len = utf8_len(b);
            let end = (i + ch_len).min(bytes.len());
            out.push_str(&s[i..end]);
            i = end;
        }
    }
    out
}

fn utf8_len(b: u8) -> usize {
    match b {
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => 1,
    }
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        _ => b - b'A' + 10,
    }
}

/// §5.2.3 merge: combine a relative-path reference with the base
/// path.
fn merge(base_has_authority: bool, base_path: &str, ref_path: &str) -> String {
    if base_has_authority && base_path.is_empty() {
        // "return a string consisting of '/' concatenated with the
        // reference's path"
        return format!("/{ref_path}");
    }
    // "the reference's path component appended to all but the last
    // segment of the base URI's path (i.e., excluding any characters
    // after the right-most '/' ..., or excluding the entire base URI
    // path if it does not contain any '/' characters)"
    match base_path.rfind('/') {
        Some(i) => format!("{}{}", &base_path[..=i], ref_path),
        None => ref_path.to_owned(),
    }
}

/// §5.2.4 remove_dot_segments, implemented with the two-buffer
/// method the RFC describes.
pub(crate) fn remove_dot_segments(path: &str) -> String {
    // 1. input buffer := path; output buffer := "".
    let mut input = path.to_owned();
    let mut output = String::with_capacity(path.len());
    while !input.is_empty() {
        if let Some(rest) = input.strip_prefix("../") {
            // 2A: remove "../" prefix.
            input = rest.to_owned();
        } else if let Some(rest) = input.strip_prefix("./") {
            // 2A: remove "./" prefix.
            input = rest.to_owned();
        } else if let Some(rest) = input.strip_prefix("/./") {
            // 2B: replace "/./" prefix with "/".
            input = format!("/{rest}");
        } else if input == "/." {
            // 2B: replace "/." (complete segment) with "/".
            input = "/".to_owned();
        } else if let Some(rest) = input.strip_prefix("/../") {
            // 2C: replace "/../" prefix with "/", pop output segment.
            input = format!("/{rest}");
            pop_last_segment(&mut output);
        } else if input == "/.." {
            // 2C: replace "/.." (complete segment) with "/", pop.
            input = "/".to_owned();
            pop_last_segment(&mut output);
        } else if input == "." || input == ".." {
            // 2D: a bare "." / ".." input is dropped.
            input.clear();
        } else {
            // 2E: move the first segment (with its leading "/", if
            // any) to the output buffer.
            let start = usize::from(input.starts_with('/'));
            let end = input[start..]
                .find('/')
                .map(|i| i + start)
                .unwrap_or(input.len());
            output.push_str(&input[..end]);
            input.drain(..end);
        }
    }
    // 3. return the output buffer.
    output
}

/// 2C's "remove the last segment and its preceding '/' (if any) from
/// the output buffer".
fn pop_last_segment(output: &mut String) {
    match output.rfind('/') {
        Some(i) => output.truncate(i),
        None => output.clear(),
    }
}

impl fmt::Display for UriRef {
    /// §5.3 component recomposition — preserves the
    /// defined-but-empty vs undefined distinction.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(s) = &self.scheme {
            write!(f, "{s}:")?;
        }
        if let Some(a) = &self.authority {
            write!(f, "//{a}")?;
        }
        f.write_str(&self.path)?;
        if let Some(q) = &self.query {
            write!(f, "?{q}")?;
        }
        if let Some(fr) = &self.fragment {
            write!(f, "#{fr}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> UriRef {
        // §5.4: "Within a representation with a well defined base URI
        // of http://a/b/c/d;p?q".
        UriRef::parse("http://a/b/c/d;p?q").expect("base parses")
    }

    fn resolve(reference: &str) -> String {
        let r = UriRef::parse(reference).expect("reference parses");
        base().resolve(&r).expect("resolves").to_string()
    }

    #[test]
    fn rfc3986_section_5_4_1_normal_examples() {
        // Every §5.4.1 pair, verbatim.
        let cases = [
            ("g:h", "g:h"),
            ("g", "http://a/b/c/g"),
            ("./g", "http://a/b/c/g"),
            ("g/", "http://a/b/c/g/"),
            ("/g", "http://a/g"),
            ("//g", "http://g"),
            ("?y", "http://a/b/c/d;p?y"),
            ("g?y", "http://a/b/c/g?y"),
            ("#s", "http://a/b/c/d;p?q#s"),
            ("g#s", "http://a/b/c/g#s"),
            ("g?y#s", "http://a/b/c/g?y#s"),
            (";x", "http://a/b/c/;x"),
            ("g;x", "http://a/b/c/g;x"),
            ("g;x?y#s", "http://a/b/c/g;x?y#s"),
            ("", "http://a/b/c/d;p?q"),
            (".", "http://a/b/c/"),
            ("./", "http://a/b/c/"),
            ("..", "http://a/b/"),
            ("../", "http://a/b/"),
            ("../g", "http://a/b/g"),
            ("../..", "http://a/"),
            ("../../", "http://a/"),
            ("../../g", "http://a/g"),
        ];
        for (r, want) in cases {
            assert_eq!(resolve(r), want, "reference {r:?}");
        }
    }

    #[test]
    fn rfc3986_section_5_4_2_abnormal_examples() {
        // Every §5.4.2 pair, verbatim.
        let cases = [
            ("../../../g", "http://a/g"),
            ("../../../../g", "http://a/g"),
            ("/./g", "http://a/g"),
            ("/../g", "http://a/g"),
            ("g.", "http://a/b/c/g."),
            (".g", "http://a/b/c/.g"),
            ("g..", "http://a/b/c/g.."),
            ("..g", "http://a/b/c/..g"),
            ("./../g", "http://a/b/g"),
            ("./g/.", "http://a/b/c/g/"),
            ("g/./h", "http://a/b/c/g/h"),
            ("g/../h", "http://a/b/c/h"),
            ("g;x=1/./y", "http://a/b/c/g;x=1/y"),
            ("g;x=1/../y", "http://a/b/c/y"),
            ("g?y/./x", "http://a/b/c/g?y/./x"),
            ("g?y/../x", "http://a/b/c/g?y/../x"),
            ("g#s/./x", "http://a/b/c/g#s/./x"),
            ("g#s/../x", "http://a/b/c/g#s/../x"),
        ];
        for (r, want) in cases {
            assert_eq!(resolve(r), want, "reference {r:?}");
        }
    }

    #[test]
    fn strict_resolution_keeps_same_scheme_reference_absolute() {
        // §5.4.2 closing note: "http:g" resolves to "http:g" for a
        // strict parser (the non-strict loophole "should be
        // avoided").
        assert_eq!(resolve("http:g"), "http:g");
    }

    #[test]
    fn remove_dot_segments_matches_section_5_2_4_worked_examples() {
        // The two §5.2.4 buffer walk-throughs.
        assert_eq!(remove_dot_segments("/a/b/c/./../../g"), "/a/g");
        assert_eq!(remove_dot_segments("mid/content=5/../6"), "mid/6");
    }

    #[test]
    fn parse_splits_all_five_components() {
        let u = UriRef::parse("https://u:p@h.example:8443/p/q?x=1#frag").expect("parse");
        assert_eq!(u.scheme(), Some("https"));
        assert_eq!(u.authority(), Some("u:p@h.example:8443"));
        assert_eq!(u.path(), "/p/q");
        assert_eq!(u.query(), Some("x=1"));
        assert_eq!(u.fragment(), Some("frag"));
        let (ui, host, port) = u.authority_parts().expect("authority splits");
        assert_eq!(ui, Some("u:p"));
        assert_eq!(host, Some("h.example"));
        assert_eq!(port, Some("8443"));
    }

    #[test]
    fn parse_roundtrips_verbatim() {
        // §5.3: recomposition preserves the undefined vs empty
        // distinction.
        for s in [
            "http://h/p?q#f",
            "http://h/p?#",
            "http://h",
            "http://h/",
            "//h/p",
            "/p",
            "p",
            "",
            "?q",
            "#f",
            "http://h:8080/a%2Fb",
            "http://[::1]:9/x",
            "mailto:someone",
        ] {
            assert_eq!(
                UriRef::parse(s).expect("parse").to_string(),
                s,
                "round-trip {s:?}"
            );
        }
    }

    #[test]
    fn parse_rejects_out_of_grammar_bytes() {
        for s in [
            "http://h/a b",       // raw space in path
            "http://h/%zz",       // broken pct-encoding
            "http://h/%2",        // truncated pct-encoding
            "http://h\u{7f}/",    // control byte in host
            "http://h/p\u{1}",    // control byte in path
            "http://ho st/",      // space in host
            "http://h:80a/",      // non-digit port
            "http://[::1/x",      // unterminated IP-literal
            "http://[::1]x/",     // junk after IP-literal
            "1http://h/x",        // first segment with ':' / bad scheme
            "http://h/x?q\u{9}y", // tab in query
        ] {
            assert!(UriRef::parse(s).is_err(), "{s:?} must be rejected");
        }
    }

    #[test]
    fn lenient_parse_accepts_odd_path_bytes_but_keeps_structure() {
        // Path charset is not enforced leniently…
        let u = UriRef::parse_lenient("http://h/a|b{c}").expect("lenient");
        assert_eq!(u.path(), "/a|b{c}");
        // …but structure still is.
        assert!(UriRef::parse_lenient("http://h:80a/").is_err());
        assert!(UriRef::parse_lenient("http://[::1/x").is_err());
        assert!(UriRef::parse_lenient("http://h/a b").is_err());
    }

    #[test]
    fn ipv6_literal_hosts_parse_with_ports() {
        let u = UriRef::parse("http://[2001:db8::1]:8080/x").expect("parse");
        let (ui, host, port) = u.authority_parts().expect("split");
        assert_eq!(ui, None);
        assert_eq!(host, Some("[2001:db8::1]"));
        assert_eq!(port, Some("8080"));
        // IPvFuture form (§3.2.2).
        assert!(UriRef::parse("http://[v7.fe]/x").is_ok());
        assert!(UriRef::parse("http://[vX.fe]/x").is_err());
    }

    #[test]
    fn normalized_applies_case_pct_and_scheme_rules() {
        // §6.2.2 + §6.2.3 + RFC 9110 §4.2.3 worked examples.
        let cases = [
            // RFC 9110 §4.2.3's three equivalent URIs.
            (
                "http://example.com:80/~smith/home.html",
                "http://example.com/~smith/home.html",
            ),
            (
                "http://EXAMPLE.com/%7Esmith/home.html",
                "http://example.com/~smith/home.html",
            ),
            (
                "http://EXAMPLE.com:/%7esmith/home.html",
                "http://example.com/~smith/home.html",
            ),
            // §6.2.3: empty path → "/", default port elision.
            ("http://example.com", "http://example.com/"),
            ("http://example.com:/", "http://example.com/"),
            ("http://example.com:80/", "http://example.com/"),
            ("https://example.com:443", "https://example.com/"),
            // Non-default port survives.
            ("http://example.com:8080/", "http://example.com:8080/"),
            // §6.2.2.1: pct HEXDIG uppercased when retained.
            ("http://h/%3a", "http://h/%3A"),
            // §6.2.2.3: dot segments removed.
            ("http://h/a/./b/../c", "http://h/a/c"),
            // Scheme case-insensitive (§6.2.2.1).
            ("HTTP://h/", "http://h/"),
        ];
        for (input, want) in cases {
            assert_eq!(
                UriRef::parse(input).expect("parse").normalized(),
                want,
                "normalize {input:?}"
            );
        }
    }

    #[test]
    fn normalized_is_a_stable_equivalence_key() {
        // The §6.2.2 example pair (schemes swapped to http for the
        // §6.2.3 port/path rules to apply).
        let a = UriRef::parse("http://a/b/c/%7Bfoo%7D").expect("a");
        let b = UriRef::parse("HTTP://a/./b/../b/%63/%7bfoo%7d").expect("b");
        assert_eq!(a.normalized(), b.normalized());
    }

    #[test]
    fn resolve_requires_absolute_base() {
        let rel = UriRef::parse("/only/path").expect("parse");
        let r = UriRef::parse("x").expect("parse");
        let e = rel.resolve(&r).expect_err("relative base must fail");
        assert!(e.to_string().contains("absolute"), "{e}");
    }

    #[test]
    fn without_fragment_strips_only_the_fragment() {
        let u = UriRef::parse("http://h/p?q#f").expect("parse");
        assert_eq!(u.without_fragment().to_string(), "http://h/p?q");
        // Undefined stays undefined; empty stays empty.
        let v = UriRef::parse("http://h/p#").expect("parse");
        assert_eq!(v.fragment(), Some(""));
        assert_eq!(v.without_fragment().to_string(), "http://h/p");
    }

    #[test]
    fn empty_base_path_merge_inserts_slash() {
        // §5.2.3 first bullet: authority + empty path → "/" + ref.
        let b = UriRef::parse("http://h").expect("base");
        let r = UriRef::parse("g").expect("ref");
        assert_eq!(b.resolve(&r).expect("resolve").to_string(), "http://h/g");
    }
}
