//! HTTP/HTTPS source driver for oxideav.
//!
//! Implements `Read + Seek` over HTTP `Range` requests so any container
//! demuxer that takes a `Box<dyn BytesSource>` can read directly from a
//! URL. Servers must support `Range: bytes=…` (most static-file hosts
//! do; we verify with a `HEAD` at construction).
//!
//! Wire it into a [`oxideav_core::RuntimeContext`] with [`register`]:
//! both `http` and `https` register as bytes-shape sources, so
//! `ctx.sources.open(uri)` yields `SourceOutput::Bytes(_)`. For callers
//! that hold a bare [`oxideav_source::SourceRegistry`] use
//! [`register_source`] directly.
//!
//! ```no_run
//! let mut ctx = oxideav_core::RuntimeContext::new();
//! oxideav_http::register(&mut ctx);
//! let _r = ctx.sources.open("https://example.com/clip.mp4").unwrap();
//! ```
//!
//! ## Configuring the underlying agent
//!
//! By default the driver uses a process-wide `ureq` agent with library
//! defaults. To tighten policy (redirect cap, downgrade-safe
//! `Authorization` handling, custom `User-Agent`, timeouts, https-only
//! mode) build an [`HttpConfig`] and either:
//!
//! 1. Install it once at startup with [`install_default_config`], so
//!    every `ctx.sources.open("http://…")` call honours it; or
//! 2. Open a one-off source with [`HttpSource::open_with_config`],
//!    leaving the registry-default agent untouched.
//!
//! ```no_run
//! let cfg = oxideav_http::HttpConfig::builder()
//!     .max_redirects(5)
//!     .user_agent("my-app/1.0")
//!     .https_only(true)
//!     .build();
//! oxideav_http::install_default_config(cfg).ok();
//! ```

use std::io::{self, Read, Seek, SeekFrom};
use std::sync::OnceLock;
use std::time::Duration;

use oxideav_core::BytesSource;
use oxideav_core::RuntimeContext;
use oxideav_core::{Error, Result};
use oxideav_source::SourceRegistry;
use ureq::Agent;

/// Install the `http` + `https` schemes into a full runtime context.
///
/// This is the unified entry point every sibling crate exposes; it
/// just forwards to [`register_source`] on `ctx.sources`.
pub fn register(ctx: &mut RuntimeContext) {
    register_source(&mut ctx.sources);
}

oxideav_core::register!("http", register);

/// Register the `http` and `https` schemes on a bare
/// [`SourceRegistry`] as bytes sources. Both schemes share the same
/// opener (`open_http`).
///
/// Most callers should use [`register`] instead — it threads through a
/// full [`RuntimeContext`].
pub fn register_source(registry: &mut SourceRegistry) {
    registry.register_bytes("http", open_http);
    registry.register_bytes("https", open_http);
}

/// Open a URL as a seekable byte source.
pub fn open_http(uri: &str) -> Result<Box<dyn BytesSource>> {
    let src = HttpSource::open(uri)?;
    Ok(Box::new(src))
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Policy for re-sending an `Authorization` header across an HTTP
/// redirect.
///
/// Mirrors `ureq::config::RedirectAuthHeaders` — exposed here so the
/// public surface stays independent of which underlying client we wire
/// in. Default is [`RedirectAuthPolicy::Never`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum RedirectAuthPolicy {
    /// Strip `Authorization` on every redirect.
    #[default]
    Never,
    /// Keep `Authorization` only when the target shares the origin host
    /// and the scheme does not downgrade (e.g. `https` → `https` is
    /// fine, `https` → `http` is not).
    SameHost,
}

/// Tunable policy for the HTTP/HTTPS source driver.
///
/// Build with [`HttpConfig::builder`]; finalised with
/// [`HttpConfigBuilder::build`]. A default `HttpConfig` matches the
/// library's pre-r77 behaviour: ureq defaults, no extra restrictions,
/// `Authorization` stripped on redirect.
///
/// `HttpConfig` is a thin policy struct; it does *not* itself hold the
/// underlying agent. Either install one globally with
/// [`install_default_config`] (one-shot, before the first open call)
/// or pass to [`HttpSource::open_with_config`] per-request.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    max_redirects: u32,
    max_redirects_will_error: bool,
    redirect_auth_policy: RedirectAuthPolicy,
    user_agent: Option<String>,
    https_only: bool,
    timeout_global: Option<Duration>,
    timeout_connect: Option<Duration>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        // ureq 3 defaults: 10 redirects, error on cap, no user-agent
        // override, no https-only, no timeouts. We override
        // `redirect_auth_policy` to `Never` (matches ureq's own
        // default but pin it explicitly for surface clarity).
        Self {
            max_redirects: 10,
            max_redirects_will_error: true,
            redirect_auth_policy: RedirectAuthPolicy::Never,
            user_agent: None,
            https_only: false,
            timeout_global: None,
            timeout_connect: None,
        }
    }
}

impl HttpConfig {
    /// Start a builder pre-populated with the library defaults.
    pub fn builder() -> HttpConfigBuilder {
        HttpConfigBuilder {
            inner: Self::default(),
        }
    }

    /// Maximum number of redirects the client will follow before
    /// giving up.
    pub fn max_redirects(&self) -> u32 {
        self.max_redirects
    }

    /// Whether exceeding [`Self::max_redirects`] surfaces as an error
    /// (`true`) or returns the final 3xx response (`false`).
    pub fn max_redirects_will_error(&self) -> bool {
        self.max_redirects_will_error
    }

    /// Redirect handling for the `Authorization` header.
    pub fn redirect_auth_policy(&self) -> RedirectAuthPolicy {
        self.redirect_auth_policy
    }

    /// Custom `User-Agent` header value, if set.
    pub fn user_agent(&self) -> Option<&str> {
        self.user_agent.as_deref()
    }

    /// Whether to reject all `http://` requests (including redirect
    /// targets) at the agent level.
    pub fn https_only(&self) -> bool {
        self.https_only
    }

    /// End-to-end timeout for an entire call (DNS through body read).
    pub fn timeout_global(&self) -> Option<Duration> {
        self.timeout_global
    }

    /// Maximum time to establish a connection (TCP + TLS handshake).
    pub fn timeout_connect(&self) -> Option<Duration> {
        self.timeout_connect
    }
}

/// Builder for [`HttpConfig`].
#[derive(Debug, Clone)]
pub struct HttpConfigBuilder {
    inner: HttpConfig,
}

impl HttpConfigBuilder {
    /// Cap the redirect chain. ureq's default is 10.
    pub fn max_redirects(mut self, n: u32) -> Self {
        self.inner.max_redirects = n;
        self
    }

    /// If `true`, hitting [`HttpConfigBuilder::max_redirects`] is an
    /// error (default); if `false`, the last 3xx response is returned.
    pub fn max_redirects_will_error(mut self, v: bool) -> Self {
        self.inner.max_redirects_will_error = v;
        self
    }

    /// How `Authorization` should be carried across redirects. Default
    /// is [`RedirectAuthPolicy::Never`].
    pub fn redirect_auth_policy(mut self, p: RedirectAuthPolicy) -> Self {
        self.inner.redirect_auth_policy = p;
        self
    }

    /// Override the `User-Agent` request header. ureq's own default
    /// (`ureq/<version>`) is used when this is left unset.
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.inner.user_agent = Some(ua.into());
        self
    }

    /// When `true`, the agent refuses any non-`https` URL, including
    /// redirect targets. Default `false`.
    pub fn https_only(mut self, v: bool) -> Self {
        self.inner.https_only = v;
        self
    }

    /// End-to-end timeout for an entire call. None = unlimited.
    pub fn timeout_global(mut self, d: Option<Duration>) -> Self {
        self.inner.timeout_global = d;
        self
    }

    /// Connect timeout (TCP + TLS handshake). None = unlimited.
    pub fn timeout_connect(mut self, d: Option<Duration>) -> Self {
        self.inner.timeout_connect = d;
        self
    }

    /// Finalise the policy.
    pub fn build(self) -> HttpConfig {
        self.inner
    }
}

fn agent_from(cfg: &HttpConfig) -> Agent {
    let mut b = Agent::config_builder()
        .max_redirects(cfg.max_redirects)
        .max_redirects_will_error(cfg.max_redirects_will_error)
        .https_only(cfg.https_only)
        .redirect_auth_headers(match cfg.redirect_auth_policy {
            RedirectAuthPolicy::Never => ureq::config::RedirectAuthHeaders::Never,
            RedirectAuthPolicy::SameHost => ureq::config::RedirectAuthHeaders::SameHost,
        });
    if let Some(ua) = cfg.user_agent.as_deref() {
        b = b.user_agent(ua);
    }
    b = b
        .timeout_global(cfg.timeout_global)
        .timeout_connect(cfg.timeout_connect);
    b.build().new_agent()
}

// ---------------------------------------------------------------------------
// Default / global agent
// ---------------------------------------------------------------------------

static DEFAULT_CONFIG: OnceLock<HttpConfig> = OnceLock::new();
static DEFAULT_AGENT: OnceLock<Agent> = OnceLock::new();

/// Returned by [`install_default_config`] when the global agent has
/// already been materialised (either by a prior `install_default_config`
/// call or by a `register`/`open` call that consumed the default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigAlreadyInstalled;

impl std::fmt::Display for ConfigAlreadyInstalled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("oxideav-http default config has already been installed")
    }
}

impl std::error::Error for ConfigAlreadyInstalled {}

/// Install a process-wide [`HttpConfig`] that the default scheme
/// openers ([`register`], [`register_source`], [`open_http`]) will use.
///
/// One-shot: returns [`ConfigAlreadyInstalled`] if either the config or
/// the agent has already been built. Call this once during program
/// start-up, *before* the first source-registry open. Per-call
/// overrides remain available through [`HttpSource::open_with_config`]
/// even after a default has been installed.
pub fn install_default_config(cfg: HttpConfig) -> std::result::Result<(), ConfigAlreadyInstalled> {
    if DEFAULT_AGENT.get().is_some() {
        return Err(ConfigAlreadyInstalled);
    }
    DEFAULT_CONFIG.set(cfg).map_err(|_| ConfigAlreadyInstalled)
}

fn agent() -> &'static Agent {
    DEFAULT_AGENT.get_or_init(|| {
        let cfg = DEFAULT_CONFIG.get().cloned().unwrap_or_default();
        agent_from(&cfg)
    })
}

// ---------------------------------------------------------------------------
// HttpSource
// ---------------------------------------------------------------------------

/// `ReadSeek` over an HTTP/HTTPS resource, using `Range` requests.
pub struct HttpSource {
    uri: String,
    total_len: u64,
    pos: u64,
    /// Per-source agent. When `None` we use the shared default agent.
    agent: Option<Agent>,
    /// Active response body for the current contiguous read run, if any.
    body: Option<Box<dyn Read + Send>>,
}

impl HttpSource {
    /// Open a URL with the process-wide default agent.
    ///
    /// See [`install_default_config`] for how to tune that agent
    /// once at startup. For one-off overrides without touching the
    /// global agent, use [`HttpSource::open_with_config`].
    pub fn open(uri: &str) -> Result<Self> {
        Self::open_impl(uri, None)
    }

    /// Open a URL using a one-off agent built from `cfg`.
    ///
    /// The agent is owned by the returned `HttpSource` and dropped
    /// when it goes out of scope; the process-wide default agent is
    /// unaffected.
    pub fn open_with_config(uri: &str, cfg: &HttpConfig) -> Result<Self> {
        Self::open_impl(uri, Some(agent_from(cfg)))
    }

    fn open_impl(uri: &str, scoped: Option<Agent>) -> Result<Self> {
        let head_agent: &Agent = scoped.as_ref().unwrap_or_else(|| agent());
        let head = head_agent
            .head(uri)
            .call()
            .map_err(|e| Error::other(format!("HTTP HEAD {uri}: {e}")))?;

        let status = head.status();
        if !status.is_success() {
            return Err(Error::other(format!("HTTP HEAD {uri}: status {status}")));
        }
        let headers = head.headers();
        let total_len = headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| {
                Error::Unsupported(format!("HTTP HEAD {uri}: missing Content-Length"))
            })?;
        let accept_ranges = headers
            .get("accept-ranges")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !accept_ranges.eq_ignore_ascii_case("bytes") {
            return Err(Error::Unsupported(format!(
                "HTTP HEAD {uri}: server does not advertise byte ranges (Accept-Ranges: '{accept_ranges}')"
            )));
        }
        Ok(Self {
            uri: uri.to_owned(),
            total_len,
            pos: 0,
            agent: scoped,
            body: None,
        })
    }

    pub fn len(&self) -> u64 {
        self.total_len
    }

    pub fn is_empty(&self) -> bool {
        self.total_len == 0
    }

    fn agent_ref(&self) -> &Agent {
        self.agent.as_ref().unwrap_or_else(|| agent())
    }

    fn issue_range(&mut self) -> io::Result<()> {
        if self.pos >= self.total_len {
            self.body = None;
            return Ok(());
        }
        let range = format!("bytes={}-", self.pos);
        let resp = self
            .agent_ref()
            .get(&self.uri)
            .header("Range", &range)
            .call()
            .map_err(|e| io::Error::other(format!("HTTP GET {} {}: {e}", self.uri, range)))?;
        let status = resp.status();
        if !(status == 206 || status == 200) {
            return Err(io::Error::other(format!(
                "HTTP GET {} {}: status {status}",
                self.uri, range
            )));
        }
        let pos = self.pos;
        let total_len = self.total_len;
        // Per RFC 7233 §3.1, a server that does not support (or chooses
        // to ignore) Range MAY answer a range request with a full 200
        // response. In that case we must drop the prefix [0, self.pos)
        // before exposing bytes to the reader so the demuxer keeps a
        // consistent file-offset view.
        let skip_prefix = if status == 200 { pos } else { 0 };
        if status == 206 {
            // RFC 7233 §4.2: validate the server's Content-Range echo
            // covers what we asked for and is self-consistent. A 206
            // without Content-Range, or with a multipart/byteranges
            // (handled at the body layer, not via Content-Range), or
            // with a different first-byte-pos than self.pos, would
            // silently misalign every subsequent read.
            let cr_raw = resp
                .headers()
                .get("content-range")
                .ok_or_else(|| {
                    io::Error::other(format!(
                        "HTTP 206 {} {}: missing Content-Range",
                        self.uri, range
                    ))
                })?
                .to_str()
                .map_err(|_| {
                    io::Error::other(format!(
                        "HTTP 206 {} {}: non-ASCII Content-Range",
                        self.uri, range
                    ))
                })?
                .to_owned();
            let parsed = parse_byte_content_range(&cr_raw).map_err(|e| {
                io::Error::other(format!(
                    "HTTP 206 {} {}: invalid Content-Range '{cr_raw}': {e}",
                    self.uri, range
                ))
            })?;
            // first-byte-pos MUST match the position we asked for. The
            // server is allowed to satisfy a partial subrange, but
            // not to slide the start.
            if parsed.first != pos {
                return Err(io::Error::other(format!(
                    "HTTP 206 {} {}: Content-Range first-byte-pos {} != requested pos {}",
                    self.uri, range, parsed.first, pos
                )));
            }
            // complete-length, when concrete, must equal the size we
            // recorded at HEAD. A mid-stream resource resize is a
            // cache/origin mismatch we cannot recover from in-band.
            if let Some(complete) = parsed.complete {
                if complete != total_len {
                    return Err(io::Error::other(format!(
                        "HTTP 206 {} {}: Content-Range complete-length {complete} != known total {total_len}",
                        self.uri, range
                    )));
                }
            }
            // last-byte-pos must lie inside the representation we
            // expect.
            if parsed.last >= total_len {
                return Err(io::Error::other(format!(
                    "HTTP 206 {} {}: Content-Range last-byte-pos {} >= total {}",
                    self.uri, range, parsed.last, total_len
                )));
            }
        }
        // ureq 3: Body owns the stream; into_body().into_reader() yields
        // a `Read` that pulls from the wire as bytes are requested.
        let mut reader: Box<dyn Read + Send> = Box::new(resp.into_body().into_reader());
        if skip_prefix > 0 {
            // Drain the prefix in 8 KiB chunks rather than allocating
            // a single huge buffer for very large seek offsets.
            let mut remaining = skip_prefix;
            let mut buf = [0u8; 8 * 1024];
            while remaining > 0 {
                let want = remaining.min(buf.len() as u64) as usize;
                let n = reader.read(&mut buf[..want])?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "HTTP 200 {}: EOF after draining {} of {skip_prefix} prefix bytes",
                            self.uri,
                            skip_prefix - remaining
                        ),
                    ));
                }
                remaining -= n as u64;
            }
        }
        self.body = Some(reader);
        Ok(())
    }
}

/// Parsed `Content-Range: bytes <first>-<last>/<complete-or-*>`.
///
/// Public-but-internal: lives in the crate so the validator and the
/// unit tests can share one parser. We deliberately do NOT export it —
/// any future surface change shouldn't drag this representation into
/// the public API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ByteContentRange {
    first: u64,
    last: u64,
    /// `None` when the server emitted `*` for complete-length.
    complete: Option<u64>,
}

/// Parse a `Content-Range` field value per RFC 7233 §4.2
/// (`bytes <first>-<last>/<complete|*>`), enforcing the §4.2 validity
/// rules on the spot:
///
/// * range unit MUST be `bytes` (case-insensitive — RFC 7230 §3.2.6
///   tokens are case-insensitive; ABNF in §4.2 happens to use the
///   lowercase literal).
/// * `last >= first` (otherwise §4.2 "byte-range-resp ... last-byte-pos
///   value less than its first-byte-pos" is invalid).
/// * `complete > last` (§4.2 "complete-length value less than or equal
///   to its last-byte-pos" is invalid).
///
/// Unsatisfied-range (`bytes */N`) is intentionally rejected here — it
/// is a 416 payload, never a 206 payload, so its arrival on a 206 is
/// itself invalid.
fn parse_byte_content_range(s: &str) -> std::result::Result<ByteContentRange, &'static str> {
    let s = s.trim();
    // unit SP byte-range-resp
    let (unit, rest) = s.split_once(' ').ok_or("missing SP after range unit")?;
    if !unit.eq_ignore_ascii_case("bytes") {
        return Err("range unit is not 'bytes'");
    }
    let rest = rest.trim_start();
    // byte-range-resp = first "-" last "/" (complete / "*")
    // unsatisfied-range = "*/" complete  — rejected for 206.
    if rest.starts_with('*') {
        return Err("unsatisfied-range ('*/N') not valid on 206");
    }
    let (range_part, complete_part) = rest
        .split_once('/')
        .ok_or("missing '/' before complete-length")?;
    let (first_s, last_s) = range_part
        .split_once('-')
        .ok_or("missing '-' between first-byte-pos and last-byte-pos")?;
    let first: u64 = first_s.parse().map_err(|_| "first-byte-pos is not a u64")?;
    let last: u64 = last_s.parse().map_err(|_| "last-byte-pos is not a u64")?;
    if last < first {
        return Err("last-byte-pos < first-byte-pos");
    }
    let complete = if complete_part == "*" {
        None
    } else {
        let c: u64 = complete_part
            .parse()
            .map_err(|_| "complete-length is not a u64 or '*'")?;
        if c <= last {
            return Err("complete-length <= last-byte-pos");
        }
        Some(c)
    };
    Ok(ByteContentRange {
        first,
        last,
        complete,
    })
}

impl Read for HttpSource {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.pos >= self.total_len {
            return Ok(0);
        }
        loop {
            if self.body.is_none() {
                self.issue_range()?;
            }
            let body = self.body.as_mut().expect("body just issued");
            let n = body.read(out)?;
            if n > 0 {
                self.pos += n as u64;
                return Ok(n);
            }
            self.body = None;
            if self.pos >= self.total_len {
                return Ok(0);
            }
        }
    }
}

impl Seek for HttpSource {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let new_pos: u64 = match from {
            SeekFrom::Start(n) => n,
            SeekFrom::Current(d) => add_signed(self.pos, d)?,
            SeekFrom::End(d) => add_signed(self.total_len, d)?,
        };
        if new_pos > self.total_len {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek past end"));
        }
        if new_pos != self.pos {
            self.body = None;
            self.pos = new_pos;
        }
        Ok(new_pos)
    }
}

fn add_signed(base: u64, delta: i64) -> io::Result<u64> {
    if delta >= 0 {
        base.checked_add(delta as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek overflow"))
    } else {
        base.checked_sub(delta.unsigned_abs())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before start"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn register_via_runtime_context_installs_http_and_https_schemes() {
        let mut ctx = RuntimeContext::new();
        register(&mut ctx);
        let schemes: BTreeSet<&str> = ctx.sources.schemes().collect();
        assert!(
            schemes.contains("http"),
            "register did not install http; got {schemes:?}"
        );
        assert!(
            schemes.contains("https"),
            "register did not install https; got {schemes:?}"
        );
    }

    #[test]
    fn register_source_installs_http_and_https_schemes_on_bare_registry() {
        let mut reg = SourceRegistry::new();
        register_source(&mut reg);
        let schemes: BTreeSet<&str> = reg.schemes().collect();
        assert!(schemes.contains("http"));
        assert!(schemes.contains("https"));
    }

    #[test]
    fn http_config_default_matches_documented_surface() {
        let c = HttpConfig::default();
        assert_eq!(c.max_redirects(), 10);
        assert!(c.max_redirects_will_error());
        assert_eq!(c.redirect_auth_policy(), RedirectAuthPolicy::Never);
        assert_eq!(c.user_agent(), None);
        assert!(!c.https_only());
        assert_eq!(c.timeout_global(), None);
        assert_eq!(c.timeout_connect(), None);
    }

    #[test]
    fn http_config_builder_threads_values_through() {
        let c = HttpConfig::builder()
            .max_redirects(3)
            .max_redirects_will_error(false)
            .redirect_auth_policy(RedirectAuthPolicy::SameHost)
            .user_agent("oxideav-test/0.0")
            .https_only(true)
            .timeout_global(Some(Duration::from_secs(30)))
            .timeout_connect(Some(Duration::from_secs(5)))
            .build();
        assert_eq!(c.max_redirects(), 3);
        assert!(!c.max_redirects_will_error());
        assert_eq!(c.redirect_auth_policy(), RedirectAuthPolicy::SameHost);
        assert_eq!(c.user_agent(), Some("oxideav-test/0.0"));
        assert!(c.https_only());
        assert_eq!(c.timeout_global(), Some(Duration::from_secs(30)));
        assert_eq!(c.timeout_connect(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn agent_from_config_succeeds_for_every_redirect_policy() {
        // Just exercise the construction path — failure modes are
        // panics inside ureq, which would surface here.
        for p in [RedirectAuthPolicy::Never, RedirectAuthPolicy::SameHost] {
            let c = HttpConfig::builder().redirect_auth_policy(p).build();
            let _ = agent_from(&c);
        }
    }

    #[test]
    fn http_config_clone_is_cheap_and_independent() {
        let a = HttpConfig::builder()
            .user_agent("alpha/1.0")
            .max_redirects(7)
            .build();
        let b = a.clone();
        assert_eq!(a.user_agent(), b.user_agent());
        assert_eq!(a.max_redirects(), b.max_redirects());
    }

    #[test]
    fn install_default_config_is_one_shot() {
        // We run this test in isolation per-process effectively — the
        // OnceLock keeps state, so try once then assert the second
        // attempt is rejected. Tests run in arbitrary order; if the
        // default agent has already materialised via another test,
        // the first install attempt itself may be rejected. Either
        // outcome must trip the "already installed" guard at some
        // point.
        let first = install_default_config(HttpConfig::default());
        // Force the agent to materialise so the second attempt is
        // guaranteed to be rejected even if the first succeeded.
        let _ = agent();
        let second = install_default_config(HttpConfig::default());
        assert!(
            first.is_err() || second.is_err(),
            "expected at least one install to be rejected once the agent is built (first={first:?}, second={second:?})"
        );
        assert_eq!(second, Err(ConfigAlreadyInstalled));
    }

    #[test]
    fn config_already_installed_implements_error_trait() {
        let e: &dyn std::error::Error = &ConfigAlreadyInstalled;
        assert!(e.to_string().contains("already"));
    }

    // -- RFC 7233 §4.2 Content-Range parser ----------------------------------

    #[test]
    fn content_range_parses_canonical_form() {
        let r = parse_byte_content_range("bytes 42-1233/1234").unwrap();
        assert_eq!(
            r,
            ByteContentRange {
                first: 42,
                last: 1233,
                complete: Some(1234),
            }
        );
    }

    #[test]
    fn content_range_accepts_star_complete_length() {
        // RFC 7233 §4.2: "An asterisk character ('*') in place of the
        // complete-length indicates that the representation length was
        // unknown when the header field was generated."
        let r = parse_byte_content_range("bytes 42-1233/*").unwrap();
        assert_eq!(r.first, 42);
        assert_eq!(r.last, 1233);
        assert_eq!(r.complete, None);
    }

    #[test]
    fn content_range_accepts_full_resource_first_last() {
        let r = parse_byte_content_range("bytes 0-0/1").unwrap();
        assert_eq!(r.first, 0);
        assert_eq!(r.last, 0);
        assert_eq!(r.complete, Some(1));
    }

    #[test]
    fn content_range_unit_is_case_insensitive() {
        // RFC 7230 §3.2.6 tokens are case-insensitive.
        assert!(parse_byte_content_range("BYTES 0-9/10").is_ok());
        assert!(parse_byte_content_range("Bytes 0-9/10").is_ok());
    }

    #[test]
    fn content_range_rejects_unknown_unit() {
        // RFC 7233 §4.2: "If a 206 (Partial Content) response contains
        // a Content-Range header field with a range unit (Section 2)
        // that the recipient does not understand, the recipient MUST
        // NOT attempt to recombine it with a stored representation."
        assert!(parse_byte_content_range("frames 0-9/100").is_err());
    }

    #[test]
    fn content_range_rejects_last_lt_first() {
        // §4.2: invalid if last-byte-pos < first-byte-pos.
        assert!(parse_byte_content_range("bytes 100-50/200").is_err());
    }

    #[test]
    fn content_range_rejects_complete_le_last() {
        // §4.2: invalid if complete-length <= last-byte-pos.
        assert!(parse_byte_content_range("bytes 0-100/100").is_err());
        assert!(parse_byte_content_range("bytes 0-100/50").is_err());
    }

    #[test]
    fn content_range_rejects_unsatisfied_payload_on_206() {
        // §4.2 unsatisfied-range = "*/" complete is a 416 payload, not
        // a 206 payload — we reject it at parse time.
        assert!(parse_byte_content_range("bytes */1234").is_err());
    }

    #[test]
    fn content_range_rejects_malformed_strings() {
        for bad in [
            "",
            "bytes",
            "bytes 0-9",                       // missing /complete
            "bytes 09/10",                     // missing -
            "bytes a-9/10",                    // non-numeric first
            "bytes 0-b/10",                    // non-numeric last
            "bytes 0-9/x",                     // non-numeric complete
            "bytes 18446744073709551616-0/10", // u64 overflow on first
            "0-9/10",                          // missing unit + SP
        ] {
            assert!(
                parse_byte_content_range(bad).is_err(),
                "expected reject for {bad:?}"
            );
        }
    }

    // -- Local-TCP end-to-end tests ------------------------------------------
    //
    // These spin up a single-shot std::net::TcpListener on 127.0.0.1:0,
    // accept N connections, hand-craft minimal HTTP/1.1 responses, and
    // verify our HttpSource's Content-Range validator catches the
    // bad-server cases and accepts the canonical-server cases. They do
    // not depend on external network reachability.

    use std::io::Write as _;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    /// Spawn a minimal HTTP/1.1 server on 127.0.0.1:0 that responds to
    /// `HEAD` requests with `head_resp` and to `GET` requests with
    /// `get_resp`. Each response is the literal byte string the test
    /// supplies (status line + headers + CRLF + body, no
    /// chunked-encoding).
    fn spawn_server(
        head_resp: &'static [u8],
        get_resp: &'static [u8],
    ) -> (String, mpsc::Receiver<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel::<()>();
        thread::spawn(move || {
            // Accept up to 4 connections so HEAD + GET (and one retry)
            // all land. ureq may use separate connections.
            for _ in 0..4 {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut buf = [0u8; 4096];
                use std::io::Read as _;
                let n = stream.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    continue;
                }
                let req = &buf[..n];
                let resp = if req.starts_with(b"HEAD ") {
                    head_resp
                } else {
                    get_resp
                };
                let _ = stream.write_all(resp);
                let _ = stream.flush();
            }
            let _ = tx.send(());
        });
        (format!("http://127.0.0.1:{port}/x"), rx)
    }

    const HEAD_10B_BYTES: &[u8] = b"HTTP/1.1 200 OK\r\n\
        Content-Length: 10\r\n\
        Accept-Ranges: bytes\r\n\
        Connection: close\r\n\
        \r\n";

    fn make_get_206(content_range: &str, body: &[u8]) -> Vec<u8> {
        let mut v = format!(
            "HTTP/1.1 206 Partial Content\r\n\
             Content-Length: {}\r\n\
             Content-Range: {content_range}\r\n\
             Connection: close\r\n\
             \r\n",
            body.len()
        )
        .into_bytes();
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn local_server_canonical_206_succeeds() {
        // Static GET response: Content-Range echoes the requested
        // open-ended `bytes=0-`, body is the full 10 B.
        static GET: &[u8] = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Length: 10\r\n\
            Content-Range: bytes 0-9/10\r\n\
            Connection: close\r\n\
            \r\n\
            0123456789";
        let (uri, _done) = spawn_server(HEAD_10B_BYTES, GET);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        assert_eq!(&buf, b"0123456789");
    }

    #[test]
    fn local_server_206_without_content_range_is_rejected() {
        static GET: &[u8] = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Length: 10\r\n\
            Connection: close\r\n\
            \r\n\
            0123456789";
        let (uri, _done) = spawn_server(HEAD_10B_BYTES, GET);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        let err = std::io::Read::read_exact(&mut src, &mut buf).unwrap_err();
        assert!(
            err.to_string().contains("missing Content-Range"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn local_server_206_with_wrong_first_pos_is_rejected() {
        // We ask for bytes=0-; server replies with bytes 3-9/10 — that
        // would silently misalign the demuxer.
        static GET: &[u8] = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Length: 7\r\n\
            Content-Range: bytes 3-9/10\r\n\
            Connection: close\r\n\
            \r\n\
            3456789";
        let (uri, _done) = spawn_server(HEAD_10B_BYTES, GET);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        let err = std::io::Read::read_exact(&mut src, &mut buf).unwrap_err();
        assert!(
            err.to_string().contains("first-byte-pos"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn local_server_206_with_resource_resize_is_rejected() {
        // HEAD said 10; 206 says complete-length 20 — origin/cache
        // disagreement we cannot recover from in-band.
        static GET: &[u8] = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Length: 10\r\n\
            Content-Range: bytes 0-9/20\r\n\
            Connection: close\r\n\
            \r\n\
            0123456789";
        let (uri, _done) = spawn_server(HEAD_10B_BYTES, GET);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        let err = std::io::Read::read_exact(&mut src, &mut buf).unwrap_err();
        assert!(
            err.to_string().contains("complete-length"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn local_server_206_with_star_complete_is_accepted() {
        // RFC 7233 §4.2 explicitly permits `*` complete-length when
        // the server doesn't know the total. We must accept it.
        static GET: &[u8] = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Length: 10\r\n\
            Content-Range: bytes 0-9/*\r\n\
            Connection: close\r\n\
            \r\n\
            0123456789";
        let (uri, _done) = spawn_server(HEAD_10B_BYTES, GET);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        assert_eq!(&buf, b"0123456789");
    }

    #[test]
    fn local_server_200_after_seek_drops_prefix() {
        // Server ignores Range entirely and serves full body with 200.
        // We seek to byte 4 first; the driver must drain bytes 0..4
        // before exposing byte 4 onward to the reader.
        static GET: &[u8] = b"HTTP/1.1 200 OK\r\n\
            Content-Length: 10\r\n\
            Connection: close\r\n\
            \r\n\
            0123456789";
        let (uri, _done) = spawn_server(HEAD_10B_BYTES, GET);
        let mut src = HttpSource::open(&uri).expect("open");
        std::io::Seek::seek(&mut src, SeekFrom::Start(4)).unwrap();
        let mut buf = [0u8; 6];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        assert_eq!(&buf, b"456789");
    }

    // Silence "unused" warning when these helpers aren't all picked up
    // — make_get_206 is a convenience the next test round may use.
    #[allow(dead_code)]
    fn _keep_helper() {
        let _ = make_get_206("bytes 0-9/10", b"0123456789");
    }
}
