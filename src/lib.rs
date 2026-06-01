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
//!
//! ## Mid-stream mutation detection (RFC 9110 §13.1.5)
//!
//! When the origin's `HEAD` reply carries a STRONG validator (an ETag
//! without the `W/` weakness prefix, or a `Last-Modified` whose
//! companion `Date` header is at least one second later — the §8.8.2.2
//! promotion rule), every subsequent `Range: bytes=N-` GET is sent
//! with `If-Range: <validator>`. Per §13.1.5 the server then EITHER
//! satisfies the range (`206 Partial Content` — happy path) OR ignores
//! `Range` and returns the full new representation (`200 OK`). The
//! driver treats the latter as a fatal mid-stream-mutation error
//! rather than silently re-anchoring the byte offset against a
//! different resource.

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
        })
        // Inspect 4xx/5xx ourselves so we can give RFC 9110 §15.5.17 +
        // §14.4 treatment to 416 (Range Not Satisfiable). With the
        // status-as-error default, the response's Content-Range body is
        // surfaced as an opaque status string and the unsatisfied-range
        // payload is lost before our handler ever sees it.
        .http_status_as_error(false);
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

/// Strong validator captured at HEAD construction, used as the
/// `If-Range` value on subsequent `Range` GETs per RFC 9110 §13.1.5.
///
/// Per §13.1.5 a client MUST NOT send a weak entity tag in `If-Range`,
/// and a `Last-Modified`-based `If-Range` is only legitimate when the
/// `Last-Modified` value is a strong validator per §8.8.2.2 (here:
/// the HEAD response's `Date` is at least one second after its
/// `Last-Modified`). When neither condition holds we record `None`
/// and the GET path goes out without `If-Range`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum StrongValidator {
    /// `ETag: "<opaque>"` — already verified strong (no `W/` prefix).
    /// Stored as the wire form (with surrounding double quotes).
    Etag(String),
    /// `Last-Modified: <HTTP-date>` deemed strong by the §8.8.2.2
    /// "Date - Last-Modified >= 1s" rule. Stored as the wire form.
    LastModified(String),
}

impl StrongValidator {
    /// Render as a complete `If-Range` field value.
    fn as_if_range(&self) -> &str {
        match self {
            StrongValidator::Etag(s) => s,
            StrongValidator::LastModified(s) => s,
        }
    }
}

/// `ReadSeek` over an HTTP/HTTPS resource, using `Range` requests.
pub struct HttpSource {
    uri: String,
    total_len: u64,
    pos: u64,
    /// Per-source agent. When `None` we use the shared default agent.
    agent: Option<Agent>,
    /// Strong validator captured at HEAD, replayed as `If-Range` on
    /// every subsequent range GET so the server replaces a stale
    /// 206 with a 200 — which we surface as a fatal mid-stream
    /// mutation rather than silently re-anchor.
    validator: Option<StrongValidator>,
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
        // Capture a STRONG validator per RFC 9110 §13.1.5 so subsequent
        // range GETs can carry `If-Range: <validator>` and surface a
        // mid-stream mutation cleanly. ETag takes precedence (§8.8.3
        // is "more reliable for validation than a modification date"
        // and the strong/weak distinction is grammatical); fall back to
        // Last-Modified only when §8.8.2.2's "Date - Last-Modified >= 1s"
        // rule promotes it from implicitly-weak to strong.
        let etag_raw = headers
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::trim);
        let last_modified = headers
            .get("last-modified")
            .and_then(|v| v.to_str().ok())
            .map(str::trim);
        let date_hdr = headers
            .get("date")
            .and_then(|v| v.to_str().ok())
            .map(str::trim);
        let validator = derive_strong_validator(etag_raw, last_modified, date_hdr);
        Ok(Self {
            uri: uri.to_owned(),
            total_len,
            pos: 0,
            agent: scoped,
            validator,
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
        // RFC 9110 §13.1.5: when we have a strong validator from HEAD,
        // attach `If-Range: <validator>` so a mid-stream mutation flips
        // the response from 206 to 200 (the §13.1.5 short-circuit) and
        // we can surface it as a hard error below rather than silently
        // re-anchor the byte offset against a different representation.
        let if_range = self.validator.as_ref().map(|v| v.as_if_range().to_owned());
        let sent_if_range = if_range.is_some();
        let mut req = self.agent_ref().get(&self.uri).header("Range", &range);
        if let Some(ref v) = if_range {
            req = req.header("If-Range", v.as_str());
        }
        let resp = req
            .call()
            .map_err(|e| io::Error::other(format!("HTTP GET {} {}: {e}", self.uri, range)))?;
        let status = resp.status();
        // RFC 9110 §15.5.17: a 416 (Range Not Satisfiable) means the
        // server has rejected our requested range. §14.4 SHOULDs a
        // `Content-Range: bytes */<complete-length>` header in this
        // case, naming the server's current authoritative resource
        // length. We surface that length so the caller can distinguish
        // "past EOF" from "resource shrank mid-stream" (the HEAD said N
        // and a later GET reports M < self.pos).
        if status == 416 {
            let cr_raw = resp
                .headers()
                .get("content-range")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            if let Some(cr) = cr_raw.as_deref() {
                match parse_byte_unsatisfied_range(cr) {
                    Ok(complete) => {
                        return Err(io::Error::other(format!(
                            "HTTP 416 {} {}: server reports complete-length {complete} (HEAD observed {}, requested pos {})",
                            self.uri, range, self.total_len, self.pos
                        )));
                    }
                    Err(e) => {
                        return Err(io::Error::other(format!(
                            "HTTP 416 {} {}: invalid Content-Range '{cr}': {e}",
                            self.uri, range
                        )));
                    }
                }
            }
            // §14.4 SHOULD, not MUST — a 416 with no Content-Range is
            // unusual but legal. Still treat it as a hard error since
            // the read can't proceed; just say so plainly.
            return Err(io::Error::other(format!(
                "HTTP 416 {} {}: server rejected range (no Content-Range body)",
                self.uri, range
            )));
        }
        if !(status == 206 || status == 200) {
            return Err(io::Error::other(format!(
                "HTTP GET {} {}: status {status}",
                self.uri, range
            )));
        }
        // RFC 9110 §13.1.5: when we sent `If-Range`, a 200 means the
        // server's current validator did NOT match ours — i.e. the
        // representation has been replaced since HEAD. Silently
        // resuming on the new bytes would re-anchor every later
        // file-offset view against a different resource; that's a
        // misalignment bug, not a soft fallback. Surface as fatal.
        if status == 200 && sent_if_range {
            return Err(io::Error::other(format!(
                "HTTP 200 {} {}: If-Range validator did not match — \
                 representation changed since HEAD (origin/cache mutation)",
                self.uri, range
            )));
        }
        let pos = self.pos;
        let total_len = self.total_len;
        // RFC 9110 §8.6: "a server MUST NOT send Content-Length in [a
        // HEAD] response unless its field value equals the decimal
        // number of octets that would have been sent in the content of
        // a response if the same request had used the GET method."
        // So a 200-fallback (full-body GET, §3.1) whose Content-Length
        // contradicts the HEAD-observed total is a resource resize we
        // cannot recover from in-band — surface as a hard error rather
        // than drain a now-wrong-sized prefix and read short.
        let get_content_length = resp
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());
        // Per RFC 7233 §3.1, a server that does not support (or chooses
        // to ignore) Range MAY answer a range request with a full 200
        // response. In that case we must drop the prefix [0, self.pos)
        // before exposing bytes to the reader so the demuxer keeps a
        // consistent file-offset view. We only walk this branch when
        // we did NOT send If-Range; a 200 with If-Range is the
        // mid-stream-mutation case handled above.
        let skip_prefix = if status == 200 { pos } else { 0 };
        if status == 200 {
            if let Some(cl) = get_content_length {
                if cl != total_len {
                    return Err(io::Error::other(format!(
                        "HTTP 200 {} {}: Content-Length {cl} != HEAD-observed total {total_len} \
                         (RFC 9110 §8.6 — resource resized between HEAD and GET)",
                        self.uri, range
                    )));
                }
            }
        }
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
            // RFC 9110 §8.6: when a 206 carries Content-Length, it MUST
            // be the byte count of the body actually being sent — i.e.
            // for a single-range 206 (the only form we ask for), it
            // equals `last - first + 1`. A mismatch is either a
            // multipart/byteranges body (we never request multi-range,
            // and Content-Type would be `multipart/byteranges` not the
            // raw representation type) or an outright framing bug;
            // either way the demuxer's byte-offset view will drift if
            // we proceed.
            if let Some(cl) = get_content_length {
                let expected = parsed.last - parsed.first + 1;
                if cl != expected {
                    return Err(io::Error::other(format!(
                        "HTTP 206 {} {}: Content-Length {cl} != Content-Range span {expected} \
                         (RFC 9110 §8.6)",
                        self.uri, range
                    )));
                }
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

/// Parse a `Content-Range: bytes */<complete-length>` field value per
/// RFC 9110 §14.4 — the *unsatisfied-range* form a server SHOULD return
/// alongside a 416 (Range Not Satisfiable) response (§15.5.17).
///
/// Returns the server's authoritative complete-length on success. The
/// 416 status itself tells the caller the range was rejected; this
/// parser only extracts the length value so the caller can compare it
/// against what was observed at HEAD construction and tell whether the
/// rejection is "past EOF" or "resource shrank mid-stream."
///
/// Rejects the canonical `range-resp` form (`bytes first-last/complete`)
/// — a 416 body is the unsatisfied-range form per §14.4, never a
/// range-resp.
fn parse_byte_unsatisfied_range(s: &str) -> std::result::Result<u64, &'static str> {
    let s = s.trim();
    let (unit, rest) = s.split_once(' ').ok_or("missing SP after range unit")?;
    if !unit.eq_ignore_ascii_case("bytes") {
        return Err("range unit is not 'bytes'");
    }
    let rest = rest.trim_start();
    let complete_part = rest
        .strip_prefix("*/")
        .ok_or("not an unsatisfied-range ('*/N' expected)")?;
    let complete: u64 = complete_part
        .parse()
        .map_err(|_| "complete-length is not a u64")?;
    Ok(complete)
}

/// Parse an `ETag` field value per RFC 9110 §8.8.3 grammar:
///
/// ```text
/// entity-tag = [ weak ] opaque-tag
/// weak       = %s"W/"
/// opaque-tag = DQUOTE *etagc DQUOTE
/// etagc      = %x21 / %x23-7E / obs-text
/// ```
///
/// Returns `Some((is_weak, full_wire_form))` on a syntactically valid
/// entity-tag, `None` on anything else (an unset or malformed value
/// must not surface as a usable validator).
///
/// `full_wire_form` is the input including the surrounding DQUOTEs and
/// the `W/` prefix if any — what we'd echo back in `If-Range`.
fn parse_entity_tag(s: &str) -> Option<(bool, String)> {
    let s = s.trim();
    // `weak` is case-sensitive `W/` per §8.8.3 (`%s"W/"`).
    let (is_weak, body) = if let Some(rest) = s.strip_prefix("W/") {
        (true, rest)
    } else {
        (false, s)
    };
    let body = body.strip_prefix('"')?;
    let body = body.strip_suffix('"')?;
    // §8.8.3 etagc = %x21 / %x23-7E / obs-text. We accept obs-text
    // (%x80-FF) too, since RFC 9110 §5.5 permits it as a deprecated
    // historical byte class.
    for b in body.bytes() {
        let ok = b == 0x21 || (0x23..=0x7E).contains(&b) || b >= 0x80;
        if !ok {
            return None;
        }
    }
    Some((is_weak, s.to_owned()))
}

/// Parse the canonical IMF-fixdate form per RFC 9110 §5.6.7 into a
/// (year, month, day, hour, minute, second) tuple. Only IMF-fixdate
/// (`Sun, 06 Nov 1994 08:49:37 GMT`) is parsed here; the obsolete
/// `rfc850-date` and `asctime-date` forms have their own parsers and
/// the unified [`parse_http_date`] entry point dispatches between them.
fn parse_imf_fixdate(s: &str) -> Option<(i32, u8, u8, u8, u8, u8)> {
    // Expect: "Wkd, DD Mon YYYY HH:MM:SS GMT"
    let s = s.trim();
    let bytes = s.as_bytes();
    if bytes.len() < 29 {
        return None;
    }
    // bytes[3] = ',', bytes[4] = ' '
    if bytes[3] != b',' || bytes[4] != b' ' {
        return None;
    }
    let day: u8 = s.get(5..7)?.parse().ok()?;
    if bytes[7] != b' ' {
        return None;
    }
    let mon = parse_month_abbr(s.get(8..11)?)?;
    if bytes[11] != b' ' {
        return None;
    }
    let year: i32 = s.get(12..16)?.parse().ok()?;
    if bytes[16] != b' ' {
        return None;
    }
    let hour: u8 = s.get(17..19)?.parse().ok()?;
    if bytes[19] != b':' {
        return None;
    }
    let minute: u8 = s.get(20..22)?.parse().ok()?;
    if bytes[22] != b':' {
        return None;
    }
    let second: u8 = s.get(23..25)?.parse().ok()?;
    if &s[25..] != " GMT" {
        return None;
    }
    Some((year, mon, day, hour, minute, second))
}

/// Three-letter month abbreviation → 1..=12, per RFC 9110 §5.6.7
/// `month` ABNF (case-sensitive). Shared between every HTTP-date form.
fn parse_month_abbr(s: &str) -> Option<u8> {
    match s {
        "Jan" => Some(1),
        "Feb" => Some(2),
        "Mar" => Some(3),
        "Apr" => Some(4),
        "May" => Some(5),
        "Jun" => Some(6),
        "Jul" => Some(7),
        "Aug" => Some(8),
        "Sep" => Some(9),
        "Oct" => Some(10),
        "Nov" => Some(11),
        "Dec" => Some(12),
        _ => None,
    }
}

/// Parse the obsolete `rfc850-date` form per RFC 9110 §5.6.7 ABNF:
///
/// ```text
/// rfc850-date  = day-name-l "," SP date2 SP time-of-day SP GMT
/// date2        = day "-" month "-" 2DIGIT          ; e.g. 02-Jun-82
/// day-name-l   = "Monday" / "Tuesday" / "Wednesday"
///              / "Thursday" / "Friday" / "Saturday" / "Sunday"
/// ```
///
/// A typical example: `Sunday, 06-Nov-94 08:49:37 GMT`.
///
/// The 2-digit year is interpreted per §5.6.7's MUST: a value that would
/// otherwise be more than 50 years in the future is wrapped to the most
/// recent year in the past with the same last two digits. The reference
/// year for the 50-year window is fixed at 2026 here — the rolling-clock
/// approximation. Any non-zero margin is fine for the §8.8.2.2 "Date >=
/// Last-Modified + 1 s" comparison, which is the only consumer.
fn parse_rfc850_date(s: &str) -> Option<(i32, u8, u8, u8, u8, u8)> {
    let s = s.trim();
    // Split on ", " to separate the (variable-length) day-name-l from
    // the fixed-width "DD-Mon-YY HH:MM:SS GMT" tail.
    let (wkd, rest) = s.split_once(", ")?;
    // Validate day-name-l literally — keeps us from accepting
    // IMF-fixdate's three-letter "Sun, " accidentally (the comma+SP
    // split would otherwise allow it; rejecting non-l names here makes
    // each parser own its own grammar).
    match wkd {
        "Monday" | "Tuesday" | "Wednesday" | "Thursday" | "Friday" | "Saturday" | "Sunday" => {}
        _ => return None,
    }
    let bytes = rest.as_bytes();
    // "DD-Mon-YY HH:MM:SS GMT" = 22 bytes
    if bytes.len() != 22 {
        return None;
    }
    let day: u8 = rest.get(0..2)?.parse().ok()?;
    if bytes[2] != b'-' {
        return None;
    }
    let mon = parse_month_abbr(rest.get(3..6)?)?;
    if bytes[6] != b'-' {
        return None;
    }
    let yy: u32 = rest.get(7..9)?.parse().ok()?;
    if bytes[9] != b' ' {
        return None;
    }
    let hour: u8 = rest.get(10..12)?.parse().ok()?;
    if bytes[12] != b':' {
        return None;
    }
    let minute: u8 = rest.get(13..15)?.parse().ok()?;
    if bytes[15] != b':' {
        return None;
    }
    let second: u8 = rest.get(16..18)?.parse().ok()?;
    if &rest[18..] != " GMT" {
        return None;
    }
    Some((rfc850_expand_year(yy), mon, day, hour, minute, second))
}

/// Expand a 2-digit year per RFC 9110 §5.6.7's sliding-window rule:
/// "Recipients of a timestamp value in rfc850-date format ... MUST
/// interpret a timestamp that appears to be more than 50 years in the
/// future as representing the most recent year in the past that had the
/// same last two digits."
///
/// Reference year is a compile-time constant (`REF_YEAR_2DIGIT_BASE`)
/// chosen to keep us inside the 50-year window for current traffic.
/// A 2-digit year `yy` first maps to `cc*100 + yy` for the current
/// century; if that lands more than 50 years past `REF_YEAR`, the
/// previous century is used.
fn rfc850_expand_year(yy: u32) -> i32 {
    // The §5.6.7 rule is "more than 50 years in the future"; we anchor
    // the window at a fixed reference rather than the system clock so
    // the parser is deterministic across machines / time.
    const REF_YEAR: i32 = 2026;
    let century = (REF_YEAR / 100) * 100;
    let candidate = century + yy as i32;
    if candidate - REF_YEAR > 50 {
        candidate - 100
    } else {
        candidate
    }
}

/// Parse the obsolete `asctime-date` form per RFC 9110 §5.6.7 ABNF:
///
/// ```text
/// asctime-date = day-name SP date3 SP time-of-day SP year
/// date3        = month SP ( 2DIGIT / ( SP 1DIGIT ))  ; e.g. Jun  2
/// day-name     = "Mon" / "Tue" / "Wed" / "Thu" / "Fri" / "Sat" / "Sun"
/// ```
///
/// Typical example: `Sun Nov  6 08:49:37 1994`. Note the day field is
/// either two digits or `SP + 1 digit` — the single-space-padded form
/// is what ANSI C `asctime()` emits for days 1..9.
///
/// §5.6.7: "values in the asctime format are assumed to be in UTC".
fn parse_asctime_date(s: &str) -> Option<(i32, u8, u8, u8, u8, u8)> {
    // Format is exactly: "Www Mmm DD HH:MM:SS YYYY" (24 chars) when day
    // has 2 digits, and "Www Mmm  D HH:MM:SS YYYY" (24 chars) when day
    // has 1 digit (SP-padded). Both are 24 bytes total.
    let s = s.trim();
    let bytes = s.as_bytes();
    if bytes.len() != 24 {
        return None;
    }
    let wkd = s.get(0..3)?;
    match wkd {
        "Mon" | "Tue" | "Wed" | "Thu" | "Fri" | "Sat" | "Sun" => {}
        _ => return None,
    }
    if bytes[3] != b' ' {
        return None;
    }
    let mon = parse_month_abbr(s.get(4..7)?)?;
    if bytes[7] != b' ' {
        return None;
    }
    // date3: either "DD" or " D"
    let day_field = s.get(8..10)?;
    let day: u8 = if let Some(b) = day_field.strip_prefix(' ') {
        // SP + 1 digit form — accept only one digit.
        if b.len() != 1 || !b.as_bytes()[0].is_ascii_digit() {
            return None;
        }
        b.parse().ok()?
    } else {
        day_field.parse().ok()?
    };
    if bytes[10] != b' ' {
        return None;
    }
    let hour: u8 = s.get(11..13)?.parse().ok()?;
    if bytes[13] != b':' {
        return None;
    }
    let minute: u8 = s.get(14..16)?.parse().ok()?;
    if bytes[16] != b':' {
        return None;
    }
    let second: u8 = s.get(17..19)?.parse().ok()?;
    if bytes[19] != b' ' {
        return None;
    }
    let year: i32 = s.get(20..24)?.parse().ok()?;
    Some((year, mon, day, hour, minute, second))
}

/// Unified HTTP-date parser per RFC 9110 §5.6.7. Tries IMF-fixdate
/// first (the form every modern origin emits — §5.6.7 senders MUST
/// emit this), then falls back to `rfc850-date`, then `asctime-date`.
///
/// §5.6.7 makes accepting all three forms a MUST on the recipient side;
/// this is the single entry point that satisfies it.
fn parse_http_date(s: &str) -> Option<(i32, u8, u8, u8, u8, u8)> {
    parse_imf_fixdate(s)
        .or_else(|| parse_rfc850_date(s))
        .or_else(|| parse_asctime_date(s))
}

/// Convert an IMF-fixdate (already in UTC per §5.6.7 "GMT") into a
/// strictly-monotonic 64-bit second count from a fixed epoch. Used only
/// for the §8.8.2.2 "Date >= Last-Modified + 1 s" comparison, so any
/// epoch that yields a total ordering on real-world HTTP dates is fine.
/// We pick (year-2000)*31_557_600 + ... — close enough for the
/// strict-greater test; not used as a wall-clock value.
fn imf_seconds(d: (i32, u8, u8, u8, u8, u8)) -> i64 {
    let (y, mo, da, h, mi, s) = d;
    // Cumulative days at start of month, Jan=0..Dec=334 (non-leap),
    // good enough for ordering within the same year — across years
    // the 365-day step dominates.
    const CUM: [u16; 13] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365];
    let day_of_year = CUM[(mo - 1) as usize] as i64 + (da as i64 - 1);
    let day_index = (y as i64 - 2000) * 365 + day_of_year;
    day_index * 86_400 + (h as i64) * 3_600 + (mi as i64) * 60 + s as i64
}

/// Decide which validator (if any) we may use as a strong `If-Range`
/// value per RFC 9110 §13.1.5 + §8.8.2.2 + §8.8.3.
///
/// Returns `Some(StrongValidator::Etag(_))` when the HEAD's `ETag` is a
/// syntactically valid strong entity-tag (no `W/` prefix). Otherwise
/// returns `Some(StrongValidator::LastModified(_))` only when both
/// `Last-Modified` and `Date` parse as one of the §5.6.7 HTTP-date
/// forms (IMF-fixdate / rfc850-date / asctime-date — §5.6.7 makes
/// accepting all three a MUST on recipients) AND the §8.8.2.2
/// promotion rule holds (`Date >= Last-Modified + 1 second`). The two
/// headers do not need to share the same date form. Returns `None`
/// otherwise — the read path then issues plain Range GETs with no
/// `If-Range`.
fn derive_strong_validator(
    etag: Option<&str>,
    last_modified: Option<&str>,
    date: Option<&str>,
) -> Option<StrongValidator> {
    if let Some(raw) = etag {
        if let Some((is_weak, wire)) = parse_entity_tag(raw) {
            if !is_weak {
                return Some(StrongValidator::Etag(wire));
            }
        }
    }
    if let (Some(lm), Some(dt)) = (last_modified, date) {
        // §5.6.7 makes accepting all three HTTP-date forms a MUST on
        // recipients: try IMF-fixdate first, fall back to rfc850-date
        // and asctime-date. Either header may legitimately use any
        // form even though §5.6.7 requires senders to emit IMF-fixdate
        // — older proxies and §5.6.7's own "be robust in parsing"
        // guidance mean we still see the obsolete forms in the wild.
        if let (Some(lm_p), Some(dt_p)) = (parse_http_date(lm), parse_http_date(dt)) {
            // §8.8.2.2: promotion requires Date strictly greater than
            // Last-Modified (at 1-second resolution). `dt > lm` is the
            // clippy-idiomatic spelling of `dt >= lm + 1` on integers.
            if imf_seconds(dt_p) > imf_seconds(lm_p) {
                return Some(StrongValidator::LastModified(lm.to_owned()));
            }
        }
    }
    None
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

/// Header-parser wrappers exposed for the cargo-fuzz harness under
/// `fuzz/`. Not part of the stable public surface; gated behind the
/// `fuzz` cargo feature so the published artefact carries the same
/// crate boundary it always had.
///
/// The wrappers return `bool` (parse succeeded vs not) — the fuzz
/// contract under test is that none of these parsers panic on any
/// byte string, not that any particular byte string parses.
#[cfg(feature = "fuzz")]
#[doc(hidden)]
pub mod __fuzz {
    /// Fuzz-only wrapper for [`super::parse_byte_content_range`].
    pub fn parse_byte_content_range(s: &str) -> bool {
        super::parse_byte_content_range(s).is_ok()
    }
    /// Fuzz-only wrapper for [`super::parse_byte_unsatisfied_range`].
    pub fn parse_byte_unsatisfied_range(s: &str) -> bool {
        super::parse_byte_unsatisfied_range(s).is_ok()
    }
    /// Fuzz-only wrapper for [`super::parse_entity_tag`].
    pub fn parse_entity_tag(s: &str) -> bool {
        super::parse_entity_tag(s).is_some()
    }
    /// Fuzz-only wrapper for [`super::parse_imf_fixdate`].
    pub fn parse_imf_fixdate(s: &str) -> bool {
        super::parse_imf_fixdate(s).is_some()
    }
    /// Fuzz-only wrapper for [`super::parse_rfc850_date`].
    pub fn parse_rfc850_date(s: &str) -> bool {
        super::parse_rfc850_date(s).is_some()
    }
    /// Fuzz-only wrapper for [`super::parse_asctime_date`].
    pub fn parse_asctime_date(s: &str) -> bool {
        super::parse_asctime_date(s).is_some()
    }
    /// Fuzz-only wrapper for [`super::parse_http_date`] (the unified
    /// §5.6.7 entry point covering IMF-fixdate / rfc850-date /
    /// asctime-date).
    pub fn parse_http_date(s: &str) -> bool {
        super::parse_http_date(s).is_some()
    }
    /// Fuzz-only wrapper for [`super::derive_strong_validator`]. The
    /// caller splits the input on NUL bytes into up to three optional
    /// header values (etag, last-modified, date) so the fuzzer can
    /// drive all 8 input-presence combinations.
    pub fn derive_strong_validator(etag: Option<&str>, lm: Option<&str>, date: Option<&str>) {
        let _ = super::derive_strong_validator(etag, lm, date);
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
    fn unsatisfied_range_parses_canonical_form() {
        // RFC 9110 §14.4 example: `bytes */1234`.
        let n = parse_byte_unsatisfied_range("bytes */1234").unwrap();
        assert_eq!(n, 1234);
    }

    #[test]
    fn unsatisfied_range_unit_is_case_insensitive() {
        assert_eq!(
            parse_byte_unsatisfied_range("BYTES */47022").unwrap(),
            47022
        );
        assert_eq!(
            parse_byte_unsatisfied_range("Bytes */47022").unwrap(),
            47022
        );
    }

    #[test]
    fn unsatisfied_range_rejects_unknown_unit() {
        assert!(parse_byte_unsatisfied_range("frames */1234").is_err());
    }

    #[test]
    fn unsatisfied_range_rejects_range_resp_form() {
        // §14.4: a 416 body is unsatisfied-range, never the canonical
        // range-resp form (first-last/complete).
        assert!(parse_byte_unsatisfied_range("bytes 0-9/10").is_err());
        assert!(parse_byte_unsatisfied_range("bytes 42-1233/1234").is_err());
    }

    #[test]
    fn unsatisfied_range_rejects_malformed() {
        for bad in [
            "",
            "bytes",
            "bytes */",  // no digits after '*/'
            "bytes */x", // non-numeric complete
            "bytes /1234",
            "*/1234", // missing unit + SP
        ] {
            assert!(
                parse_byte_unsatisfied_range(bad).is_err(),
                "expected reject for {bad:?}"
            );
        }
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

    #[test]
    fn local_server_416_with_unsatisfied_range_surfaces_complete_length() {
        // RFC 9110 §15.5.17 + §14.4: a 416 carries `bytes */<complete>`
        // naming the server's authoritative current length. We seek
        // past EOF (HEAD said 10, seek to 8, server reports current
        // length 5 — i.e. resource shrank) and expect the error message
        // to surface BOTH the server's reported length and the
        // HEAD-observed length so the caller can distinguish the case.
        static GET: &[u8] = b"HTTP/1.1 416 Range Not Satisfiable\r\n\
            Content-Length: 0\r\n\
            Content-Range: bytes */5\r\n\
            Connection: close\r\n\
            \r\n";
        let (uri, _done) = spawn_server(HEAD_10B_BYTES, GET);
        let mut src = HttpSource::open(&uri).expect("open");
        // Seek to byte 8 — HEAD said 10 so this is in-bounds from our
        // pov; the server's 416 then tells us the resource is now 5.
        std::io::Seek::seek(&mut src, SeekFrom::Start(8)).unwrap();
        let mut buf = [0u8; 1];
        let err = std::io::Read::read_exact(&mut src, &mut buf).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("416"), "wrong error (no 416): {msg}");
        assert!(
            msg.contains("complete-length 5"),
            "wrong error (no 'complete-length 5'): {msg}"
        );
        assert!(
            msg.contains("HEAD observed 10"),
            "wrong error (no 'HEAD observed 10'): {msg}"
        );
    }

    #[test]
    fn local_server_416_without_content_range_still_errors_cleanly() {
        // §14.4 makes the Content-Range a SHOULD on 416, not a MUST. A
        // 416 without the body still needs a clean error path that
        // names the status.
        static GET: &[u8] = b"HTTP/1.1 416 Range Not Satisfiable\r\n\
            Content-Length: 0\r\n\
            Connection: close\r\n\
            \r\n";
        let (uri, _done) = spawn_server(HEAD_10B_BYTES, GET);
        let mut src = HttpSource::open(&uri).expect("open");
        std::io::Seek::seek(&mut src, SeekFrom::Start(8)).unwrap();
        let mut buf = [0u8; 1];
        let err = std::io::Read::read_exact(&mut src, &mut buf).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("416"), "wrong error (no 416): {msg}");
        assert!(
            msg.contains("no Content-Range"),
            "wrong error (no 'no Content-Range'): {msg}"
        );
    }

    #[test]
    fn local_server_416_with_invalid_content_range_reports_parse_error() {
        // A 416 whose Content-Range is malformed — the read still
        // fails, but the error names the parse failure rather than
        // surfacing nonsense as a length.
        static GET: &[u8] = b"HTTP/1.1 416 Range Not Satisfiable\r\n\
            Content-Length: 0\r\n\
            Content-Range: bytes 0-9/10\r\n\
            Connection: close\r\n\
            \r\n";
        // 'bytes 0-9/10' is a range-resp form, not unsatisfied-range —
        // §14.4 says the 416 body should be `*/N`. Anything else is a
        // server bug; we surface the parse error.
        let (uri, _done) = spawn_server(HEAD_10B_BYTES, GET);
        let mut src = HttpSource::open(&uri).expect("open");
        std::io::Seek::seek(&mut src, SeekFrom::Start(8)).unwrap();
        let mut buf = [0u8; 1];
        let err = std::io::Read::read_exact(&mut src, &mut buf).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("416"), "wrong error (no 416): {msg}");
        assert!(
            msg.contains("invalid Content-Range"),
            "wrong error (no 'invalid Content-Range'): {msg}"
        );
    }

    // Silence "unused" warning when these helpers aren't all picked up
    // — make_get_206 is a convenience the next test round may use.
    #[allow(dead_code)]
    fn _keep_helper() {
        let _ = make_get_206("bytes 0-9/10", b"0123456789");
    }

    // -- RFC 9110 §13.1.5 If-Range strong-validator path ---------------------

    #[test]
    fn entity_tag_parses_strong_tag() {
        let (weak, wire) = parse_entity_tag("\"xyzzy\"").unwrap();
        assert!(!weak);
        assert_eq!(wire, "\"xyzzy\"");
    }

    #[test]
    fn entity_tag_parses_weak_tag() {
        let (weak, wire) = parse_entity_tag("W/\"xyzzy\"").unwrap();
        assert!(weak);
        assert_eq!(wire, "W/\"xyzzy\"");
    }

    #[test]
    fn entity_tag_parses_empty_opaque() {
        // §8.8.3 example: ETag: ""
        let (weak, wire) = parse_entity_tag("\"\"").unwrap();
        assert!(!weak);
        assert_eq!(wire, "\"\"");
    }

    #[test]
    fn entity_tag_rejects_unquoted_value() {
        // The grammar requires DQUOTE-wrapped opaque-tag.
        assert!(parse_entity_tag("xyzzy").is_none());
        assert!(parse_entity_tag("W/xyzzy").is_none());
    }

    #[test]
    fn entity_tag_weak_marker_is_case_sensitive() {
        // §8.8.3: weak = %s"W/" — case-sensitive. A lowercase w/ is
        // not a weakness indicator; it becomes part of the opaque-tag
        // which then fails the DQUOTE-wrap test.
        assert!(parse_entity_tag("w/\"xyzzy\"").is_none());
    }

    #[test]
    fn entity_tag_rejects_disallowed_inner_bytes() {
        // etagc forbids DQUOTE (0x22) and most controls.
        assert!(parse_entity_tag("\"hello\"world\"").is_none());
        assert!(parse_entity_tag("\"tab\there\"").is_none()); // 0x09
    }

    #[test]
    fn imf_fixdate_parses_canonical_example() {
        // RFC 9110 §5.6.7 canonical form.
        let d = parse_imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        assert_eq!(d, (1994, 11, 6, 8, 49, 37));
    }

    #[test]
    fn imf_fixdate_rejects_non_imf_forms() {
        // The IMF-fixdate parser itself is strict — the §5.6.7 MUST-
        // accept on the other two forms is handled by `parse_http_date`
        // dispatching to the dedicated rfc850 / asctime parsers.
        assert!(parse_imf_fixdate("Sunday, 06-Nov-94 08:49:37 GMT").is_none());
        assert!(parse_imf_fixdate("Sun Nov  6 08:49:37 1994").is_none());
        // Missing GMT suffix.
        assert!(parse_imf_fixdate("Sun, 06 Nov 1994 08:49:37").is_none());
        // Bogus month name.
        assert!(parse_imf_fixdate("Sun, 06 Foo 1994 08:49:37 GMT").is_none());
    }

    // -- RFC 9110 §5.6.7 obsolete rfc850-date form ---------------------------

    #[test]
    fn rfc850_date_parses_canonical_example() {
        // §5.6.7 example. 2-digit year 94 expands to 1994 under the
        // sliding-window rule (REF_YEAR=2026; 94→2094 is >50 years
        // future → roll back a century).
        let d = parse_rfc850_date("Sunday, 06-Nov-94 08:49:37 GMT").unwrap();
        assert_eq!(d, (1994, 11, 6, 8, 49, 37));
    }

    #[test]
    fn rfc850_date_parses_every_long_weekday_name() {
        for wkd in [
            "Monday",
            "Tuesday",
            "Wednesday",
            "Thursday",
            "Friday",
            "Saturday",
            "Sunday",
        ] {
            let s = format!("{wkd}, 01-Jan-00 00:00:00 GMT");
            assert!(parse_rfc850_date(&s).is_some(), "rejected {s:?}");
        }
    }

    #[test]
    fn rfc850_date_window_expands_year_per_section_5_6_7() {
        // §5.6.7 MUST: a 2-digit year > 50 years in the future maps to
        // the most recent past year with the same last two digits.
        // REF_YEAR = 2026.
        //
        // 26 → 2026 (current ref year).
        // 76 → 2076 (50 years out — still within the window, "more than
        //   50 years in the future" is the trigger so 50 itself stays).
        // 77 → 1977 (51 years out → wrap).
        // 00 → 2000 (24 years past → unchanged).
        // 99 → 1999 (-27 years → unchanged because not in the future).
        let yr = |s: &str| parse_rfc850_date(s).unwrap().0;
        assert_eq!(yr("Monday, 01-Jan-26 00:00:00 GMT"), 2026);
        assert_eq!(yr("Monday, 01-Jan-76 00:00:00 GMT"), 2076);
        assert_eq!(yr("Monday, 01-Jan-77 00:00:00 GMT"), 1977);
        assert_eq!(yr("Monday, 01-Jan-00 00:00:00 GMT"), 2000);
        assert_eq!(yr("Monday, 01-Jan-99 00:00:00 GMT"), 1999);
    }

    #[test]
    fn rfc850_date_rejects_short_weekday_names() {
        // The short three-letter "Sun" form is IMF-fixdate, not
        // rfc850-date. The rfc850 parser must reject it (parse_http_date
        // dispatches the right form).
        assert!(parse_rfc850_date("Sun, 06-Nov-94 08:49:37 GMT").is_none());
    }

    #[test]
    fn rfc850_date_rejects_malformed_strings() {
        for bad in [
            "",
            "Sunday 06-Nov-94 08:49:37 GMT",   // missing comma
            "Sunday, 06-Nov-94 08:49:37",      // missing GMT
            "Sunday, 06/Nov/94 08:49:37 GMT",  // wrong separator
            "Sunday, 06-Foo-94 08:49:37 GMT",  // bad month
            "Sunday, AB-Nov-94 08:49:37 GMT",  // non-digit day
            "Sunday, 06-Nov-9X 08:49:37 GMT",  // non-digit year
            "Sunday, 06-Nov-94 08:49:37  GMT", // extra space (§5.6.7 forbids)
        ] {
            assert!(
                parse_rfc850_date(bad).is_none(),
                "expected reject for {bad:?}"
            );
        }
    }

    // -- RFC 9110 §5.6.7 obsolete asctime-date form ---------------------------

    #[test]
    fn asctime_date_parses_canonical_example() {
        // §5.6.7 example. Double space after month means day is the
        // SP-padded single-digit form.
        let d = parse_asctime_date("Sun Nov  6 08:49:37 1994").unwrap();
        assert_eq!(d, (1994, 11, 6, 8, 49, 37));
    }

    #[test]
    fn asctime_date_parses_two_digit_day() {
        // Day 06 written with leading zero is NOT what asctime emits,
        // but §5.6.7 date3 = month SP ( 2DIGIT / ( SP 1DIGIT )) so
        // "Nov 06" is a valid 2DIGIT alternative. Be lenient per
        // §5.6.7's "be robust in parsing" note.
        let d = parse_asctime_date("Mon Nov 30 23:59:59 1994").unwrap();
        assert_eq!(d, (1994, 11, 30, 23, 59, 59));
    }

    #[test]
    fn asctime_date_rejects_malformed_strings() {
        for bad in [
            "",
            "Sun Nov  6 08:49:37 199",  // short year (23 bytes total)
            "Sun XYZ  6 08:49:37 1994", // bad month
            "Foo Nov  6 08:49:37 1994", // bad day-name
            "Sun Nov  6 08-49-37 1994", // wrong time separator
            "Sun, Nov 6 08:49:37 1994", // stray comma (changes layout)
            "Sun Nov   6 08:49:37 199", // 23 bytes — short
        ] {
            assert!(
                parse_asctime_date(bad).is_none(),
                "expected reject for {bad:?}"
            );
        }
    }

    // -- §5.6.7 unified HTTP-date parser dispatches all three forms ----------

    #[test]
    fn http_date_accepts_all_three_5_6_7_forms() {
        // §5.6.7 MUST: a recipient MUST accept all three HTTP-date
        // formats. The unified entry point covers that.
        assert!(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT").is_some()); // IMF-fixdate
        assert!(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT").is_some()); // rfc850
        assert!(parse_http_date("Sun Nov  6 08:49:37 1994").is_some()); // asctime
    }

    #[test]
    fn http_date_returns_same_components_across_forms() {
        // The three §5.6.7 examples all denote the same UTC instant.
        // The parser must produce identical (y, mo, d, h, mi, s) tuples
        // for each so downstream §8.8.2.2 second-comparison works
        // regardless of which form an origin emits.
        let imf = parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        let rfc850 = parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT").unwrap();
        let asctime = parse_http_date("Sun Nov  6 08:49:37 1994").unwrap();
        assert_eq!(imf, rfc850);
        assert_eq!(imf, asctime);
    }

    #[test]
    fn http_date_rejects_garbage() {
        for bad in ["", "not a date", "1994-11-06T08:49:37Z", "Sun, BAD"] {
            assert!(
                parse_http_date(bad).is_none(),
                "expected reject for {bad:?}"
            );
        }
    }

    #[test]
    fn derive_strong_validator_accepts_rfc850_dates() {
        // Strong-validator promotion path (§13.1.5 + §8.8.2.2) now
        // works for rfc850-date headers, not just IMF-fixdate.
        let v = derive_strong_validator(
            None,
            Some("Sunday, 06-Nov-94 08:49:37 GMT"),
            Some("Sunday, 06-Nov-94 08:49:42 GMT"),
        );
        assert_eq!(
            v,
            Some(StrongValidator::LastModified(
                "Sunday, 06-Nov-94 08:49:37 GMT".into()
            ))
        );
    }

    #[test]
    fn derive_strong_validator_accepts_asctime_dates() {
        // Same path, asctime-date forms. The Last-Modified value is
        // echoed back verbatim as the If-Range field, which is what
        // §13.1.5 requires (we don't normalise the wire form).
        let v = derive_strong_validator(
            None,
            Some("Sun Nov  6 08:49:37 1994"),
            Some("Sun Nov  6 08:49:42 1994"),
        );
        assert_eq!(
            v,
            Some(StrongValidator::LastModified(
                "Sun Nov  6 08:49:37 1994".into()
            ))
        );
    }

    #[test]
    fn derive_strong_validator_accepts_mixed_forms_across_headers() {
        // §5.6.7 doesn't constrain different fields in a single message
        // to use the same form. Last-Modified in IMF-fixdate + Date in
        // rfc850-date must still promote when the 1-second rule holds.
        let v = derive_strong_validator(
            None,
            Some("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some("Sunday, 06-Nov-94 08:49:42 GMT"),
        );
        assert!(matches!(v, Some(StrongValidator::LastModified(_))));
    }

    #[test]
    fn imf_seconds_orders_within_one_second_correctly() {
        // §8.8.2.2 needs strict-greater-than-or-equal at 1-second
        // resolution. Confirm the ordering primitive supports that.
        let lm = parse_imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        let dt_eq = parse_imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        let dt_p1 = parse_imf_fixdate("Sun, 06 Nov 1994 08:49:38 GMT").unwrap();
        let dt_m1 = parse_imf_fixdate("Sun, 06 Nov 1994 08:49:36 GMT").unwrap();
        assert!(imf_seconds(dt_eq) == imf_seconds(lm));
        assert!(imf_seconds(dt_p1) == imf_seconds(lm) + 1);
        assert!(imf_seconds(dt_m1) == imf_seconds(lm) - 1);
    }

    #[test]
    fn derive_strong_validator_prefers_strong_etag() {
        let v = derive_strong_validator(
            Some("\"xyz\""),
            Some("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some("Sun, 06 Nov 1994 08:49:37 GMT"),
        );
        assert_eq!(v, Some(StrongValidator::Etag("\"xyz\"".into())));
    }

    #[test]
    fn derive_strong_validator_skips_weak_etag_falls_to_strong_last_modified() {
        // Weak ETag → not usable for If-Range. Last-Modified is
        // promotable because Date is 5 s after it.
        let v = derive_strong_validator(
            Some("W/\"xyz\""),
            Some("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some("Sun, 06 Nov 1994 08:49:42 GMT"),
        );
        assert_eq!(
            v,
            Some(StrongValidator::LastModified(
                "Sun, 06 Nov 1994 08:49:37 GMT".into()
            ))
        );
    }

    #[test]
    fn derive_strong_validator_rejects_lm_when_date_within_one_second() {
        // Date == Last-Modified is NOT strong per §8.8.2.2 — needs at
        // least 1 s of separation. The result must be None (we fall
        // back to issuing the GET without If-Range).
        let v = derive_strong_validator(
            None,
            Some("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some("Sun, 06 Nov 1994 08:49:37 GMT"),
        );
        assert_eq!(v, None);
    }

    #[test]
    fn derive_strong_validator_rejects_lm_without_date() {
        // §8.8.2.2 promotion needs both timestamps — without Date we
        // can't reason about clock skew, so stay weak (= None).
        let v = derive_strong_validator(None, Some("Sun, 06 Nov 1994 08:49:37 GMT"), None);
        assert_eq!(v, None);
    }

    #[test]
    fn derive_strong_validator_handles_missing_headers() {
        assert_eq!(derive_strong_validator(None, None, None), None);
    }

    #[test]
    fn derive_strong_validator_skips_malformed_etag_falls_through() {
        // A malformed ETag is treated as absent — try Last-Modified.
        let v = derive_strong_validator(
            Some("not-quoted"),
            Some("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some("Sun, 06 Nov 1994 08:49:42 GMT"),
        );
        assert_eq!(
            v,
            Some(StrongValidator::LastModified(
                "Sun, 06 Nov 1994 08:49:37 GMT".into()
            ))
        );
    }

    /// Variant of `spawn_server` that captures the GET request bytes
    /// in a channel so the test can verify our `If-Range` field made
    /// it onto the wire exactly as expected.
    fn spawn_server_capturing_get(
        head_resp: &'static [u8],
        get_resp: &'static [u8],
    ) -> (String, mpsc::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        thread::spawn(move || {
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
                    // GET — record the full request bytes so the test
                    // can grep for If-Range presence.
                    let _ = tx.send(req.to_vec());
                    get_resp
                };
                let _ = stream.write_all(resp);
                let _ = stream.flush();
            }
        });
        (format!("http://127.0.0.1:{port}/x"), rx)
    }

    /// HEAD response that supplies a strong ETag so the driver will
    /// elect to send `If-Range: "v1"` on the next GET.
    const HEAD_10B_WITH_STRONG_ETAG: &[u8] = b"HTTP/1.1 200 OK\r\n\
        Content-Length: 10\r\n\
        Accept-Ranges: bytes\r\n\
        ETag: \"v1\"\r\n\
        Connection: close\r\n\
        \r\n";

    #[test]
    fn local_server_strong_etag_emits_if_range_header_on_get() {
        // Server replies 206 normally; we just need to confirm the
        // outgoing GET request line carried `If-Range: "v1"`.
        static GET: &[u8] = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Length: 10\r\n\
            Content-Range: bytes 0-9/10\r\n\
            Connection: close\r\n\
            \r\n\
            0123456789";
        let (uri, captured) = spawn_server_capturing_get(HEAD_10B_WITH_STRONG_ETAG, GET);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        let req = captured.recv().expect("captured GET request");
        let s = String::from_utf8_lossy(&req);
        assert!(
            s.to_ascii_lowercase().contains("if-range: \"v1\""),
            "GET did not carry If-Range; got:\n{s}"
        );
    }

    /// HEAD response with a weak ETag and no Last-Modified — driver
    /// must not invent a validator.
    const HEAD_10B_WITH_WEAK_ETAG: &[u8] = b"HTTP/1.1 200 OK\r\n\
        Content-Length: 10\r\n\
        Accept-Ranges: bytes\r\n\
        ETag: W/\"v1\"\r\n\
        Connection: close\r\n\
        \r\n";

    #[test]
    fn local_server_weak_etag_does_not_emit_if_range_header() {
        // §13.1.5: "A client MUST NOT generate an If-Range header
        // field containing an entity tag that is marked as weak."
        static GET: &[u8] = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Length: 10\r\n\
            Content-Range: bytes 0-9/10\r\n\
            Connection: close\r\n\
            \r\n\
            0123456789";
        let (uri, captured) = spawn_server_capturing_get(HEAD_10B_WITH_WEAK_ETAG, GET);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        let req = captured.recv().expect("captured GET request");
        let s = String::from_utf8_lossy(&req);
        assert!(
            !s.to_ascii_lowercase().contains("if-range:"),
            "GET unexpectedly carried If-Range with a weak ETag; got:\n{s}"
        );
    }

    #[test]
    fn local_server_200_with_if_range_set_is_fatal_mutation() {
        // §13.1.5 short-circuit: when the validator we sent does NOT
        // match, the server omits the Range honour and sends 200 with
        // the full new representation. Our driver must surface that
        // as a hard error rather than silently re-anchoring the byte
        // offset against a different resource.
        static GET: &[u8] = b"HTTP/1.1 200 OK\r\n\
            Content-Length: 10\r\n\
            Connection: close\r\n\
            \r\n\
            ABCDEFGHIJ";
        let (uri, _captured) = spawn_server_capturing_get(HEAD_10B_WITH_STRONG_ETAG, GET);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        let err = std::io::Read::read_exact(&mut src, &mut buf).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("If-Range"),
            "wrong error (no If-Range mention): {msg}"
        );
        assert!(
            msg.contains("changed since HEAD"),
            "wrong error (no mutation phrasing): {msg}"
        );
    }

    #[test]
    fn local_server_no_validator_still_drains_prefix_on_200() {
        // Sanity: when HEAD supplies no usable validator, we did NOT
        // send If-Range, so the §3.1 "server ignores Range, sends 200"
        // soft-fallback (drain prefix) still works. This confirms we
        // did not regress the existing path.
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

    // -- RFC 9110 §8.6 Content-Length sanity ---------------------------------

    #[test]
    fn local_server_200_fallback_content_length_mismatch_is_fatal() {
        // §8.6: HEAD's Content-Length MUST equal what a GET would have
        // sent. So a 200-fallback (server ignored Range, served full
        // body) carrying a Content-Length different from the HEAD's is
        // a mid-stream resize disguised as a §3.1 soft-fallback. The
        // demuxer would drain a now-wrong-sized prefix and read short;
        // surface as a hard error instead.
        //
        // HEAD says 10 bytes, GET says 5 — the body actually shipped is
        // 5 bytes so this is also a real wire condition (not just a
        // header lie).
        static GET: &[u8] = b"HTTP/1.1 200 OK\r\n\
            Content-Length: 5\r\n\
            Connection: close\r\n\
            \r\n\
            01234";
        let (uri, _done) = spawn_server(HEAD_10B_BYTES, GET);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        let err = std::io::Read::read_exact(&mut src, &mut buf).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Content-Length 5"),
            "wrong error (no 'Content-Length 5'): {msg}"
        );
        assert!(
            msg.contains("HEAD-observed total 10"),
            "wrong error (no HEAD-observed mention): {msg}"
        );
        assert!(msg.contains("§8.6"), "wrong error (no §8.6 cite): {msg}");
    }

    #[test]
    fn local_server_200_fallback_without_content_length_is_accepted() {
        // §8.6 makes Content-Length a SHOULD on responses (not a MUST
        // outside specific cases). A 200 with no Content-Length cannot
        // be cross-checked against HEAD; we still walk the §3.1
        // drain-prefix path. (HTTP/1.1 framing here uses Connection:
        // close to delimit the body — RFC 9112 §6.3 case 7.)
        static GET: &[u8] = b"HTTP/1.1 200 OK\r\n\
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

    #[test]
    fn local_server_206_content_length_mismatch_is_fatal() {
        // §8.6: a 206's Content-Length is the count of bytes actually
        // being sent. For our open-ended single-range request the
        // implied span is `last - first + 1`. A header value that
        // disagrees would let the downstream reader drift past the
        // end of the satisfied range silently.
        //
        // We ask for bytes=0-; server replies with Content-Range
        // 'bytes 0-9/10' (span 10) but Content-Length 5 (lie). The
        // mismatch is what we surface, not whatever short body would
        // arrive.
        static GET: &[u8] = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Length: 5\r\n\
            Content-Range: bytes 0-9/10\r\n\
            Connection: close\r\n\
            \r\n\
            01234";
        let (uri, _done) = spawn_server(HEAD_10B_BYTES, GET);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        let err = std::io::Read::read_exact(&mut src, &mut buf).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Content-Length 5"),
            "wrong error (no 'Content-Length 5'): {msg}"
        );
        assert!(
            msg.contains("Content-Range span 10"),
            "wrong error (no 'Content-Range span 10'): {msg}"
        );
        assert!(msg.contains("§8.6"), "wrong error (no §8.6 cite): {msg}");
    }

    #[test]
    fn local_server_206_matching_content_length_is_accepted() {
        // Sanity: Content-Length 10 + Content-Range 'bytes 0-9/10'
        // (span 10) is the canonical happy path and must continue to
        // succeed.
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
}
