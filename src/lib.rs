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
            // RFC 9110 §10.2.3: when sent with 503 (Service Unavailable),
            // Retry-After indicates how long the service is expected to
            // be unavailable; with 3xx (Redirection) responses it
            // indicates the minimum time before a follow-up request.
            // §10.2.3 says the field MAY also accompany 429 (RFC 6585).
            // We surface the parsed value in the error message so a
            // caller wiring back-off doesn't have to also fish the
            // header out of a now-consumed response. The driver itself
            // does NOT sleep — interpreting an absolute UTC date
            // requires a clock the source does not own, and back-off
            // strategy belongs in the caller.
            let retry_after = head
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .map(normalize_obs_fold);
            // RFC 7230 §3.2.4: normalise obs-fold "prior to interpreting
            // the field value". `format_retry_after_hint` is the
            // interpretation step here, so the normalisation must
            // happen before it sees the input.
            let retry_msg = retry_after
                .as_deref()
                .map(format_retry_after_hint)
                .unwrap_or_default();
            return Err(Error::other(format!(
                "HTTP HEAD {uri}: status {status}{retry_msg}"
            )));
        }
        let headers = head.headers();
        let total_len = headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| {
                Error::Unsupported(format!("HTTP HEAD {uri}: missing Content-Length"))
            })?;
        // RFC 9110 §14.3: `Accept-Ranges = 1#range-unit`. Use the §5.6.1
        // list parser instead of a bare equality so a server returning
        // `Accept-Ranges: bytes, foo-unit` (legitimate per §14.3) is
        // accepted, and so an explicit `Accept-Ranges: none` (§14.3's
        // reserved-token advice) is reported distinctly from "header
        // absent" — the former is the server saying "do not attempt",
        // the latter is silence (§14.3 makes the header advisory, not
        // mandatory, even for range-capable servers).
        // RFC 7230 §3.2.4: normalise obs-fold "prior to interpreting
        // the field value". `Accept-Ranges` is a §5.6.1 list whose
        // delimiter (`,`) makes it a plausible target for obs-folding
        // by older origins or proxies, so the normalisation is wired
        // here before the §14.3 list parser runs.
        let accept_ranges_owned = headers
            .get("accept-ranges")
            .and_then(|v| v.to_str().ok())
            .map(normalize_obs_fold);
        let accept_ranges_raw = accept_ranges_owned.as_deref().unwrap_or("");
        match parse_accept_ranges(accept_ranges_raw) {
            AcceptRanges::Bytes => {}
            AcceptRanges::None => {
                return Err(Error::Unsupported(format!(
                    "HTTP HEAD {uri}: server explicitly refused range support (Accept-Ranges: none, RFC 9110 §14.3)"
                )));
            }
            AcceptRanges::Other(units) => {
                return Err(Error::Unsupported(format!(
                    "HTTP HEAD {uri}: server advertises range units {units:?} but not 'bytes' (RFC 9110 §14.3)"
                )));
            }
            AcceptRanges::Absent => {
                // §14.3: "A client MAY generate range requests
                // regardless of having received an Accept-Ranges
                // field." But the present driver's correctness model
                // (validate Content-Range echo etc.) needs the server
                // to actually satisfy them, and a HEAD that omits the
                // hint is also far more likely to refuse. Preserve
                // the historical refusal here so we don't quietly
                // start issuing Range GETs against servers we'd have
                // refused before; the message is now distinct.
                return Err(Error::Unsupported(format!(
                    "HTTP HEAD {uri}: server did not advertise Accept-Ranges (RFC 9110 §14.3)"
                )));
            }
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
            // RFC 9110 §15.3.7.2 ("A server MUST NOT generate a multipart
            // response to a request for a single range") + §14.6
            // (multipart/byteranges media type). The driver only ever
            // requests `Range: bytes=N-` (a single range), so a 206
            // whose Content-Type is `multipart/byteranges` is a server
            // bug. Surface a clean cite rather than letting the body
            // surface as the binary representation type and have the
            // §8.6 / Content-Range invariants light up downstream with
            // confusing diagnostics: multipart bodies carry per-part
            // Content-Range headers, the top-level Content-Range is
            // either absent or names the synthetic outer span, and
            // either way the demuxer would parse boundary delimiters
            // as if they were bitstream bytes.
            let ct_raw = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if is_multipart_byteranges_content_type(ct_raw) {
                return Err(io::Error::other(format!(
                    "HTTP 206 {} {}: server returned multipart/byteranges to a single-range \
                     request (RFC 9110 §15.3.7.2 MUST NOT). Content-Type: {ct_raw:?}",
                    self.uri, range
                )));
            }
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

/// What a `Accept-Ranges` response field tells the client about the
/// server's willingness to satisfy a range request, per RFC 9110 §14.3.
///
/// §14.3 ABNF:
///
/// ```text
/// Accept-Ranges     = acceptable-ranges
/// acceptable-ranges = 1#range-unit
/// range-unit        = token            ; §14.1
/// ```
///
/// `1#X` is the list construction from RFC 9110 §5.6.1: a non-empty
/// comma-separated list, OWS-tolerant on both sides of each comma. So
/// `Accept-Ranges: bytes, foo-unit` legitimately advertises both units.
/// The §14.1 range-unit names are case-insensitive (§14.1 cross-refs
/// the §3.2.6 token rule).
///
/// §14.3 reserves the unit name `none` (lowercase by example, but a
/// recipient treats it case-insensitively per §3.2.6 token equality)
/// for the explicit "do not attempt a range request" advice. The list
/// constructor in §5.6.1 explicitly tolerates a sender producing
/// `none` alongside other units — the recipient SHOULD treat that as
/// a contradiction, but §14.3 does not name a hard rule so the
/// helper below reports `Other` rather than rejecting outright when
/// `none` appears next to a real unit.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AcceptRanges {
    /// Server advertised at least one range unit that includes `bytes`
    /// (case-insensitive). Range requests are expected to work.
    Bytes,
    /// Server advertised exactly `none` (case-insensitive, single
    /// element) — explicit advice not to attempt a range request per
    /// §14.3 "The range unit 'none' is reserved for this purpose".
    None,
    /// Server advertised one or more range units but none of them is
    /// `bytes`. Carries the original token list (lowercased, trimmed)
    /// for diagnostic surfacing. Driver treats this like "no range
    /// support" for the current driver (which only knows the `bytes`
    /// unit), but distinguishes the message so a caller can tell
    /// "server speaks ranges, just not in our unit" apart from "server
    /// declined ranges entirely".
    Other(Vec<String>),
    /// The header was absent or contained only empty list elements.
    /// §14.3 doesn't mandate the field's presence even when the server
    /// supports ranges; this is informational, not a refusal.
    Absent,
}

/// Parse a `Accept-Ranges` field value per RFC 9110 §14.3 ABNF.
///
/// Returns the categorised classification described on [`AcceptRanges`].
///
/// Empty list elements (e.g. the trailing element of `"bytes,"`) are
/// silently dropped per §5.6.1 — the list construction expressly
/// permits empty members and the recipient is meant to skip them.
fn parse_accept_ranges(s: &str) -> AcceptRanges {
    // §5.6.1: split on comma, then strip OWS on each element. Empty
    // elements (zero-length after trim) are tolerated and dropped.
    let mut tokens: Vec<String> = Vec::new();
    let mut had_none = false;
    let mut had_bytes = false;
    for part in s.split(',') {
        let tok = part.trim_matches(|c: char| c == ' ' || c == '\t');
        if tok.is_empty() {
            continue;
        }
        // §3.2.6 token validity: every byte in 1*tchar. We do not
        // hard-fail on a non-token element; we just skip it so a
        // misbehaving server that puts garbage in one slot doesn't
        // black-hole the legitimate `bytes` next to it. The validity
        // gate is intentionally permissive — the §14.3 advice value
        // is the token itself, not how it was framed.
        if !is_token(tok) {
            continue;
        }
        let lower = tok.to_ascii_lowercase();
        if lower == "bytes" {
            had_bytes = true;
        }
        if lower == "none" {
            had_none = true;
        }
        tokens.push(lower);
    }
    if tokens.is_empty() {
        return AcceptRanges::Absent;
    }
    if had_bytes {
        // §14.3 implicit rule: a server that advertises `bytes` MAY
        // also advertise other units. The recipient acts on `bytes`.
        return AcceptRanges::Bytes;
    }
    if had_none && tokens.len() == 1 {
        // §14.3 explicit "none" advice — single element, lowercase
        // by example.
        return AcceptRanges::None;
    }
    AcceptRanges::Other(tokens)
}

/// RFC 9110 §5.6.2 token grammar:
///
/// ```text
/// token  = 1*tchar
/// tchar  = "!" / "#" / "$" / "%" / "&" / "'" / "*"
///        / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
///        / DIGIT / ALPHA
/// ```
fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Normalize obsolete line folding (`obs-fold`) in a header field value
/// per RFC 7230 §3.2.4.
///
/// The §3.2 ABNF allows `field-value = *( field-content / obs-fold )`
/// where `obs-fold = CRLF 1*( SP / HTAB )`. §3.2.4 makes the following
/// hard requirement on a user agent that receives an obs-fold in a
/// response (not within a `message/http` container):
///
/// > "A user agent that receives an obs-fold in a response message
/// > that is not within a message/http container MUST replace each
/// > received obs-fold with one or more SP octets prior to
/// > interpreting the field value."
///
/// This helper performs exactly that normalisation. Each maximal run
/// of `CRLF (SP/HTAB)+` inside `s` is collapsed to a single ASCII
/// space (`0x20`). The "one or more SP" wording leaves the count to
/// the recipient; one SP is the smallest stable choice — it preserves
/// the token-boundary signal that the original whitespace carried (so
/// e.g. an obs-folded comma-separated list still tokenises the same
/// way) without padding the value with arbitrary whitespace that
/// downstream parsers would just have to trim again.
///
/// The function is *only* a normaliser — it does not reject the input
/// or report whether folding was found. §3.2.4 also permits a
/// recipient to reject obs-folded requests with 400, but a user agent
/// receiving a response has the MUST-normalise obligation, not a
/// MUST-reject option, so the API surface here only models the
/// normalisation outcome.
///
/// Returns a `Cow::Borrowed(s)` when no obs-fold occurrence is found
/// (the common case) so cold-path callers stay allocation-free. A
/// `Cow::Owned(_)` is returned when at least one fold was collapsed.
///
/// Bare CR or bare LF (not part of a CRLF pair) and CRLF NOT followed
/// by SP/HTAB are left untouched — those are not obs-fold per the
/// §3.2 ABNF; deciding what to do with them is the caller's job (the
/// framing layer typically rejects them as line-terminators, which is
/// out of scope for a field-value normaliser).
///
/// Examples (informal):
///
/// ```text
/// "abc\r\n def"     -> "abc def"
/// "abc\r\n\t def"   -> "abc def"   (multiple SP/HTAB collapsed to 1)
/// "abc\r\n  \tdef"  -> "abc def"
/// "a\r\n b\r\n\tc"  -> "a b c"     (two folds, two collapses)
/// "abc def"         -> "abc def"   (no fold, no allocation)
/// "abc\r\nxyz"      -> "abc\r\nxyz" (CRLF not followed by SP/HTAB:
///                                    not obs-fold; left as-is)
/// "abc\rdef"        -> "abc\rdef"  (bare CR: not obs-fold)
/// ```
fn normalize_obs_fold(s: &str) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;
    // Fast scan on the &[u8] view to locate the first real obs-fold.
    // SP / HTAB / CR / LF are all single-byte ASCII; obs-text (%x80-FF)
    // is multi-byte in UTF-8 but never matches the CRLF + SP/HTAB
    // pattern, so byte-level matching is safe.
    let bytes = s.as_bytes();
    let mut first_fold: Option<usize> = None;
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'\r'
            && bytes[i + 1] == b'\n'
            && (bytes[i + 2] == b' ' || bytes[i + 2] == b'\t')
        {
            first_fold = Some(i);
            break;
        }
        i += 1;
    }
    let start = match first_fold {
        Some(p) => p,
        None => return Cow::Borrowed(s),
    };
    // At least one fold confirmed. Build the owned form as bytes; the
    // output is always UTF-8 because we only ever copy original bytes
    // verbatim (preserving any obs-text multi-byte sequences in their
    // entirety) or inject a single ASCII SP per collapsed fold.
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    out.extend_from_slice(&bytes[..start]);
    let mut i = start;
    while i < bytes.len() {
        if i + 2 < bytes.len()
            && bytes[i] == b'\r'
            && bytes[i + 1] == b'\n'
            && (bytes[i + 2] == b' ' || bytes[i + 2] == b'\t')
        {
            // §3.2.4: replace the obs-fold with "one or more SP
            // octets". We emit exactly one SP — the smallest stable
            // choice — and consume the maximal trailing SP/HTAB run.
            out.push(b' ');
            i += 2;
            while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
                i += 1;
            }
        } else {
            // Not a fold start — copy this byte through verbatim.
            // Multi-byte UTF-8 sequences are preserved because each
            // continuation byte is also copied as-is by the next
            // loop iteration; we never split a code point.
            out.push(bytes[i]);
            i += 1;
        }
    }
    // SAFETY-equivalent: the output is byte-for-byte derived from a
    // valid &str by (a) verbatim byte copies and (b) insertion of
    // ASCII SP (0x20), neither of which can invalidate UTF-8. We
    // still call the checked constructor to avoid `unsafe`.
    match String::from_utf8(out) {
        Ok(s2) => Cow::Owned(s2),
        // Unreachable in practice (see above), but if a future edit
        // ever breaks the byte-preserving invariant we'd rather fall
        // back to the un-normalised input than silently corrupt the
        // field value.
        Err(_) => Cow::Borrowed(s),
    }
}

/// Unwrap a `quoted-string` per RFC 9110 §5.6.4 into its logical
/// value (the byte sequence the producer meant to convey, with every
/// `quoted-pair` collapsed to the octet that followed the backslash).
///
/// ```text
/// quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE
/// qdtext        = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
/// quoted-pair   = "\" ( HTAB / SP / VCHAR / obs-text )
/// ```
///
/// §5.6.4 makes the unescape a hard MUST: "Recipients that process the
/// value of a quoted-string MUST handle a quoted-pair as if it were
/// replaced by the octet following the backslash." Any caller that
/// inspects a quoted-string's contents — media-type parameters per
/// §5.6.6 / §8.3.1, auth-params per §11.4, the `Link` header's
/// `title="…"` per RFC 8288, etc. — must run the input through this
/// step before pattern-matching on its bytes; otherwise a server's
/// `"foo\"bar"` reads as a value boundary instead of a literal `"`.
///
/// Returns `None` when the input is not a syntactically valid
/// `quoted-string`:
///
/// - missing leading or trailing `"`,
/// - any inner byte that is neither `qdtext` nor a `quoted-pair`,
/// - a trailing lone `\` with no octet to escape,
/// - a `\` followed by an octet outside the §5.6.4 `quoted-pair` RHS
///   (`HTAB / SP / VCHAR / obs-text`; notably bare CR/LF cannot be
///   quoted-paired — they would unbalance the field line).
///
/// On success returns the unescaped logical value. When the body
/// carries no `\`-escapes the return is a borrow of the input slice
/// (zero allocations on the common path).
///
/// Currently exercised by the unit-test suite and the cargo-fuzz
/// `parse_headers` harness (through the `__fuzz` re-export gate); no
/// in-driver caller yet, since the §15.3.7.2 multipart rejection
/// only needs the bare type/subtype and the §8.8.3 `entity-tag`
/// production explicitly excludes `quoted-pair` from `etagc`. The
/// primitive is in place ready to back any future per-parameter
/// inspection a §5.6.6 / §8.3.1 / §11.4 parser would need.
#[allow(dead_code)]
fn unquote_string(s: &str) -> Option<std::borrow::Cow<'_, str>> {
    use std::borrow::Cow;
    let bytes = s.as_bytes();
    // Must be DQUOTE-wrapped and at least two bytes long for the
    // empty `""` case.
    if bytes.len() < 2 || bytes[0] != b'"' || bytes[bytes.len() - 1] != b'"' {
        return None;
    }
    let inner = &bytes[1..bytes.len() - 1];
    // Fast pre-scan: validate every byte and detect whether any
    // quoted-pair is present. If none, we can return a Cow::Borrowed
    // slice of the original &str (zero allocation).
    let mut i = 0;
    let mut has_escape = false;
    while i < inner.len() {
        let b = inner[i];
        if b == b'\\' {
            // quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )
            // VCHAR = %x21-7E; obs-text = %x80-FF.
            let nxt = *inner.get(i + 1)?;
            let ok = nxt == 0x09 || nxt == 0x20 || (0x21..=0x7E).contains(&nxt) || nxt >= 0x80;
            if !ok {
                return None;
            }
            has_escape = true;
            i += 2;
        } else {
            // qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
            let ok = b == 0x09
                || b == 0x20
                || b == 0x21
                || (0x23..=0x5B).contains(&b)
                || (0x5D..=0x7E).contains(&b)
                || b >= 0x80;
            if !ok {
                return None;
            }
            i += 1;
        }
    }
    if !has_escape {
        // SAFETY-equivalent: the inner slice is a substring of `s`
        // bounded on both ends by an ASCII byte (`"`), so the byte
        // offsets [1, len-1] fall on UTF-8 code-point boundaries.
        return Some(Cow::Borrowed(
            std::str::from_utf8(inner).expect("inner slice is UTF-8 by construction"),
        ));
    }
    // Slow path: collapse each quoted-pair.
    let mut out: Vec<u8> = Vec::with_capacity(inner.len());
    let mut i = 0;
    while i < inner.len() {
        let b = inner[i];
        if b == b'\\' {
            // Validated above; emit the next octet verbatim.
            out.push(inner[i + 1]);
            i += 2;
        } else {
            out.push(b);
            i += 1;
        }
    }
    // The body is byte-for-byte derived from a valid UTF-8 slice by
    // copying either a qdtext octet or the octet following a `\`,
    // both of which originated as bytes within `s`. The escape's
    // RHS may break a multi-byte UTF-8 sequence boundary if a
    // sender backslash-escaped a single continuation byte, so we
    // must run a checked conversion rather than assume validity.
    match String::from_utf8(out) {
        Ok(decoded) => Some(Cow::Owned(decoded)),
        Err(_) => None,
    }
}

/// Parse a `parameters` production per RFC 9110 §5.6.6 into an ordered
/// `Vec<(name, value)>` of `(lowercase-name, decoded-value)` pairs.
///
/// ```text
/// parameters      = *( OWS ";" OWS [ parameter ] )
/// parameter       = parameter-name "=" parameter-value
/// parameter-name  = token
/// parameter-value = ( token / quoted-string )
/// ```
///
/// Used by callers that have already split a field value's "main" item
/// off of the parameters tail — e.g. the §8.3.1 media type
/// (`type/subtype`) is followed by `*( OWS ";" OWS parameter )`, the
/// §12.5.1 `Accept` field's q-factor lives in the same construction, and
/// the §11.4 `WWW-Authenticate` challenges carry `realm="…", scope=token`
/// auth-params using equivalent shape. The caller passes the tail
/// starting from the first `;` (or starting from an empty/whitespace-only
/// slice if no parameters were attached), and we return one entry per
/// `parameter` that parses; empty list elements (e.g. `;; charset=utf-8`)
/// are silently ignored, matching the §5.6.1 recipient note that empty
/// elements do not contribute. The function never panics on arbitrary
/// input.
///
/// Behaviour:
///
/// - **Names**: lowercased on the way out (§5.6.6: "Parameter names are
///   case-insensitive"). A `parameter-name` that is not a valid §5.6.2
///   token causes that whole entry to be skipped, not a hard reject of
///   the surrounding list — same defensive choice as the
///   `parse_accept_ranges` recipient logic.
/// - **Values**: when the value is `( token )` we return it verbatim
///   (case preservation is the caller's job per §5.6.6's "Parameter
///   values might or might not be case-sensitive, depending on the
///   semantics of the parameter name"); when the value is
///   `( quoted-string )` we run it through [`unquote_string`] so any
///   `quoted-pair` is collapsed per §5.6.4's MUST and the consumer
///   receives the logical octet sequence (boundaries, charsets, realms)
///   ready to pattern-match.
/// - **No whitespace around `=`**: §5.6.6's informational note says
///   "Parameters do not allow whitespace (not even 'bad' whitespace)
///   around the '=' character." A parameter that has SP / HTAB before
///   or after `=` is skipped (not a list-fatal reject), matching the
///   "ignore the bad slot" defensive posture.
/// - **Missing `=`**: a slot like `; foo` (token with no `=value` tail)
///   is skipped — §5.6.6's `parameter = parameter-name "=" parameter-value`
///   makes the `=` a required production; some §8.3.1 in-the-wild
///   senders strip the value, but recipients here decline to invent one.
/// - **Quoted-string boundary**: the `;` split honours quoted-strings —
///   a `;` inside a `"…"` body (e.g. `boundary="a;b"`) is not a slot
///   terminator. Backslash escapes inside the quoted-string are
///   respected by the splitter (so `"a\";b"` reads the `\"` as a
///   quoted-pair and continues past it).
/// - **Optional leading `;`**: callers that hand the tail starting from
///   the first byte after the main item (which is usually `;` but can be
///   `OWS ;`) get the same result as callers that hand the tail starting
///   from the OWS-stripped post-`;` position; the function consumes
///   leading whitespace and an optional `;` before the first parameter.
///
/// Returns an empty `Vec` for empty / whitespace-only / `;`-only inputs.
/// Allocates one `String` per kept name and one per quoted-string body
/// containing at least one `quoted-pair`; token-shape values reuse the
/// input via `String::from(&str)`.
#[allow(dead_code)]
fn parse_parameters(s: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0usize;
    // Outer loop: each iteration consumes one slot (between two `;`
    // boundaries) and either pushes a (name, value) pair or skips it.
    loop {
        // 1. Strip OWS (SP / HTAB only — §5.6.3 OWS).
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }
        // 2. A leading `;` (or any subsequent slot boundary) is consumed
        //    once here; if the slot started directly at a parameter,
        //    skip this step.
        if i < bytes.len() && bytes[i] == b';' {
            i += 1;
            continue;
        }
        if i >= bytes.len() {
            break;
        }
        // 3. Find the end of this slot. The slot ends at the next
        //    top-level `;` (i.e. a `;` not inside a quoted-string).
        let slot_start = i;
        let mut in_quote = false;
        while i < bytes.len() {
            let b = bytes[i];
            if in_quote {
                if b == b'\\' {
                    // Skip the next octet (the quoted-pair RHS) so that
                    // `\"` inside the body does not close the quote.
                    if i + 1 < bytes.len() {
                        i += 2;
                        continue;
                    }
                    // Trailing lone backslash inside a quoted-string —
                    // the slot is malformed; let the per-slot parser
                    // see the body and reject it.
                    i += 1;
                } else if b == b'"' {
                    in_quote = false;
                    i += 1;
                } else {
                    i += 1;
                }
            } else if b == b';' {
                break;
            } else if b == b'"' {
                in_quote = true;
                i += 1;
            } else {
                i += 1;
            }
        }
        let slot = &s[slot_start..i];
        // 4. Try to parse the slot as a single parameter. Anything
        //    that doesn't fit `name=value` (token + `=` + token/qstr)
        //    is skipped per the §5.6.1 "tolerate empty / garbage
        //    list slots" recipient posture.
        if let Some(pair) = parse_one_parameter(slot) {
            out.push(pair);
        }
        // 5. Slot terminator: consume the `;` (if any) and loop.
        if i < bytes.len() && bytes[i] == b';' {
            i += 1;
        }
    }
    out
}

/// Single-parameter parser: `parameter-name "=" parameter-value`. Returns
/// `Some((lowercase-name, decoded-value))` on a syntactically valid
/// `parameter`, `None` for empty / whitespace-only / no-`=` / bad-token
/// / whitespace-around-`=` / malformed-quoted-string slots.
fn parse_one_parameter(slot: &str) -> Option<(String, String)> {
    // §5.6.3 OWS strip on the slot edges. The split-into-slots step
    // above already stripped OWS at the start of the slot, but an OWS
    // *trail* (between the last value byte and the next `;`) is normal
    // in a §5.6.6 list and must be removed here. We trim both ends in
    // case the slot came from a no-`;`-yet single-call.
    let slot = slot.trim_matches(|c: char| c == ' ' || c == '\t');
    if slot.is_empty() {
        return None;
    }
    let eq = slot.find('=')?;
    let name = &slot[..eq];
    let value = &slot[eq + 1..];
    // §5.6.6 note: "Parameters do not allow whitespace (not even 'bad'
    // whitespace) around the '=' character." If the byte just before
    // `=` or the byte just after `=` is SP / HTAB, reject the slot.
    if name
        .as_bytes()
        .last()
        .map(|&b| b == b' ' || b == b'\t')
        .unwrap_or(false)
    {
        return None;
    }
    if value
        .as_bytes()
        .first()
        .map(|&b| b == b' ' || b == b'\t')
        .unwrap_or(false)
    {
        return None;
    }
    // §5.6.6: `parameter-name = token` — reject any non-token name so
    // that downstream consumers can rely on it. (We do not gate on
    // emptiness specifically; `is_token` rejects empty inputs.)
    if !is_token(name) {
        return None;
    }
    // §5.6.6: `parameter-value = ( token / quoted-string )`. If the
    // value starts with DQUOTE, route it through the §5.6.4 unwrap
    // (which collapses any quoted-pair). Otherwise it MUST be a token.
    let decoded_value = if value.starts_with('"') {
        unquote_string(value)?.into_owned()
    } else if is_token(value) {
        value.to_owned()
    } else {
        return None;
    };
    Some((name.to_ascii_lowercase(), decoded_value))
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

/// A parsed `Retry-After` header value per RFC 9110 §10.2.3.
///
/// Servers send this header to indicate how long a user agent ought to
/// wait before issuing a follow-up request. The grammar is
///
/// ```text
/// Retry-After   = HTTP-date / delay-seconds
/// delay-seconds = 1*DIGIT
/// ```
///
/// We surface both variants — the delay-seconds form as a
/// [`std::time::Duration`] for direct sleep-arithmetic, the HTTP-date
/// form as the same six-tuple `(year, month, day, hour, minute,
/// second)` that the §5.6.7 parsers return so the caller can compare
/// against its own clock without dragging a date-time crate in. The
/// driver does NOT itself wall-clock the date — interpreting "wait
/// until this absolute time" requires a clock the source does not
/// own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryAfter {
    /// `Retry-After: <N>` — delay this many seconds from receipt of
    /// the response. §10.2.3 mandates a non-negative decimal integer
    /// (`1*DIGIT`).
    Delay(Duration),
    /// `Retry-After: <HTTP-date>` — wait until this absolute UTC time.
    /// All three §5.6.7 forms are accepted on the receiver side
    /// (IMF-fixdate / rfc850-date / asctime-date), matching the MUST
    /// in §5.6.7.
    Date {
        /// Four-digit calendar year (1-9999, but the §5.6.7 sliding
        /// window for rfc850-date constrains real-world values to
        /// roughly REF_YEAR-49..=REF_YEAR+49).
        year: i32,
        /// Calendar month, 1-12.
        month: u8,
        /// Day of month, 1-31.
        day: u8,
        /// Hour, 0-23.
        hour: u8,
        /// Minute, 0-59.
        minute: u8,
        /// Second, 0-60 (the §5.6.7 grammar allows 60 for leap
        /// seconds; the parser does not range-check it specially).
        second: u8,
    },
}

/// Parse a `Retry-After` field value per RFC 9110 §10.2.3.
///
/// ABNF: `Retry-After = HTTP-date / delay-seconds` where
/// `delay-seconds = 1*DIGIT`. The grammar is `delay-seconds`
/// disjoint from `HTTP-date`, so we try `delay-seconds` first
/// (cheaper, ambiguity-free — pure digits cannot match any of the
/// three HTTP-date forms which all start with an alphabetic weekday
/// name or token) then fall back to `parse_http_date`.
///
/// Returns `None` on syntactically invalid input (leading sign,
/// non-numeric characters in the delay-seconds form that also fail
/// every HTTP-date form, empty input, etc.). §10.2.3 makes
/// `delay-seconds` "a non-negative decimal integer" — we reject a
/// leading `+` or `-` even though Rust's `u64::parse` would refuse
/// `-` natively, because `+` would otherwise parse successfully.
pub fn parse_retry_after(s: &str) -> Option<RetryAfter> {
    // §10.2.3 doesn't itself say "OWS-tolerant" but every other
    // field value in §5.6 is trimmed of surrounding OWS at field-
    // parse time; we match that convention here.
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // delay-seconds = 1*DIGIT. A leading sign would parse via
    // `u64::from_str` for `+` only; reject explicitly so the
    // §10.2.3 "non-negative decimal integer" rule is enforced
    // grammar-strictly rather than accidentally.
    if s.bytes().all(|b| b.is_ascii_digit()) {
        if let Ok(n) = s.parse::<u64>() {
            return Some(RetryAfter::Delay(Duration::from_secs(n)));
        }
        // All-digit but overflows u64 — §10.2.3 has no upper
        // bound, but a value that doesn't fit u64 seconds (≈ 584
        // billion years) is not a real-world Retry-After. Surface
        // as "unparseable" rather than silently saturating.
        return None;
    }
    let (year, month, day, hour, minute, second) = parse_http_date(s)?;
    Some(RetryAfter::Date {
        year,
        month,
        day,
        hour,
        minute,
        second,
    })
}

/// Render a `Retry-After` field value into a parenthesised hint suitable
/// for appending to an error message — `" (Retry-After: 120 s)"` for the
/// `delay-seconds` form, `" (Retry-After: 1999-12-31T23:59:59 UTC)"` for
/// the HTTP-date form, `" (Retry-After: <raw>, unparseable per RFC 9110
/// §10.2.3)"` when the field is set but does not match either grammar.
///
/// Returns the empty string when `raw.trim().is_empty()` so the caller
/// can append unconditionally. The `UTC` suffix mirrors §5.6.7's "values
/// in the asctime format are assumed to be in UTC" / "GMT" semantics
/// — every §5.6.7 form is wall-clock UTC.
fn format_retry_after_hint(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    match parse_retry_after(trimmed) {
        Some(RetryAfter::Delay(d)) => format!(" (Retry-After: {} s)", d.as_secs()),
        Some(RetryAfter::Date {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }) => {
            format!(
                " (Retry-After: {year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02} UTC)"
            )
        }
        None => format!(" (Retry-After: {trimmed:?}, unparseable per RFC 9110 §10.2.3)"),
    }
}

/// Detect a `Content-Type: multipart/byteranges[; …]` field value per
/// RFC 9110 §14.6 / §15.3.7. The media-type proper is case-insensitive
/// (§8.3.1: "type, subtype, and parameter name tokens are
/// case-insensitive"); the boundary parameter is required by §14.6 but
/// we do not need to extract it — every multipart 206 we ever see is a
/// server bug because the driver only ever requests single-range, and
/// §15.3.7.2 makes "A server MUST NOT generate a multipart response to
/// a request for a single range" a hard MUST NOT.
///
/// Tolerant of OWS before/after the media type per §5.6.3 and of
/// trailing `; key=value` parameters per §8.3 (we discard them — the
/// only thing the driver acts on is the type/subtype match).
fn is_multipart_byteranges_content_type(s: &str) -> bool {
    let s = s.trim();
    // §8.3 media-type ABNF: `type "/" subtype *( OWS ";" OWS parameter )`.
    // Split off the first `;` so trailing parameters (boundary=…, etc.)
    // don't affect the type/subtype match.
    let media = match s.split_once(';') {
        Some((m, _)) => m.trim_end(),
        None => s,
    };
    media.eq_ignore_ascii_case("multipart/byteranges")
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
    /// Fuzz-only wrapper for [`super::parse_retry_after`] (RFC 9110
    /// §10.2.3 — `HTTP-date / delay-seconds`).
    pub fn parse_retry_after(s: &str) -> bool {
        super::parse_retry_after(s).is_some()
    }
    /// Fuzz-only wrapper for [`super::derive_strong_validator`]. The
    /// caller splits the input on NUL bytes into up to three optional
    /// header values (etag, last-modified, date) so the fuzzer can
    /// drive all 8 input-presence combinations.
    pub fn derive_strong_validator(etag: Option<&str>, lm: Option<&str>, date: Option<&str>) {
        let _ = super::derive_strong_validator(etag, lm, date);
    }
    /// Fuzz-only wrapper for [`super::parse_accept_ranges`] (RFC 9110
    /// §14.3 `acceptable-ranges = 1#range-unit`). Returns a small
    /// integer tag (0=Bytes, 1=None, 2=Other, 3=Absent) so the fuzzer
    /// can drive every classification branch.
    pub fn parse_accept_ranges(s: &str) -> u8 {
        match super::parse_accept_ranges(s) {
            super::AcceptRanges::Bytes => 0,
            super::AcceptRanges::None => 1,
            super::AcceptRanges::Other(_) => 2,
            super::AcceptRanges::Absent => 3,
        }
    }
    /// Fuzz-only wrapper for
    /// [`super::is_multipart_byteranges_content_type`] (RFC 9110 §8.3
    /// + §14.6 / §15.3.7.2).
    pub fn is_multipart_byteranges_content_type(s: &str) -> bool {
        super::is_multipart_byteranges_content_type(s)
    }
    /// Fuzz-only wrapper for [`super::format_retry_after_hint`] —
    /// exercises the RFC 9110 §10.2.3 surfacing path used by the HEAD
    /// non-success branch. Returns the rendered hint so the fuzzer can
    /// verify the function never panics on arbitrary input.
    pub fn format_retry_after_hint(s: &str) -> String {
        super::format_retry_after_hint(s)
    }
    /// Fuzz-only wrapper for [`super::normalize_obs_fold`] — exercises
    /// the RFC 7230 §3.2.4 obs-fold normaliser on arbitrary input.
    /// Returns the normalised string so the fuzzer can verify the
    /// function never panics and always yields valid UTF-8.
    pub fn normalize_obs_fold(s: &str) -> String {
        super::normalize_obs_fold(s).into_owned()
    }
    /// Fuzz-only wrapper for [`super::unquote_string`] — exercises the
    /// RFC 9110 §5.6.4 `quoted-string` unwrap (DQUOTE-stripping +
    /// `quoted-pair` collapsing) on arbitrary input. Returns the
    /// decoded value when the input parses, `None` otherwise; either
    /// outcome must be reachable without a panic.
    pub fn unquote_string(s: &str) -> Option<String> {
        super::unquote_string(s).map(|c| c.into_owned())
    }
    /// Fuzz-only wrapper for [`super::parse_parameters`] — exercises the
    /// RFC 9110 §5.6.6 `parameters` grammar (semicolon-delimited
    /// `name=value` slots with quoted-string-aware splitting) on
    /// arbitrary input. Returns the count of recognised parameters so
    /// the fuzzer can drive both the zero-parameter and many-parameter
    /// branches; the function must never panic, and every returned
    /// `(name, value)` pair must be valid UTF-8.
    pub fn parse_parameters(s: &str) -> usize {
        super::parse_parameters(s).len()
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

    // -- RFC 9110 §10.2.3 Retry-After parser ---------------------------------

    #[test]
    fn retry_after_parses_canonical_delay_seconds_form() {
        // §10.2.3 example: "Retry-After: 120" means wait two minutes.
        assert_eq!(
            parse_retry_after("120"),
            Some(RetryAfter::Delay(Duration::from_secs(120)))
        );
    }

    #[test]
    fn retry_after_parses_zero_delay() {
        // §10.2.3 delay-seconds = 1*DIGIT — zero is in-range.
        assert_eq!(
            parse_retry_after("0"),
            Some(RetryAfter::Delay(Duration::from_secs(0)))
        );
    }

    #[test]
    fn retry_after_parses_large_delay_within_u64() {
        // A small CDN reasonably emits "Retry-After: 86400" (one day).
        assert_eq!(
            parse_retry_after("86400"),
            Some(RetryAfter::Delay(Duration::from_secs(86_400)))
        );
    }

    #[test]
    fn retry_after_trims_surrounding_whitespace() {
        // Field-value parsers in this crate are OWS-tolerant per §5.6
        // convention.
        assert_eq!(
            parse_retry_after("   42   "),
            Some(RetryAfter::Delay(Duration::from_secs(42)))
        );
    }

    #[test]
    fn retry_after_parses_imf_fixdate_form() {
        // §10.2.3 example: "Retry-After: Fri, 31 Dec 1999 23:59:59 GMT".
        assert_eq!(
            parse_retry_after("Fri, 31 Dec 1999 23:59:59 GMT"),
            Some(RetryAfter::Date {
                year: 1999,
                month: 12,
                day: 31,
                hour: 23,
                minute: 59,
                second: 59,
            })
        );
    }

    #[test]
    fn retry_after_parses_rfc850_date_form() {
        // §5.6.7 MUSTs receiver acceptance of the obsolete rfc850
        // form — Retry-After inherits that grammar.
        assert_eq!(
            parse_retry_after("Sunday, 06-Nov-94 08:49:37 GMT"),
            Some(RetryAfter::Date {
                year: 1994,
                month: 11,
                day: 6,
                hour: 8,
                minute: 49,
                second: 37,
            })
        );
    }

    #[test]
    fn retry_after_parses_asctime_form() {
        // §5.6.7 MUSTs receiver acceptance of the obsolete asctime
        // form.
        assert_eq!(
            parse_retry_after("Sun Nov  6 08:49:37 1994"),
            Some(RetryAfter::Date {
                year: 1994,
                month: 11,
                day: 6,
                hour: 8,
                minute: 49,
                second: 37,
            })
        );
    }

    #[test]
    fn retry_after_rejects_empty_input() {
        assert_eq!(parse_retry_after(""), None);
        assert_eq!(parse_retry_after("   "), None);
    }

    #[test]
    fn retry_after_rejects_signed_delay_seconds() {
        // §10.2.3 delay-seconds = 1*DIGIT (non-negative decimal
        // integer); a leading sign is grammar-invalid even though
        // `u64::parse` would refuse it for the negative form.
        assert_eq!(parse_retry_after("-1"), None);
        // The crucial case: `+5` would round-trip through
        // `u64::from_str` on some toolchains; reject explicitly via
        // the all-digit gate.
        assert_eq!(parse_retry_after("+5"), None);
    }

    #[test]
    fn retry_after_rejects_decimal_or_hex_delay() {
        // Pure 1*DIGIT — no fractions, no hex prefix.
        assert_eq!(parse_retry_after("12.5"), None);
        assert_eq!(parse_retry_after("0x10"), None);
        assert_eq!(parse_retry_after("1_000"), None);
    }

    #[test]
    fn retry_after_rejects_delay_with_trailing_garbage() {
        // "120s" looks like a unit-bearing delay but §10.2.3 grammar
        // is bare digits.
        assert_eq!(parse_retry_after("120s"), None);
        assert_eq!(parse_retry_after("120 seconds"), None);
    }

    #[test]
    fn retry_after_rejects_u64_overflow() {
        // §10.2.3 has no upper bound, but a value that doesn't fit
        // u64 seconds (≈ 584 billion years) is not a real-world
        // Retry-After. We surface None rather than saturate.
        // 2^64 = 18446744073709551616 — one beyond u64::MAX.
        assert_eq!(parse_retry_after("18446744073709551616"), None);
    }

    #[test]
    fn retry_after_rejects_malformed_date() {
        // Not a §5.6.7 date in any of the three accepted forms.
        assert_eq!(parse_retry_after("never"), None);
        assert_eq!(parse_retry_after("Tomorrow at noon"), None);
        assert_eq!(parse_retry_after("Fri, 31 Dec 1999 23:59:59 UTC"), None);
    }

    #[test]
    fn retry_after_disambiguates_digit_only_from_date() {
        // §10.2.3 grammar is `HTTP-date / delay-seconds` — disjoint
        // (a pure-digit string cannot match any of the three HTTP-
        // date forms which all begin with an alphabetic weekday
        // name or token). Confirm we pick the delay branch for a
        // pure-digit input even though "1994" could be misread as
        // a year fragment by a sloppy parser.
        assert_eq!(
            parse_retry_after("1994"),
            Some(RetryAfter::Delay(Duration::from_secs(1994)))
        );
    }

    #[test]
    fn retry_after_examples_from_spec_appendix_round_trip() {
        // §10.2.3 names two example values verbatim. Pin both so a
        // future regression cannot silently change behaviour on the
        // canonical inputs.
        let a = parse_retry_after("Fri, 31 Dec 1999 23:59:59 GMT");
        let b = parse_retry_after("120");
        assert!(matches!(a, Some(RetryAfter::Date { year: 1999, .. })));
        assert!(matches!(b, Some(RetryAfter::Delay(d)) if d == Duration::from_secs(120)));
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

    // -- RFC 9110 §14.3 Accept-Ranges parser ---------------------------------

    #[test]
    fn accept_ranges_bare_bytes_is_bytes() {
        // §14.3 canonical example: `Accept-Ranges: bytes`.
        assert_eq!(parse_accept_ranges("bytes"), AcceptRanges::Bytes);
    }

    #[test]
    fn accept_ranges_is_case_insensitive_on_unit_name() {
        // §3.2.6 token equality is case-insensitive; §14.1 cross-refs
        // it. So `BYTES` and `Bytes` must both classify as bytes.
        assert_eq!(parse_accept_ranges("BYTES"), AcceptRanges::Bytes);
        assert_eq!(parse_accept_ranges("Bytes"), AcceptRanges::Bytes);
        assert_eq!(parse_accept_ranges("byTeS"), AcceptRanges::Bytes);
    }

    #[test]
    fn accept_ranges_explicit_none_is_distinct_from_absent() {
        // §14.3 reserves `none` as the explicit-refusal token. The
        // driver must distinguish that from "header simply absent"
        // — the former is the server actively saying "don't try",
        // the latter is informational silence (§14.3 makes the
        // header advisory).
        assert_eq!(parse_accept_ranges("none"), AcceptRanges::None);
        assert_eq!(parse_accept_ranges("NONE"), AcceptRanges::None);
        assert_eq!(parse_accept_ranges(""), AcceptRanges::Absent);
        assert_eq!(parse_accept_ranges("   "), AcceptRanges::Absent);
    }

    #[test]
    fn accept_ranges_list_with_bytes_anywhere_is_bytes() {
        // §14.3 ABNF: `acceptable-ranges = 1#range-unit`. A list
        // construction (RFC 9110 §5.6.1) is comma-separated with
        // OWS tolerance. `bytes` anywhere in the list means the
        // server supports byte ranges.
        assert_eq!(parse_accept_ranges("bytes, foo"), AcceptRanges::Bytes);
        assert_eq!(parse_accept_ranges("foo, bytes"), AcceptRanges::Bytes);
        assert_eq!(parse_accept_ranges("foo,bytes,bar"), AcceptRanges::Bytes);
        assert_eq!(
            parse_accept_ranges("  bytes  ,  baz-units  "),
            AcceptRanges::Bytes
        );
    }

    #[test]
    fn accept_ranges_unknown_units_only_is_other() {
        // Server advertises ranges, but not in the `bytes` unit we
        // speak. The classification carries the lowercased token
        // list so a caller can surface what the server actually
        // offered.
        match parse_accept_ranges("foo-unit") {
            AcceptRanges::Other(v) => assert_eq!(v, vec!["foo-unit"]),
            other => panic!("expected Other, got {other:?}"),
        }
        match parse_accept_ranges("Foo, Bar") {
            AcceptRanges::Other(v) => assert_eq!(v, vec!["foo", "bar"]),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn accept_ranges_none_alongside_real_units_is_other_not_none() {
        // §14.3 doesn't address the contradictory "none + bytes"
        // sender, but does name `none` as a single-element advice
        // value. Treat any list-form containing `none` as `Other`
        // rather than `None` so a misconfigured server doesn't
        // accidentally lock us out of an advertised `bytes`.
        // (bytes-included path is covered above; here we cover the
        // "none + other-unit" no-bytes contradiction.)
        match parse_accept_ranges("none, foo") {
            AcceptRanges::Other(v) => {
                assert!(v.contains(&"none".to_string()));
                assert!(v.contains(&"foo".to_string()));
            }
            other => panic!("expected Other for none+foo, got {other:?}"),
        }
    }

    #[test]
    fn accept_ranges_empty_list_elements_are_skipped() {
        // §5.6.1 explicitly tolerates empty list members.
        assert_eq!(parse_accept_ranges("bytes,,"), AcceptRanges::Bytes);
        assert_eq!(parse_accept_ranges(",bytes,"), AcceptRanges::Bytes);
        assert_eq!(parse_accept_ranges(",,,"), AcceptRanges::Absent);
    }

    #[test]
    fn accept_ranges_non_token_elements_are_skipped_not_fatal() {
        // A server putting garbage (containing characters illegal in
        // a §5.6.2 token — here, a space inside what should be one
        // token) in one slot must not black-hole the legitimate
        // `bytes` next to it.
        assert_eq!(
            parse_accept_ranges("bytes, foo bar baz"),
            AcceptRanges::Bytes
        );
        // Likewise, garbage-only input falls through to Absent (not
        // a panic).
        assert_eq!(parse_accept_ranges("hello world"), AcceptRanges::Absent);
    }

    #[test]
    fn is_token_accepts_tchar_classes() {
        // §5.6.2 tchar coverage spot-check.
        assert!(is_token("bytes"));
        assert!(is_token("foo-bar"));
        assert!(is_token("foo.bar"));
        assert!(is_token("ABC123"));
        assert!(is_token("!#$%&'*+-.^_`|~"));
        assert!(!is_token(""));
        assert!(!is_token("foo bar"));
        assert!(!is_token("foo,bar"));
        assert!(!is_token("foo/bar"));
        assert!(!is_token("\"quoted\""));
    }

    #[test]
    fn local_server_accept_ranges_none_is_unsupported() {
        // §14.3: `Accept-Ranges: none` is the server's explicit advice
        // to not attempt a range request. The driver surfaces this as
        // a distinct Unsupported error so a caller can tell it apart
        // from "header absent" and "header advertises some other
        // unit".
        const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\n\
            Content-Length: 10\r\n\
            Accept-Ranges: none\r\n\
            Connection: close\r\n\
            \r\n";
        const GET: &[u8] = b"HTTP/1.1 200 OK\r\n\
            Content-Length: 10\r\n\
            Connection: close\r\n\
            \r\n\
            0123456789";
        let (uri, _done) = spawn_server(HEAD, GET);
        let err = match HttpSource::open(&uri) {
            Ok(_) => panic!("open must refuse Accept-Ranges: none"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("explicitly refused") || msg.contains("Accept-Ranges: none"),
            "wrong error (no §14.3 'none' refusal phrasing): {msg}"
        );
        assert!(msg.contains("§14.3"), "missing §14.3 cite: {msg}");
    }

    #[test]
    fn local_server_accept_ranges_list_with_bytes_is_accepted() {
        // §14.3 §5.6.1: a list-form Accept-Ranges that includes
        // `bytes` legitimately advertises byte-range support. Must
        // not be refused just because there is a second unit.
        const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\n\
            Content-Length: 10\r\n\
            Accept-Ranges: bytes, foo-unit\r\n\
            Connection: close\r\n\
            \r\n";
        const GET: &[u8] = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Length: 10\r\n\
            Content-Range: bytes 0-9/10\r\n\
            Connection: close\r\n\
            \r\n\
            0123456789";
        let (uri, _done) = spawn_server(HEAD, GET);
        let mut src = HttpSource::open(&uri).expect("open ok");
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        assert_eq!(&buf, b"0123456789");
    }

    #[test]
    fn local_server_accept_ranges_only_unknown_unit_is_unsupported() {
        // §14.3: server speaks ranges, just not in our unit. Surface
        // distinctly from "none" and from "absent" — the message
        // names the unit(s) the server actually advertised.
        const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\n\
            Content-Length: 10\r\n\
            Accept-Ranges: foo-unit\r\n\
            Connection: close\r\n\
            \r\n";
        const GET: &[u8] = b"HTTP/1.1 200 OK\r\n\
            Content-Length: 10\r\n\
            Connection: close\r\n\
            \r\n\
            0123456789";
        let (uri, _done) = spawn_server(HEAD, GET);
        let err = match HttpSource::open(&uri) {
            Ok(_) => panic!("open must refuse non-bytes-only"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("foo-unit") || msg.contains("not 'bytes'"),
            "error must surface the offered unit(s): {msg}"
        );
        assert!(msg.contains("§14.3"), "missing §14.3 cite: {msg}");
    }

    #[test]
    fn local_server_accept_ranges_absent_is_unsupported_distinct_message() {
        // §14.3 makes the header advisory — but the driver's
        // correctness model relies on the server actually satisfying
        // Range, so we preserve the historical refusal here. The
        // message must distinguish "absent" from "none" and from
        // "other unit" so a caller can tell what happened.
        const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\n\
            Content-Length: 10\r\n\
            Connection: close\r\n\
            \r\n";
        const GET: &[u8] = b"HTTP/1.1 200 OK\r\n\
            Content-Length: 10\r\n\
            Connection: close\r\n\
            \r\n\
            0123456789";
        let (uri, _done) = spawn_server(HEAD, GET);
        let err = match HttpSource::open(&uri) {
            Ok(_) => panic!("open must refuse absent Accept-Ranges"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("did not advertise") || msg.contains("Accept-Ranges"),
            "wrong error (no absent-header phrasing): {msg}"
        );
        assert!(msg.contains("§14.3"), "missing §14.3 cite: {msg}");
    }

    // -------------------------------------------------------------
    // RFC 9110 §14.6 / §15.3.7.2: multipart/byteranges media type
    // -------------------------------------------------------------

    #[test]
    fn is_multipart_byteranges_accepts_canonical_form() {
        assert!(is_multipart_byteranges_content_type("multipart/byteranges"));
    }

    #[test]
    fn is_multipart_byteranges_accepts_boundary_parameter() {
        // §14.6: the media type carries a required `boundary` parameter
        // in real-world use; the type/subtype match must succeed
        // regardless.
        assert!(is_multipart_byteranges_content_type(
            "multipart/byteranges; boundary=THIS_STRING_SEPARATES"
        ));
    }

    #[test]
    fn is_multipart_byteranges_is_case_insensitive_per_section_8_3_1() {
        // §8.3.1: "type, subtype, and parameter name tokens are
        // case-insensitive". A server that capitalises the type-name
        // is still §14.6.
        assert!(is_multipart_byteranges_content_type(
            "Multipart/ByteRanges; boundary=x"
        ));
        assert!(is_multipart_byteranges_content_type("MULTIPART/BYTERANGES"));
    }

    #[test]
    fn is_multipart_byteranges_tolerates_ows_around_value() {
        // §5.6.3 OWS handling — Content-Range fields are field-content
        // and OWS-trimmed at the parser level.
        assert!(is_multipart_byteranges_content_type(
            "  multipart/byteranges  "
        ));
        assert!(is_multipart_byteranges_content_type(
            "multipart/byteranges ; boundary=x"
        ));
    }

    #[test]
    fn is_multipart_byteranges_rejects_other_types() {
        // Negatives: the typical single-range Content-Type is the raw
        // representation's media type. Don't false-positive on it.
        for t in [
            "application/pdf",
            "video/mp4",
            "image/jpeg",
            "multipart/form-data; boundary=x",
            "multipart/mixed; boundary=x",
            "text/plain",
            "",
        ] {
            assert!(
                !is_multipart_byteranges_content_type(t),
                "false-positive on {t:?}"
            );
        }
    }

    #[test]
    fn is_multipart_byteranges_does_not_false_positive_on_prefix_subtype() {
        // `multipart/byteranges-foo` is NOT §14.6 even though it shares
        // a prefix — confirm token-equality, not prefix-match.
        assert!(!is_multipart_byteranges_content_type(
            "multipart/byteranges-foo"
        ));
    }

    #[test]
    fn local_server_206_with_multipart_byteranges_is_rejected() {
        // §15.3.7.2: "A server MUST NOT generate a multipart response
        // to a request for a single range." We only ever ask for one
        // range. A 206 carrying Content-Type: multipart/byteranges is a
        // server bug; surface a clean §15.3.7 cite rather than letting
        // the body's boundary delimiter sneak into the demuxer's
        // bitstream view.
        static GET: &[u8] = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Length: 10\r\n\
            Content-Type: multipart/byteranges; boundary=THIS_STRING_SEPARATES\r\n\
            Content-Range: bytes 0-9/10\r\n\
            Connection: close\r\n\
            \r\n\
            0123456789";
        let (uri, _done) = spawn_server(HEAD_10B_BYTES, GET);
        let mut src = HttpSource::open(&uri).expect("open ok");
        let mut buf = [0u8; 10];
        let err = std::io::Read::read_exact(&mut src, &mut buf).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("multipart/byteranges"),
            "error must name the offending media type: {msg}"
        );
        assert!(msg.contains("§15.3.7"), "error must cite §15.3.7: {msg}");
    }

    #[test]
    fn local_server_206_with_uppercase_multipart_byteranges_is_rejected() {
        // §8.3.1 case-insensitivity: an origin that title-cases the
        // media type must still be detected as §15.3.7.2-illegal.
        static GET: &[u8] = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Length: 10\r\n\
            Content-Type: Multipart/ByteRanges; boundary=x\r\n\
            Content-Range: bytes 0-9/10\r\n\
            Connection: close\r\n\
            \r\n\
            0123456789";
        let (uri, _done) = spawn_server(HEAD_10B_BYTES, GET);
        let mut src = HttpSource::open(&uri).expect("open ok");
        let mut buf = [0u8; 10];
        let err = std::io::Read::read_exact(&mut src, &mut buf).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("multipart/byteranges") || msg.contains("Multipart/ByteRanges"),
            "error must name the offending media type: {msg}"
        );
    }

    #[test]
    fn local_server_206_with_video_mp4_content_type_is_accepted() {
        // Sanity: a 206 with the raw representation media type must
        // still succeed — only multipart/byteranges flips the new
        // §15.3.7.2 guard.
        static GET: &[u8] = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Length: 10\r\n\
            Content-Type: video/mp4\r\n\
            Content-Range: bytes 0-9/10\r\n\
            Connection: close\r\n\
            \r\n\
            0123456789";
        let (uri, _done) = spawn_server(HEAD_10B_BYTES, GET);
        let mut src = HttpSource::open(&uri).expect("open ok");
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        assert_eq!(&buf, b"0123456789");
    }

    // -------------------------------------------------------------
    // RFC 9110 §10.2.3: Retry-After surfacing on HEAD non-success
    // -------------------------------------------------------------

    #[test]
    fn format_retry_after_hint_renders_delay_seconds_form() {
        let h = format_retry_after_hint("120");
        assert_eq!(h, " (Retry-After: 120 s)");
    }

    #[test]
    fn format_retry_after_hint_renders_zero_delay() {
        let h = format_retry_after_hint("0");
        assert_eq!(h, " (Retry-After: 0 s)");
    }

    #[test]
    fn format_retry_after_hint_renders_imf_fixdate_form() {
        // §10.2.3 canonical example.
        let h = format_retry_after_hint("Fri, 31 Dec 1999 23:59:59 GMT");
        assert_eq!(h, " (Retry-After: 1999-12-31T23:59:59 UTC)");
    }

    #[test]
    fn format_retry_after_hint_renders_rfc850_form_uniformly() {
        // §5.6.7 MUST-accept the obsolete form. The rendered hint must
        // canonicalise to the same ISO-8601-ish surface so the caller
        // gets a stable shape regardless of which form the origin used.
        let h = format_retry_after_hint("Sunday, 06-Nov-94 08:49:37 GMT");
        // Year 1994 wraps under the §5.6.7 sliding window from `94`.
        assert!(
            h.contains("1994-11-06T08:49:37 UTC"),
            "rfc850 canonicalisation: {h}"
        );
    }

    #[test]
    fn format_retry_after_hint_renders_asctime_form_uniformly() {
        let h = format_retry_after_hint("Sun Nov  6 08:49:37 1994");
        assert!(
            h.contains("1994-11-06T08:49:37 UTC"),
            "asctime canonicalisation: {h}"
        );
    }

    #[test]
    fn format_retry_after_hint_surfaces_unparseable_value() {
        // §10.2.3 grammar is strict — a unit-bearing form is rejected
        // by parse_retry_after. The hint helper should still produce a
        // diagnostic that names the raw value and the §10.2.3 cite so
        // the caller can see the origin's bug rather than a silent
        // "no Retry-After hint".
        let h = format_retry_after_hint("Tomorrow at noon");
        assert!(h.contains("Tomorrow at noon"), "unparseable hint: {h}");
        assert!(h.contains("unparseable"), "no diagnostic: {h}");
        assert!(h.contains("§10.2.3"), "no cite: {h}");
    }

    #[test]
    fn format_retry_after_hint_skips_empty_input() {
        // Sentinel: an empty / whitespace-only value collapses to "",
        // so the caller's `format!("status {status}{hint}")` does not
        // emit a parenthesised empty.
        assert_eq!(format_retry_after_hint(""), "");
        assert_eq!(format_retry_after_hint("   "), "");
        assert_eq!(format_retry_after_hint("\t"), "");
    }

    #[test]
    fn format_retry_after_hint_trims_surrounding_ows() {
        // §5.6.3 OWS — leading/trailing horizontal whitespace is field
        // framing, not value semantics.
        let h = format_retry_after_hint("  120  ");
        assert_eq!(h, " (Retry-After: 120 s)");
    }

    /// Spawn a minimal HEAD-only server that always returns
    /// `head_resp`. Used by the §10.2.3 Retry-After tests which never
    /// reach the GET stage.
    fn spawn_head_only(head_resp: &'static [u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for _ in 0..2 {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut buf = [0u8; 4096];
                use std::io::Read as _;
                let _ = stream.read(&mut buf).unwrap_or(0);
                let _ = stream.write_all(head_resp);
                let _ = stream.flush();
            }
        });
        format!("http://127.0.0.1:{port}/x")
    }

    #[test]
    fn local_server_head_503_surfaces_retry_after_delay() {
        // §10.2.3: "When sent with a 503 (Service Unavailable)
        // response, Retry-After indicates how long the service is
        // expected to be unavailable to the requesting client." The
        // HEAD non-success branch must surface the parsed delay so the
        // caller wiring back-off doesn't have to refetch the header.
        const HEAD: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
            Content-Length: 0\r\n\
            Retry-After: 120\r\n\
            Connection: close\r\n\
            \r\n";
        let uri = spawn_head_only(HEAD);
        let err = match HttpSource::open(&uri) {
            Ok(_) => panic!("503 must error"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(msg.contains("503"), "wrong error (no 503): {msg}");
        assert!(
            msg.contains("Retry-After: 120 s"),
            "Retry-After delay must surface in the message: {msg}"
        );
    }

    #[test]
    fn local_server_head_429_surfaces_retry_after_date() {
        // §10.2.3 also accompanies 429 (Too Many Requests, RFC 6585)
        // with a Retry-After. Test the HTTP-date form alongside the
        // delay-seconds form.
        const HEAD: &[u8] = b"HTTP/1.1 429 Too Many Requests\r\n\
            Content-Length: 0\r\n\
            Retry-After: Fri, 31 Dec 1999 23:59:59 GMT\r\n\
            Connection: close\r\n\
            \r\n";
        let uri = spawn_head_only(HEAD);
        let err = match HttpSource::open(&uri) {
            Ok(_) => panic!("429 must error"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(msg.contains("429"), "wrong error (no 429): {msg}");
        assert!(
            msg.contains("1999-12-31T23:59:59 UTC"),
            "Retry-After date must surface canonicalised in the message: {msg}"
        );
    }

    #[test]
    fn local_server_head_503_without_retry_after_omits_hint() {
        // Sentinel: a 503 with no Retry-After must NOT carry a
        // parenthesised empty hint. The error stays "status 503" as
        // before.
        const HEAD: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
            Content-Length: 0\r\n\
            Connection: close\r\n\
            \r\n";
        let uri = spawn_head_only(HEAD);
        let err = match HttpSource::open(&uri) {
            Ok(_) => panic!("503 must error"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(msg.contains("503"), "wrong error (no 503): {msg}");
        assert!(
            !msg.contains("Retry-After"),
            "must not emit a Retry-After hint when none was sent: {msg}"
        );
    }

    // -----------------------------------------------------------------
    // RFC 7230 §3.2.4 obs-fold normalisation
    // -----------------------------------------------------------------

    #[test]
    fn obs_fold_absent_returns_borrowed_unchanged() {
        // No `\r\n` at all — must short-circuit to Cow::Borrowed
        // without allocating.
        let s = "bytes=0-1023";
        let out = normalize_obs_fold(s);
        assert_eq!(out, "bytes=0-1023");
        assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn obs_fold_crlf_without_sp_or_htab_is_not_a_fold() {
        // §3.2 ABNF: `obs-fold = CRLF 1*( SP / HTAB )`. A CRLF NOT
        // followed by SP/HTAB is not an obs-fold; the function must
        // leave it alone (the framing layer will flag it).
        let s = "abc\r\nxyz";
        let out = normalize_obs_fold(s);
        assert_eq!(out, "abc\r\nxyz");
        assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn obs_fold_bare_cr_or_lf_is_not_a_fold() {
        // Only the full `\r\n` sequence opens an obs-fold per §3.2.
        // Bare CR followed by SP, or bare LF followed by SP, must
        // pass through unmodified.
        let s = "abc\r def";
        let out = normalize_obs_fold(s);
        assert_eq!(out, "abc\r def");
        let s = "abc\n def";
        let out = normalize_obs_fold(s);
        assert_eq!(out, "abc\n def");
    }

    #[test]
    fn obs_fold_single_sp_collapses_to_one_sp() {
        // The minimal §3.2.4 case: `CRLF SP` between two field-vchar
        // runs must become a single SP.
        let s = "abc\r\n def";
        let out = normalize_obs_fold(s);
        assert_eq!(out, "abc def");
        assert!(matches!(out, std::borrow::Cow::Owned(_)));
    }

    #[test]
    fn obs_fold_single_htab_collapses_to_one_sp() {
        // §3.2.4: HTAB is alternative-equivalent to SP inside the
        // fold continuation. Both collapse to a single SP.
        let s = "abc\r\n\tdef";
        let out = normalize_obs_fold(s);
        assert_eq!(out, "abc def");
    }

    #[test]
    fn obs_fold_multiple_sp_htab_collapses_to_one_sp() {
        // `obs-fold = CRLF 1*( SP / HTAB )` — the continuation is
        // a maximal run of any mix of SP/HTAB. We collapse the whole
        // run to one SP.
        let s = "abc\r\n  \t \tdef";
        let out = normalize_obs_fold(s);
        assert_eq!(out, "abc def");
    }

    #[test]
    fn obs_fold_multiple_folds_each_collapse_independently() {
        // Two distinct obs-fold occurrences must each become exactly
        // one SP — the count of folds in the input equals the count
        // of replacement SPs in the output.
        let s = "a\r\n b\r\n\tc";
        let out = normalize_obs_fold(s);
        assert_eq!(out, "a b c");
    }

    #[test]
    fn obs_fold_at_start_of_value_collapses() {
        // The §3.2 ABNF puts obs-fold inside `field-value`, so a
        // value that begins with an obs-fold (the recipient passes
        // through a non-stripped leading OWS context) must still
        // collapse cleanly.
        let s = "\r\n abc";
        let out = normalize_obs_fold(s);
        assert_eq!(out, " abc");
    }

    #[test]
    fn obs_fold_trailing_crlf_without_continuation_is_not_a_fold() {
        // A trailing `\r\n` with no SP/HTAB after it is the framing
        // line-terminator, not an obs-fold. Pass through unmodified.
        let s = "abc\r\n";
        let out = normalize_obs_fold(s);
        assert_eq!(out, "abc\r\n");
        assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn obs_fold_preserves_obs_text_bytes() {
        // §3.2 allows `obs-text = %x80-FF` inside field-vchar. Such
        // bytes appear as multi-byte UTF-8 sequences in &str. The
        // normaliser must not split or mangle them.
        // U+00E9 ('é') is two UTF-8 bytes: 0xC3 0xA9.
        let s = "ab\u{00e9}\r\n cd\u{00e9}";
        let out = normalize_obs_fold(s);
        assert_eq!(out, "ab\u{00e9} cd\u{00e9}");
    }

    #[test]
    fn obs_fold_does_not_touch_intra_field_whitespace_runs() {
        // The §3.2 ABNF allows `1*( SP / HTAB )` inside
        // field-content; only CRLF-prefixed runs are obs-fold. A
        // plain `   ` in the middle of a value is data and must be
        // left exactly as is.
        let s = "abc   def\t\tghi";
        let out = normalize_obs_fold(s);
        assert_eq!(out, "abc   def\t\tghi");
        assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn obs_fold_empty_input_is_borrowed_empty() {
        // Defensive: an empty field-value (§3.2 `*( field-content /
        // obs-fold )` permits zero occurrences) must short-circuit.
        let s = "";
        let out = normalize_obs_fold(s);
        assert_eq!(out, "");
        assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn obs_fold_then_non_fold_crlf_handles_each_independently() {
        // Mixed input: one real fold, then a CRLF that is NOT a
        // fold. The fold collapses; the trailing CRLF survives.
        let s = "a\r\n b\r\nc";
        let out = normalize_obs_fold(s);
        assert_eq!(out, "a b\r\nc");
    }

    #[test]
    fn obs_fold_inside_quoted_string_is_still_normalised() {
        // §3.2.4 has no exception for quoted-string spans; the
        // normalisation runs at the field-value layer, before any
        // grammar-specific parser. A folded value inside a
        // quoted-string still loses the `CRLF SP` framing — the
        // quoted-string parser sees a single SP and treats it as a
        // literal space, which matches what the sender intended
        // before the §3.2.4-deprecated line-folding pass.
        let s = "\"a\r\n b\"";
        let out = normalize_obs_fold(s);
        assert_eq!(out, "\"a b\"");
    }

    #[test]
    fn obs_fold_chained_folds_back_to_back_collapse_once_each() {
        // Two folds with no field-vchar between them is unusual but
        // not ill-formed: `CRLF SP CRLF SP`. Per §3.2.4 each fold
        // collapses to one SP, so the output is two SPs.
        let s = "a\r\n \r\n b";
        let out = normalize_obs_fold(s);
        assert_eq!(out, "a  b");
    }

    #[test]
    fn obs_fold_existing_parsers_remain_obs_fold_agnostic() {
        // Sanity coupling: the function's contract is "normalise
        // before interpreting the field value", so feeding a folded
        // input directly to one of the §5.6.7 / §10.2.3 parsers
        // would still fail (they don't know about folds). After
        // normalisation, the same parser succeeds. This pins the
        // §3.2.4 "prior to interpreting" ordering.
        let folded = "Wed, 21 Oct 2026\r\n 07:28:00 GMT";
        // Pre-normalisation: the parser sees CRLF SP and rejects.
        assert!(parse_imf_fixdate(folded).is_none());
        // Post-normalisation: a single SP collapses cleanly into
        // the expected single-space separator.
        let normalised = normalize_obs_fold(folded);
        assert!(parse_imf_fixdate(&normalised).is_some());
    }

    // --- §5.6.4 quoted-string unwrap ---------------------------------

    #[test]
    fn unquote_string_empty_pair_decodes_to_empty_borrowed() {
        // The minimal §5.6.4 input is `""` (two DQUOTEs, no content).
        // It is well-formed and decodes to the empty string. With no
        // escapes present the return must be a borrow (the inner
        // slice is the empty &str inside the input).
        let v = unquote_string("\"\"").unwrap();
        assert_eq!(&*v, "");
        assert!(matches!(v, std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn unquote_string_escape_free_returns_cow_borrowed() {
        // No `\` in the body — the §5.6.4 unescape pass is a no-op
        // and the implementation must short-circuit to Cow::Borrowed
        // so a hot path that never sees escapes stays allocation-free.
        let v = unquote_string("\"plain text\"").unwrap();
        assert_eq!(&*v, "plain text");
        assert!(matches!(v, std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn unquote_string_quoted_dquote_collapses_to_one_dquote() {
        // `quoted-pair = "\" ( … VCHAR … )` — DQUOTE is VCHAR, so the
        // pair is well-formed and the §5.6.4 MUST collapses it to the
        // single octet that followed the backslash.
        let v = unquote_string("\"a\\\"b\"").unwrap();
        assert_eq!(&*v, "a\"b");
        assert!(matches!(v, std::borrow::Cow::Owned(_)));
    }

    #[test]
    fn unquote_string_quoted_backslash_collapses_to_one_backslash() {
        // Same rule applied to `\` itself.
        let v = unquote_string("\"a\\\\b\"").unwrap();
        assert_eq!(&*v, "a\\b");
    }

    #[test]
    fn unquote_string_missing_leading_dquote_rejects() {
        assert!(unquote_string("hello\"").is_none());
    }

    #[test]
    fn unquote_string_missing_trailing_dquote_rejects() {
        assert!(unquote_string("\"hello").is_none());
    }

    #[test]
    fn unquote_string_single_dquote_rejects() {
        // One byte cannot match the `DQUOTE *(...) DQUOTE` shape.
        assert!(unquote_string("\"").is_none());
    }

    #[test]
    fn unquote_string_unwrapped_rejects() {
        assert!(unquote_string("hello").is_none());
    }

    #[test]
    fn unquote_string_empty_rejects() {
        assert!(unquote_string("").is_none());
    }

    #[test]
    fn unquote_string_trailing_lone_backslash_rejects() {
        // `\` with nothing after it cannot satisfy the
        // `quoted-pair = "\" ( … )` rule — there is no octet to
        // escape.
        assert!(unquote_string("\"abc\\\"").is_none());
    }

    #[test]
    fn unquote_string_quoted_pair_with_cr_or_lf_rejects() {
        // `quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )` — CR
        // (0x0D) and LF (0x0A) are control bytes outside that RHS,
        // and a quoted-pair'd bare line-ending would unbalance the
        // field line at the framing layer.
        let cr = [b'"', b'a', b'\\', b'\r', b'b', b'"'];
        assert!(unquote_string(std::str::from_utf8(&cr).unwrap()).is_none());
        let lf = [b'"', b'a', b'\\', b'\n', b'b', b'"'];
        assert!(unquote_string(std::str::from_utf8(&lf).unwrap()).is_none());
    }

    #[test]
    fn unquote_string_bare_qdtext_excluded_byte_rejects() {
        // `qdtext` excludes `"` (0x22) and `\` (0x5C). A bare `"`
        // inside the body without an escape would terminate the
        // string at the framing parser; our unwrap, given a slice
        // that includes the inner `"`, must refuse rather than
        // silently truncate.
        // We construct `"a"b"` — bytes 0x22 0x61 0x22 0x62 0x22 —
        // where the middle 0x22 is bare qdtext (excluded), so the
        // unwrap must refuse.
        assert!(unquote_string("\"a\"b\"").is_none());
        // Bare `\` (without a following octet pair) is the trailing
        // case covered above; bare `\` followed by a non-escapable
        // byte is the CR/LF case. There's no remaining bare-qdtext
        // path for `\` to reach this branch through.
    }

    #[test]
    fn unquote_string_bare_control_byte_rejects() {
        // `qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text`.
        // Bare BEL (0x07) is below the SP/HTAB range and outside any
        // qdtext slot, so the body fails validation.
        let bel = [b'"', b'a', 0x07, b'b', b'"'];
        assert!(unquote_string(std::str::from_utf8(&bel).unwrap()).is_none());
    }

    #[test]
    fn unquote_string_obs_text_byte_in_body_accepted() {
        // `qdtext` includes `obs-text = %x80-FF`. A literal high
        // byte is well-formed `qdtext` — the unwrap must accept it
        // and the decoded value must round-trip through valid UTF-8.
        // U+00E9 (é) is 0xC3 0xA9 — both bytes are in the obs-text
        // range, the resulting borrow is the same UTF-8 sequence.
        let v = unquote_string("\"\u{00e9}\"").unwrap();
        assert_eq!(&*v, "\u{00e9}");
        // No `\` present, so borrowing is required for the hot path.
        assert!(matches!(v, std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn unquote_string_escape_preserving_obs_text_byte_accepted() {
        // `quoted-pair`'s RHS is `HTAB / SP / VCHAR / obs-text`, so
        // an escaped obs-text byte is permitted and must collapse to
        // that byte. We escape only the first byte of U+00E9 so the
        // pair RHS is exactly one obs-text octet (0xC3), then let
        // the trailing continuation byte (0xA9) fall through as
        // bare qdtext. The decoded UTF-8 is the same `é`.
        let inp: [u8; 5] = [b'"', b'\\', 0xC3, 0xA9, b'"'];
        let v = unquote_string(std::str::from_utf8(&inp).unwrap()).unwrap();
        assert_eq!(v.as_bytes(), &[0xC3, 0xA9]);
    }

    #[test]
    fn unquote_string_only_unescapes_in_slow_path() {
        // Belt-and-braces invariant: an input that contains at least
        // one `\` must yield `Cow::Owned` even if the decoded value
        // happens to equal a substring of the input. This guards
        // against a future "optimisation" that aliased the body
        // through Cow::Borrowed when no character moved.
        let v = unquote_string("\"a\\bc\"").unwrap();
        assert_eq!(&*v, "abc");
        assert!(matches!(v, std::borrow::Cow::Owned(_)));
    }

    #[test]
    fn unquote_string_decodes_used_in_media_type_parameter_rhs() {
        // §5.6.6 says `parameter-value = ( token / quoted-string )`.
        // A media type carrying `name="weird;value"` — where the
        // body contains the parameter delimiter `;` — must round
        // through the §5.6.4 unwrap before the consumer pattern-
        // matches on its contents. This is a coupling test: it
        // pins the §5.6.4 → §5.6.6 layering.
        let v = unquote_string("\"weird;value\"").unwrap();
        assert_eq!(&*v, "weird;value");
        // §8.3.1's `boundary="..."` parameter on multipart media
        // types is the most common in-the-wild caller of this
        // primitive; the unwrap must hand back the inner bytes
        // verbatim regardless of which bytes those are.
        let v = unquote_string("\"--my\\\"boundary--\"").unwrap();
        assert_eq!(&*v, "--my\"boundary--");
    }

    // --- §5.6.6 parameters ---------------------------------------------

    #[test]
    fn parse_parameters_empty_input_yields_no_entries() {
        // §5.6.6 `parameters = *( OWS ";" OWS [ parameter ] )` — zero
        // repetitions is the canonical empty case (a media type with
        // no attached parameters).
        assert!(parse_parameters("").is_empty());
    }

    #[test]
    fn parse_parameters_whitespace_only_yields_no_entries() {
        // §5.6.3 OWS in any quantity must not produce phantom entries.
        assert!(parse_parameters("   \t  ").is_empty());
    }

    #[test]
    fn parse_parameters_semicolon_only_yields_no_entries() {
        // §5.6.1 recipient requirement: "A recipient MUST parse and
        // ignore … empty list elements." A trail of bare semicolons is
        // the in-the-wild equivalent on the §5.6.6 parameter list.
        assert!(parse_parameters(";").is_empty());
        assert!(parse_parameters(";;;").is_empty());
        assert!(parse_parameters("; ; ;").is_empty());
    }

    #[test]
    fn parse_parameters_single_token_value() {
        // Canonical `; name=token` from §5.6.6 example domain (e.g.
        // `Content-Type: text/plain; charset=utf-8` after the main
        // type/subtype has been split off).
        let p = parse_parameters("; charset=utf-8");
        assert_eq!(p, vec![("charset".to_owned(), "utf-8".to_owned())]);
    }

    #[test]
    fn parse_parameters_leading_semicolon_optional() {
        // Whether the caller strips the leading `;` or hands it through,
        // the parser must produce the same output. Both shapes are
        // legal §5.6.6 tails.
        let with_semi = parse_parameters("; charset=utf-8");
        let without_semi = parse_parameters("charset=utf-8");
        assert_eq!(with_semi, without_semi);
    }

    #[test]
    fn parse_parameters_name_lowercased_per_5_6_6_case_insensitivity() {
        // §5.6.6: "Parameter names are case-insensitive." We emit
        // lowercase so downstream pattern-matches use a stable form.
        let p = parse_parameters("; CHARSET=UTF-8");
        // Name lowercased; value preserved verbatim (case-sensitivity
        // of the value depends on the semantics of the name — §5.6.6).
        assert_eq!(p, vec![("charset".to_owned(), "UTF-8".to_owned())]);
    }

    #[test]
    fn parse_parameters_quoted_string_value_unwrapped() {
        // `parameter-value = ( token / quoted-string )`. When the value
        // is a quoted-string the parser MUST unwrap it through §5.6.4
        // so a consumer sees the logical octet sequence.
        let p = parse_parameters("; boundary=\"--foo\"");
        assert_eq!(p, vec![("boundary".to_owned(), "--foo".to_owned())]);
    }

    #[test]
    fn parse_parameters_quoted_pair_collapsed_per_5_6_4() {
        // A `\"` inside the body is a §5.6.4 quoted-pair and MUST
        // collapse to a single `"` in the decoded value. This is the
        // exact case the unquote helper exists for.
        let p = parse_parameters("; boundary=\"--my\\\"boundary--\"");
        assert_eq!(
            p,
            vec![("boundary".to_owned(), "--my\"boundary--".to_owned())],
        );
    }

    #[test]
    fn parse_parameters_semicolon_inside_quoted_string_not_a_separator() {
        // The split-into-slots step MUST honour quoted-strings: a `;`
        // inside a `"…"` body is part of the value, not a list
        // terminator. Otherwise `boundary="a;b"` would be sliced into
        // `boundary="a` + `b"`, each of which would then fail to parse
        // and the legitimate value would silently disappear.
        let p = parse_parameters("; boundary=\"a;b\"");
        assert_eq!(p, vec![("boundary".to_owned(), "a;b".to_owned())]);
    }

    #[test]
    fn parse_parameters_escaped_dquote_inside_quoted_string_not_a_close() {
        // A `\"` inside the body is a quoted-pair, NOT the closing
        // DQUOTE of the value. The splitter MUST respect that or the
        // remaining `;` would slice the value in two.
        let p = parse_parameters("; name=\"a\\\";b\"");
        assert_eq!(p, vec![("name".to_owned(), "a\";b".to_owned())]);
    }

    #[test]
    fn parse_parameters_multiple_entries_preserved_in_order() {
        // §5.6.6 doesn't mandate an ordering for downstream consumers,
        // but our return Vec preserves input order so a caller that
        // wants "first wins" or "last wins" can implement either policy.
        let p = parse_parameters("; charset=utf-8; format=flowed; delsp=yes");
        assert_eq!(
            p,
            vec![
                ("charset".to_owned(), "utf-8".to_owned()),
                ("format".to_owned(), "flowed".to_owned()),
                ("delsp".to_owned(), "yes".to_owned()),
            ],
        );
    }

    #[test]
    fn parse_parameters_empty_slot_silently_skipped() {
        // §5.6.1: "A recipient MUST parse and ignore a reasonable
        // number of empty list elements." Same applies to the §5.6.6
        // parameter list — an empty `; ; ` slot in the middle does
        // not nuke the surrounding good entries.
        let p = parse_parameters("; charset=utf-8; ; format=flowed");
        assert_eq!(
            p,
            vec![
                ("charset".to_owned(), "utf-8".to_owned()),
                ("format".to_owned(), "flowed".to_owned()),
            ],
        );
    }

    #[test]
    fn parse_parameters_missing_equals_skipped() {
        // §5.6.6: `parameter = parameter-name "=" parameter-value`. The
        // `=` is a required production; a bare token slot is malformed
        // and we skip it rather than fabricate a value.
        let p = parse_parameters("; charset=utf-8; bogus; format=flowed");
        assert_eq!(
            p,
            vec![
                ("charset".to_owned(), "utf-8".to_owned()),
                ("format".to_owned(), "flowed".to_owned()),
            ],
        );
    }

    #[test]
    fn parse_parameters_whitespace_around_equals_skipped() {
        // §5.6.6 informational note: "Parameters do not allow
        // whitespace (not even 'bad' whitespace) around the '='
        // character." Any SP / HTAB before or after `=` makes the
        // parameter ill-formed and we skip it. The legitimate
        // neighbours on either side remain.
        let p = parse_parameters("; a=1; b = 2; c=3");
        assert_eq!(
            p,
            vec![
                ("a".to_owned(), "1".to_owned()),
                ("c".to_owned(), "3".to_owned()),
            ],
        );
        // Also covers the "only-before" and "only-after" sub-cases.
        let only_before = parse_parameters("; b =2");
        assert!(only_before.is_empty());
        let only_after = parse_parameters("; b= 2");
        assert!(only_after.is_empty());
    }

    #[test]
    fn parse_parameters_non_token_name_skipped() {
        // §5.6.6: `parameter-name = token`. A name byte outside the
        // §5.6.2 tchar set (e.g. SP inside what should be one token)
        // is ill-formed. The whole slot is skipped, the rest of the
        // list survives.
        let p = parse_parameters("; bad name=v; ok=v");
        assert_eq!(p, vec![("ok".to_owned(), "v".to_owned())]);
    }

    #[test]
    fn parse_parameters_non_token_unquoted_value_skipped() {
        // §5.6.6: `parameter-value = ( token / quoted-string )`. An
        // unquoted value that includes a non-token byte (e.g. SP) is
        // neither shape and must be skipped — a sender that wanted
        // SP in the value should have quoted-string'd it.
        let p = parse_parameters("; bad=a b; ok=v");
        assert_eq!(p, vec![("ok".to_owned(), "v".to_owned())]);
    }

    #[test]
    fn parse_parameters_malformed_quoted_string_value_skipped() {
        // An unterminated `"…` is not a valid §5.6.4 quoted-string,
        // so the §5.6.6 slot it occupies is not a valid `parameter`
        // and must be skipped — the value never silently truncates.
        let p = parse_parameters("; bad=\"unterminated; ok=v");
        // The splitter walks past the `;` inside the (open) quoted
        // span looking for the close DQUOTE, runs off the end, and
        // hands the whole tail to the per-slot parser which rejects
        // it. Net effect: zero entries.
        assert!(p.is_empty(), "got: {p:?}");
    }

    #[test]
    fn parse_parameters_ows_around_semicolons_tolerated() {
        // §5.6.3 OWS is permitted on both sides of each `;` (the
        // `*( OWS ";" OWS [ parameter ] )` production). Tabs and
        // spaces in any quantity must not affect the parsed entries.
        let p = parse_parameters(" \t ;  \t a=1 \t ;\tb=2\t");
        assert_eq!(
            p,
            vec![
                ("a".to_owned(), "1".to_owned()),
                ("b".to_owned(), "2".to_owned()),
            ],
        );
    }

    #[test]
    fn parse_parameters_quoted_value_with_obs_text_byte_preserved() {
        // §5.6.4 qdtext includes obs-text = %x80-FF. A multi-byte
        // UTF-8 sequence inside a quoted-string body must survive
        // unwrap intact — the helper's checked UTF-8 reconstruction
        // covers this end of the contract.
        let p = parse_parameters("; title=\"caf\u{00e9}\"");
        assert_eq!(p, vec![("title".to_owned(), "caf\u{00e9}".to_owned())]);
    }

    #[test]
    fn parse_parameters_realm_auth_param_shape_handles_quoted_value() {
        // §11.4 `WWW-Authenticate` challenges carry `realm="…"` plus
        // other auth-params. Auth-params themselves are `,`-separated
        // (§11.2), not `;`-separated — so this §5.6.6 parser is the
        // wrong tool for a full challenge, but a caller that has
        // already split on `,` and is processing a single
        // `realm="…"` slot must get the value unwrapped cleanly.
        let p = parse_parameters("; realm=\"Protected Area\"");
        assert_eq!(p, vec![("realm".to_owned(), "Protected Area".to_owned())]);
    }

    #[test]
    fn parse_parameters_comma_inside_value_is_not_a_separator() {
        // §5.6.6 makes `;` the slot terminator; `,` is not. A `,` in
        // an unquoted token-shape value would simply not be a valid
        // token byte (§5.6.2 tchar excludes `,`) and the whole slot
        // would be skipped. Confirm the splitter doesn't accidentally
        // treat `,` as a slot end (which would silently truncate the
        // value at the `,`).
        let p = parse_parameters("; bad=a,b");
        // The value `a,b` is not a §5.6.2 token (`,` is not tchar),
        // so the slot is rejected as a whole — net result: zero
        // entries. We are NOT silently keeping the prefix `a` and
        // dropping `,b`; either we accept the whole thing or we
        // skip the whole slot.
        assert!(p.is_empty(), "got: {p:?}");
    }

    #[test]
    fn parse_parameters_token_value_with_dot_underscore_dash_accepted() {
        // §5.6.2 tchar includes `.` `_` `-` — values like `text/plain`
        // identifiers, MIME subtype tails, and protocol versions
        // (`http/1.1` would tokenise as `http/1.1` if `/` were a tchar,
        // which it isn't; but `1.1`, `my_thing`, `app-name` all do).
        let p = parse_parameters("; v=1.1; tag=my_thing; ua=app-name");
        assert_eq!(
            p,
            vec![
                ("v".to_owned(), "1.1".to_owned()),
                ("tag".to_owned(), "my_thing".to_owned()),
                ("ua".to_owned(), "app-name".to_owned()),
            ],
        );
    }

    #[test]
    fn parse_parameters_coupling_with_unquote_string_layering() {
        // Coupling test: pin the §5.6.6 → §5.6.4 layering. A value
        // that round-trips through `unquote_string` directly MUST
        // match the same value pulled out of `parse_parameters`. This
        // catches a future change that fork-decodes the quoted-string
        // inside `parse_parameters` rather than delegating.
        let direct = unquote_string("\"--my\\\"boundary--\"").unwrap();
        let via_params = parse_parameters("; boundary=\"--my\\\"boundary--\"")
            .into_iter()
            .next()
            .unwrap()
            .1;
        assert_eq!(&*direct, via_params);
    }

    #[test]
    fn local_server_head_503_with_malformed_retry_after_surfaces_diagnostic() {
        // §10.2.3 grammar is strict — "soon" matches neither
        // delay-seconds nor any HTTP-date form. The hint must surface
        // the raw value + the §10.2.3 cite so the caller can see the
        // origin's bug rather than silently dropping the field.
        const HEAD: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
            Content-Length: 0\r\n\
            Retry-After: soon\r\n\
            Connection: close\r\n\
            \r\n";
        let uri = spawn_head_only(HEAD);
        let err = match HttpSource::open(&uri) {
            Ok(_) => panic!("503 must error"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("\"soon\"") && msg.contains("unparseable"),
            "malformed Retry-After must surface raw + diagnostic: {msg}"
        );
        assert!(msg.contains("§10.2.3"), "missing §10.2.3 cite: {msg}");
    }
}
