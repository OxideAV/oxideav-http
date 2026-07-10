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
//! By default the driver uses a process-wide agent. To tighten policy
//! (redirect following/cap/scheme/host restrictions, custom
//! `User-Agent`, timeouts, https-only mode) build an [`HttpConfig`]
//! and either:
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
//! ## Driver-owned redirects (RFC 9110 §15.4 / §10.2.2, RFC 3986 §5)
//!
//! The driver follows 3xx redirects itself — the transport layer
//! hands every 3xx back unfollowed. `Location` is parsed as a
//! URI-reference and resolved against the current target URI with the
//! RFC 3986 §5 machinery in [`uri`]. Permanent hops (301/308) rewrite
//! the URI future range GETs target; temporary hops (302/307) are
//! re-walked per request; a 303 at open rebases the anchor to its
//! target (§15.4.4: the original resource has no transferable
//! representation), while a 303 during a range-anchored GET is fatal.
//! Policy knobs: [`HttpConfigBuilder::follow_redirects`],
//! [`HttpConfigBuilder::max_redirects`] (+ `max_redirects_will_error`),
//! [`HttpConfigBuilder::redirect_scheme_policy`], and
//! [`HttpConfigBuilder::redirect_same_host_only`]. Cyclical
//! redirections are detected over §4.2.3-normalized URIs, and hostile
//! `Location` values (userinfo per §4.2.4, empty host, out-of-grammar
//! bytes, non-http(s) schemes, multiple field lines) are refused with
//! precise cites. `Range` / `If-Range` ride along on every hop, so
//! the §13.1.5 validator guards whichever origin finally answers.
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
//!
//! ## Transparent resume after transport drops (RFC 9110 §14.2)
//!
//! §14.2 motivates byte ranges with "efficient recovery from partially
//! failed transfers": when a response body is truncated or the
//! connection drops mid-stream, the driver re-requests
//! `Range: bytes=<current-pos>-` and splices the remainder — up to
//! [`HttpConfigBuilder::read_retries`] times per `read` call (default
//! 2, `0` disables). The resume GET carries `If-Range` whenever a
//! strong validator exists, so a representation that mutated between
//! the drop and the resume is refused (§13.1.5), never spliced.
//!
//! ## Seek-via-Range
//!
//! `Seek` maps onto fresh `Range: bytes=<target>-` GETs, with one
//! economy: a forward hop of at most
//! [`HttpConfigBuilder::seek_drain_max`] bytes (default 64 KiB) that
//! stays inside the live body's declared span is satisfied by
//! draining the open connection instead of a new request — demuxers
//! skip small box/frame payloads constantly, and a request round trip
//! per few-byte hop is the exact waste RFC 9110 §14.2's efficiency
//! rationale warns against, in the other direction.
//!
//! ## HEAD-hostile servers (opt-in `range_probe`)
//!
//! Some origins answer HEAD with 405/501, omit Content-Length on HEAD
//! (explicitly permitted by RFC 9110 §9.3.2), or never advertise
//! `Accept-Ranges` (§14.3 keeps the header advisory and lets clients
//! probe anyway). With [`HttpConfigBuilder::range_probe`] enabled the
//! driver falls back to a `Range: bytes=0-` GET: a 206 proves range
//! support, its Content-Range supplies the complete-length (§14.4),
//! and its body becomes the initial read stream — a successful probe
//! costs no extra request. A 200 (server ignored `Range`, §14.2 MAY)
//! is refused; a 416 with `bytes */0` yields an empty source (§14.1.2
//! makes `bytes=0-` unsatisfiable against a zero-length
//! representation, so that 416 is range support working correctly).

pub mod uri;

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
/// Retained on the config surface for compatibility. The driver never
/// generates an `Authorization` header itself, and its redirect walk
/// re-sends only the headers it generated for the original request
/// (`Range`, `If-Range`, `Accept-Encoding`) — credentials are never
/// carried onto a redirect target, matching the strictest reading of
/// RFC 9110 §15.4's header-modification guidance, which lists
/// `Authorization` among the resource-specific fields to remove. Both
/// variants therefore currently behave as [`RedirectAuthPolicy::Never`].
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

/// Constraint on how a redirect target's scheme may differ from the
/// scheme of the request that received the 3xx (per hop).
///
/// Independent of [`HttpConfigBuilder::https_only`], which refuses
/// every non-`https` request outright, including the first one.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum RedirectSchemePolicy {
    /// `http` ↔ `https` hops are allowed in both directions (default —
    /// matches the historical transparent-following behaviour).
    #[default]
    Any,
    /// The scheme may stay the same or upgrade `http` → `https`; a
    /// `https` → `http` downgrade hop is refused.
    UpgradeOnly,
    /// The scheme must not change across any hop.
    Same,
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
    follow_redirects: bool,
    max_redirects: u32,
    max_redirects_will_error: bool,
    redirect_auth_policy: RedirectAuthPolicy,
    redirect_scheme_policy: RedirectSchemePolicy,
    redirect_same_host_only: bool,
    user_agent: Option<String>,
    https_only: bool,
    timeout_global: Option<Duration>,
    timeout_connect: Option<Duration>,
    read_retries: u32,
    seek_drain_max: u64,
    range_probe: bool,
}

impl Default for HttpConfig {
    fn default() -> Self {
        // Redirect defaults preserve the historical observable
        // behaviour: automatic following, a 10-hop cap that errors
        // when exceeded, no cross-scheme / cross-host restriction.
        Self {
            follow_redirects: true,
            max_redirects: 10,
            max_redirects_will_error: true,
            redirect_auth_policy: RedirectAuthPolicy::Never,
            redirect_scheme_policy: RedirectSchemePolicy::Any,
            redirect_same_host_only: false,
            user_agent: None,
            https_only: false,
            timeout_global: None,
            timeout_connect: None,
            read_retries: 2,
            seek_drain_max: 64 * 1024,
            range_probe: false,
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

    /// Whether the driver follows 3xx redirects at all (RFC 9110
    /// §15.4: a user agent "MAY automatically redirect"). When
    /// `false`, the first 3xx answer is treated as the final response
    /// — `open` then fails with its status. Default `true`.
    pub fn follow_redirects(&self) -> bool {
        self.follow_redirects
    }

    /// Maximum number of redirect hops the driver will follow on one
    /// request before giving up. Loop detection (RFC 9110 §15.4: "A
    /// client SHOULD detect and intervene in cyclical redirections")
    /// is separate and fires regardless of this cap.
    pub fn max_redirects(&self) -> u32 {
        self.max_redirects
    }

    /// Whether exceeding [`Self::max_redirects`] surfaces as an error
    /// (`true`) or hands back the final 3xx response (`false`) — the
    /// caller then sees that response's status as the outcome.
    pub fn max_redirects_will_error(&self) -> bool {
        self.max_redirects_will_error
    }

    /// Redirect handling for the `Authorization` header. See
    /// [`RedirectAuthPolicy`] — the driver generates no
    /// `Authorization` header and never carries one across a hop, so
    /// both variants currently behave as
    /// [`RedirectAuthPolicy::Never`].
    pub fn redirect_auth_policy(&self) -> RedirectAuthPolicy {
        self.redirect_auth_policy
    }

    /// Per-hop constraint on redirect scheme changes. Default
    /// [`RedirectSchemePolicy::Any`].
    pub fn redirect_scheme_policy(&self) -> RedirectSchemePolicy {
        self.redirect_scheme_policy
    }

    /// When `true`, a redirect target whose host differs from the
    /// redirecting request's host (case-insensitive, per RFC 3986
    /// §6.2.2.1) is refused. Ports may still differ — scheme changes
    /// are governed by [`Self::redirect_scheme_policy`]. Default
    /// `false`.
    pub fn redirect_same_host_only(&self) -> bool {
        self.redirect_same_host_only
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

    /// Maximum number of transparent range re-requests a single `read`
    /// call may issue after a mid-body transport drop or truncation
    /// (RFC 9110 §14.2: byte ranges "support efficient recovery from
    /// partially failed transfers"). Default 2. `0` disables resume:
    /// the first truncation surfaces as an error.
    pub fn read_retries(&self) -> u32 {
        self.read_retries
    }

    /// Longest forward seek (in bytes) the driver will satisfy by
    /// draining the live response body instead of dropping the
    /// connection and issuing a fresh range GET. Small forward hops
    /// (a demuxer skipping a box or frame payload) are far cheaper as
    /// a bounded drain than as a request round trip. Default 64 KiB;
    /// `0` restores the historical always-reissue behaviour. The
    /// stream position after either strategy is identical — only the
    /// request count differs.
    pub fn seek_drain_max(&self) -> u64 {
        self.seek_drain_max
    }

    /// Whether `open` may fall back to probing range support with a
    /// `Range: bytes=0-` GET when the HEAD hand-shake is inconclusive:
    /// HEAD answered 405 / 501 (RFC 9110 §15.5.6 / §15.6.2), HEAD
    /// omitted Content-Length (§9.3.2 explicitly permits omitting
    /// fields "determined only while generating the content"), or the
    /// response carried no Accept-Ranges field (§14.3: "A client MAY
    /// generate range requests regardless of having received an
    /// Accept-Ranges field"). The probe's 206 must self-describe the
    /// resource (Content-Range complete-length) and its body is used
    /// as the initial read stream, so a successful probe costs no
    /// extra request. Default `false` — such servers are refused at
    /// open, as before.
    pub fn range_probe(&self) -> bool {
        self.range_probe
    }
}

/// Builder for [`HttpConfig`].
#[derive(Debug, Clone)]
pub struct HttpConfigBuilder {
    inner: HttpConfig,
}

impl HttpConfigBuilder {
    /// Enable or disable automatic redirect following (RFC 9110 §15.4
    /// MAY). Default `true`; with `false` the first 3xx is the final
    /// answer and `open` fails with its status.
    pub fn follow_redirects(mut self, v: bool) -> Self {
        self.inner.follow_redirects = v;
        self
    }

    /// Cap the redirect chain. Default 10.
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
    /// is [`RedirectAuthPolicy::Never`] — see [`RedirectAuthPolicy`]
    /// for why both variants currently behave identically.
    pub fn redirect_auth_policy(mut self, p: RedirectAuthPolicy) -> Self {
        self.inner.redirect_auth_policy = p;
        self
    }

    /// Constrain per-hop scheme changes across redirects. Default
    /// [`RedirectSchemePolicy::Any`].
    pub fn redirect_scheme_policy(mut self, p: RedirectSchemePolicy) -> Self {
        self.inner.redirect_scheme_policy = p;
        self
    }

    /// When `true`, refuse redirect hops that change the host.
    /// Default `false`.
    pub fn redirect_same_host_only(mut self, v: bool) -> Self {
        self.inner.redirect_same_host_only = v;
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

    /// Cap the transparent mid-body resume re-requests per `read` call
    /// (RFC 9110 §14.2 partial-transfer recovery). Default 2; `0`
    /// surfaces the first transport truncation as an error instead of
    /// re-requesting the remainder.
    pub fn read_retries(mut self, n: u32) -> Self {
        self.inner.read_retries = n;
        self
    }

    /// Cap the forward-seek drain distance — see
    /// [`HttpConfig::seek_drain_max`]. Default 64 KiB; `0` makes every
    /// seek re-issue a range GET.
    pub fn seek_drain_max(mut self, n: u64) -> Self {
        self.inner.seek_drain_max = n;
        self
    }

    /// Allow `open` to probe range support with a `Range: bytes=0-`
    /// GET when HEAD is inconclusive — see
    /// [`HttpConfig::range_probe`]. Default `false`.
    pub fn range_probe(mut self, v: bool) -> Self {
        self.inner.range_probe = v;
        self
    }

    /// Finalise the policy.
    pub fn build(self) -> HttpConfig {
        self.inner
    }
}

fn agent_from(cfg: &HttpConfig) -> Agent {
    let mut b = Agent::config_builder()
        // The driver owns redirect semantics (RFC 9110 §15.4 /
        // §10.2.2 / RFC 3986 §5): the transport layer must hand every
        // 3xx back unfollowed and unerrored so the hop walk above it
        // can resolve the Location reference, classify the status,
        // and apply the configured policy. `cfg.max_redirects` /
        // `cfg.follow_redirects` etc. are enforced by that walk, not
        // here.
        .max_redirects(0)
        .max_redirects_will_error(false)
        .https_only(cfg.https_only)
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
// Driver-owned redirect walk (RFC 9110 §15.4 / §10.2.2, RFC 3986 §5)
// ---------------------------------------------------------------------------

type WireResponse = ureq::http::Response<ureq::Body>;

/// The two request methods this driver ever issues. Both are safe
/// retrieval methods (RFC 9110 §9.2.1 / §9.3.1–§9.3.2), which makes
/// the §15.4 method-rewrite rules vacuous for us: 307/308 MUST NOT
/// change the method, 301/302's historical POST→GET latitude does not
/// apply to GET/HEAD, and 303's "retrieval request targeting that URI
/// (a GET or HEAD request if using HTTP)" (§15.4.4) is exactly what we
/// were already sending — so every hop re-sends the original method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestMethod {
    Head,
    Get,
}

fn send_once(
    agent: &Agent,
    method: RequestMethod,
    uri: &str,
    headers: &[(&str, &str)],
) -> std::result::Result<WireResponse, ureq::Error> {
    let mut req = match method {
        RequestMethod::Head => agent.head(uri),
        RequestMethod::Get => agent.get(uri),
    };
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    req.call()
}

/// RFC 9110 §15.4's split of the followable 3xx classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HopKind {
    /// 301 / 308: "the target resource has been assigned a new
    /// permanent URI and any future references to this resource ought
    /// to use one of the enclosed URIs" (§15.4.2 / §15.4.9).
    Permanent,
    /// 302 / 307: "the client ought to continue to use the target URI
    /// for future requests" (§15.4.3 / §15.4.8) — and 303, whose
    /// Location target "is not considered equivalent to the target
    /// URI" (§15.4.4), so it must never rewrite what we ask for next
    /// time either.
    Temporary,
}

/// Classify a status as an automatically followable redirect. 300
/// (Multiple Choices) is reactive negotiation — following its optional
/// Location is a MAY (§15.4.1) this driver declines, since picking a
/// representation variant blind defeats the byte-exactness the source
/// contract needs. 304 is a cache signal (§15.4.5) that a request
/// without conditional headers must never receive. 305/306 are
/// deprecated/reserved (§15.4.6 / §15.4.7).
fn redirect_class(status: u16) -> Option<HopKind> {
    match status {
        301 | 308 => Some(HopKind::Permanent),
        302 | 303 | 307 => Some(HopKind::Temporary),
        _ => None,
    }
}

/// Checks applied to the caller's own request URI before the first
/// request. Userinfo is tolerated here (the URI comes from the
/// caller, not from the network; RFC 9110 §4.2.4's SHOULD-error is
/// scoped to references "received from an untrusted source").
fn initial_uri_check(knobs: &HttpConfig, u: &uri::UriRef) -> std::result::Result<(), String> {
    let scheme = u.scheme().unwrap_or("");
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(format!(
            "unsupported URI scheme {scheme:?} — this driver speaks http/https only"
        ));
    }
    let (_, host, _) = u.authority_parts().map_err(|e| e.to_string())?;
    if host.unwrap_or("").is_empty() {
        return Err(
            "http(s) URI with an empty host identifier — a recipient MUST reject it as \
             invalid (RFC 9110 §4.2.1 / §4.2.2)"
                .to_owned(),
        );
    }
    if knobs.https_only() && scheme.eq_ignore_ascii_case("http") {
        return Err("plain-http request refused by https_only policy".to_owned());
    }
    Ok(())
}

/// Policy gate for one redirect hop `from` → `to`. Returns the refusal
/// reason, if any. `to` must already be fully resolved (absolute).
fn hop_policy_check(
    knobs: &HttpConfig,
    from: &uri::UriRef,
    to: &uri::UriRef,
) -> std::result::Result<(), String> {
    let to_scheme = to.scheme().unwrap_or("").to_ascii_lowercase();
    if to_scheme != "http" && to_scheme != "https" {
        return Err(format!(
            "redirect target {to} has scheme {to_scheme:?} — this driver speaks http/https only"
        ));
    }
    let (userinfo, host, _) = to.authority_parts().map_err(|e| e.to_string())?;
    if host.unwrap_or("").is_empty() {
        return Err(format!(
            "redirect target {to} has an empty host identifier — a recipient MUST reject it \
             as invalid (RFC 9110 §4.2.1 / §4.2.2)"
        ));
    }
    if userinfo.is_some() {
        // §4.2.4: "Before making use of an 'http' or 'https' URI
        // reference received from an untrusted source, a recipient
        // SHOULD parse for userinfo and treat its presence as an
        // error; it is likely being used to obscure the authority for
        // the sake of phishing attacks."
        return Err(format!(
            "redirect target carries a userinfo subcomponent — treated as an error per \
             RFC 9110 §4.2.4 (likely authority obfuscation); target host would be {:?}",
            host.unwrap_or("")
        ));
    }
    if knobs.https_only() && to_scheme == "http" {
        return Err(format!(
            "redirect target {to} is plain http, refused by https_only policy"
        ));
    }
    let from_scheme = from.scheme().unwrap_or("").to_ascii_lowercase();
    match knobs.redirect_scheme_policy() {
        RedirectSchemePolicy::Any => {}
        RedirectSchemePolicy::Same => {
            if from_scheme != to_scheme {
                return Err(format!(
                    "redirect hop changes scheme {from_scheme:?} → {to_scheme:?}, refused by \
                     RedirectSchemePolicy::Same"
                ));
            }
        }
        RedirectSchemePolicy::UpgradeOnly => {
            if from_scheme != to_scheme && !(from_scheme == "http" && to_scheme == "https") {
                return Err(format!(
                    "redirect hop changes scheme {from_scheme:?} → {to_scheme:?}, refused by \
                     RedirectSchemePolicy::UpgradeOnly (only http → https may cross)"
                ));
            }
        }
    }
    if knobs.redirect_same_host_only() {
        let from_host = match from.authority_parts() {
            Ok((_, h, _)) => h.unwrap_or("").to_ascii_lowercase(),
            Err(_) => String::new(),
        };
        let to_host = host.unwrap_or("").to_ascii_lowercase();
        if from_host != to_host {
            return Err(format!(
                "redirect hop changes host {from_host:?} → {to_host:?}, refused by \
                 redirect_same_host_only policy"
            ));
        }
    }
    Ok(())
}

/// The result of a redirect-following request walk.
struct RedirectedResponse {
    /// The first non-followed response (usually a non-3xx; a 3xx when
    /// following is disabled, the cap was reached with
    /// `max_redirects_will_error(false)`, or the 3xx carried no
    /// Location).
    resp: WireResponse,
    /// URI whose request produced `resp` — the end of the hop walk.
    final_uri: String,
    /// URI that future requests for this resource should target: the
    /// original request URI rewritten through the longest *permanent*
    /// (301/308) prefix of the chain. The first temporary hop freezes
    /// it — §15.4.3/§15.4.8 say to keep using the URI that answered
    /// with the temporary redirect, and a 303 target is not the
    /// resource at all (§15.4.4).
    next_request_uri: String,
}

/// Issue `method` on `request_uri`, following 3xx redirects per the
/// configured policy: Location parsed as a URI-reference and resolved
/// against the current target URI (RFC 9110 §10.2.2 / RFC 3986 §5),
/// hop cap, cyclical-redirection detection over RFC 9110
/// §4.2.3-normalized URIs (§15.4 SHOULD), scheme/host policy, and
/// userinfo rejection (§4.2.4).
///
/// `range_anchored` marks requests whose byte offsets and `If-Range`
/// validator are anchored to an already-opened representation; a 303
/// hop is fatal for those, because its target "is not considered
/// equivalent to the target URI" (§15.4.4) and re-anchoring
/// mid-stream against a different resource is exactly the
/// misalignment the §13.1.5 machinery exists to prevent.
///
/// `label` prefixes every error message (e.g. `"HTTP HEAD http://…"`).
fn call_with_redirects(
    agent: &Agent,
    method: RequestMethod,
    request_uri: &str,
    headers: &[(&str, &str)],
    knobs: &HttpConfig,
    range_anchored: bool,
    label: &str,
) -> io::Result<RedirectedResponse> {
    let parsed = uri::UriRef::parse_lenient(request_uri)
        .map_err(|e| io::Error::other(format!("{label}: invalid request URI: {e}")))?;
    // Fragments are never part of a request target (RFC 9110 §4.2.5;
    // RFC 3986 §5.1 also strips them from any base URI).
    let mut current = parsed.without_fragment();
    initial_uri_check(knobs, &current).map_err(|m| io::Error::other(format!("{label}: {m}")))?;
    let mut sticky = current.to_string();
    let mut sticky_frozen = false;
    let mut visited: Vec<String> = vec![current.normalized()];
    let mut hops: u32 = 0;
    loop {
        let uri_str = current.to_string();
        let resp = send_once(agent, method, &uri_str, headers).map_err(|e| {
            if hops == 0 {
                io::Error::other(format!("{label}: {e}"))
            } else {
                io::Error::other(format!("{label}: redirect hop {hops} ({uri_str}): {e}"))
            }
        })?;
        let status = resp.status().as_u16();
        let done = |resp: WireResponse| RedirectedResponse {
            resp,
            final_uri: uri_str.clone(),
            next_request_uri: sticky.clone(),
        };
        let Some(kind) = redirect_class(status) else {
            return Ok(done(resp));
        };
        if !knobs.follow_redirects() {
            // Following disabled: the 3xx is the final answer.
            return Ok(done(resp));
        }
        // Location = URI-reference, a single field value (§10.2.2).
        // The comma is a valid data character inside a URI-reference,
        // so a list is not expressible; multiple field lines are the
        // invalid-message case §10.2.2 warns about ("recovery ... is
        // difficult and not interoperable") — refuse rather than
        // guess.
        let location: Option<std::result::Result<String, ()>> = {
            let mut it = resp.headers().get_all("location").iter();
            match (it.next(), it.next()) {
                (None, _) => None,
                (Some(v), None) => Some(v.to_str().map(str::to_owned).map_err(|_| ())),
                (Some(_), Some(_)) => Some(Err(())),
            }
        };
        let loc_value = match location {
            // §15.4: "If a Location header field is provided, the
            // user agent MAY automatically redirect" — without one
            // there is nothing to follow; the 3xx is final.
            None => return Ok(done(resp)),
            Some(Err(())) => {
                return Err(io::Error::other(format!(
                    "{label}: status {status} with multiple (or non-ASCII) Location field \
                     lines — a Location value cannot be a list (RFC 9110 §10.2.2)"
                )));
            }
            Some(Ok(v)) => v,
        };
        if hops >= knobs.max_redirects() {
            if knobs.max_redirects_will_error() {
                return Err(io::Error::other(format!(
                    "{label}: redirect chain exceeded max_redirects={} (status {status} at \
                     {uri_str}, Location: {loc_value})",
                    knobs.max_redirects()
                )));
            }
            // Hand the last 3xx back; its status becomes the outcome.
            return Ok(done(resp));
        }
        if range_anchored && status == 303 {
            return Err(io::Error::other(format!(
                "{label}: 303 See Other during a range-anchored request — the Location target \
                 \"is not considered equivalent to the target URI\" (RFC 9110 §15.4.4), so the \
                 byte offsets and If-Range validator of the open representation cannot be \
                 re-anchored against it"
            )));
        }
        // Strict parse: Location arrives from the network. §10.2.2
        // allows recovery from invalid references but does not mandate
        // it; this driver refuses them.
        let reference = uri::UriRef::parse(&loc_value).map_err(|e| {
            io::Error::other(format!(
                "{label}: status {status} with invalid Location {loc_value:?}: {e}"
            ))
        })?;
        // §10.2.2: relative references resolve against the target URI
        // of the request that got the 3xx (RFC 3986 §5). A fragment
        // (the target's own, or inherited from the request URI per
        // §10.2.2 — a no-op here, `current` was fragment-stripped) is
        // never sent in a request, so drop it for the next hop.
        let target = current
            .resolve(&reference)
            .map_err(|e| {
                io::Error::other(format!(
                    "{label}: cannot resolve Location {loc_value:?} against {uri_str}: {e}"
                ))
            })?
            .without_fragment();
        hop_policy_check(knobs, &current, &target)
            .map_err(|m| io::Error::other(format!("{label}: {m}")))?;
        let key = target.normalized();
        if visited.contains(&key) {
            return Err(io::Error::other(format!(
                "{label}: cyclical redirection — {key} already visited in this chain of {} \
                 (RFC 9110 §15.4: a client SHOULD detect and intervene; §4.2.3: URIs \
                 equivalent after normalization identify the same resource)",
                visited.len()
            )));
        }
        visited.push(key);
        if status == 303 {
            // §15.4.4: the Location target is a *different* resource —
            // and the only one with a transferable representation ("a
            // 303 response to a GET request indicates that the origin
            // server does not have a representation of the target
            // resource that can be transferred"). Future requests for
            // the bytes this walk ends up reading therefore anchor at
            // the 303 target: re-asking the original URI for byte
            // ranges would ask a resource the origin said it cannot
            // transfer. The rebase also unfreezes the rewrite — hops
            // before the 303 concerned a different resource's
            // whereabouts.
            sticky = target.to_string();
            sticky_frozen = false;
        } else if !sticky_frozen {
            match kind {
                // §15.4.2 / §15.4.9: "any future references to this
                // resource ought to use one of the enclosed URIs" —
                // chainable only while every link so far is permanent.
                HopKind::Permanent => sticky = target.to_string(),
                // §15.4.3 / §15.4.8: "the client ought to continue to
                // use the target URI for future requests" — freeze the
                // rewrite at this point.
                HopKind::Temporary => sticky_frozen = true,
            }
        }
        hops += 1;
        current = target;
    }
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
    /// Request URI for range GETs: the open URI rewritten through the
    /// longest permanent (301/308) redirect prefix observed on the
    /// most recent request chain (RFC 9110 §15.4.2 / §15.4.9 — "any
    /// future references to this resource ought to use one of the
    /// enclosed URIs"). Temporary hops (302/303/307) never rewrite it
    /// and are re-walked on every request (§15.4.3 / §15.4.8).
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
    /// Bytes the active `body` still promises to deliver. For a 206
    /// this is derived from the Content-Range span (RFC 9110 §15.3.7:
    /// "A client MUST inspect a 206 response's Content-Type and
    /// Content-Range field(s) to determine what parts are enclosed and
    /// whether additional requests are needed"); for a 200 fallback
    /// (RFC 7233 §3.1) it is the remainder of the representation after
    /// the prefix drain. Meaningful only while `body` is `Some`.
    body_remaining: u64,
    /// Resolved driver policy for this source: the mid-body resume
    /// budget ([`HttpConfig::read_retries`]), the forward-seek drain
    /// cap ([`HttpConfig::seek_drain_max`]), and the redirect policy
    /// every per-request hop walk enforces
    /// ([`HttpConfig::follow_redirects`] and friends).
    knobs: HttpConfig,
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
        Self::open_impl(uri, Some(cfg))
    }

    fn open_impl(uri: &str, cfg: Option<&HttpConfig>) -> Result<Self> {
        let scoped: Option<Agent> = cfg.map(agent_from);
        // Driver-behaviour knobs (as opposed to agent-construction
        // knobs) are resolved per open: a scoped config wins, else the
        // installed process-wide default, else the library defaults.
        let knobs: HttpConfig = cfg
            .cloned()
            .or_else(|| DEFAULT_CONFIG.get().cloned())
            .unwrap_or_default();
        let head_agent: &Agent = scoped.as_ref().unwrap_or_else(|| agent());
        // RFC 9110 §12.5.3 rule 1: "If no Accept-Encoding header field
        // is in the request, any content coding is considered
        // acceptable by the user agent." The driver's whole byte-offset
        // model (Content-Length recorded here, Content-Range echoes,
        // the §3.1 prefix drain) assumes the wire bytes ARE the
        // representation bytes a demuxer consumes, so any content
        // coding is in fact unacceptable. `Accept-Encoding: identity`
        // lists only the §12.5.3 "no encoding" synonym, making every
        // real coding fall under rule 3's "not listed" and steering a
        // conformant server to "send a response without any content
        // coding".
        let head_walk = call_with_redirects(
            head_agent,
            RequestMethod::Head,
            uri,
            &[("Accept-Encoding", "identity")],
            &knobs,
            false,
            &format!("HTTP HEAD {uri}"),
        )
        .map_err(|e| Error::other(e.to_string()))?;
        // Driver-owned redirect semantics: subsequent range GETs
        // target the open URI rewritten through the chain's permanent
        // (301/308) prefix; temporary hops (302/303/307) are re-walked
        // per request, per RFC 9110 §15.4.2/.9 vs §15.4.3/.8.
        let request_uri = head_walk.next_request_uri;
        let head = head_walk.resp;

        let status = head.status();
        if !status.is_success() {
            // 405 (§15.5.6: "the method received ... is known by the
            // origin server but not supported by the target resource")
            // and 501 (§15.6.2: server "does not recognize the request
            // method") say nothing about the resource's range support —
            // only that HEAD specifically is off the table. When the
            // caller opted in, learn the metadata from a ranged GET
            // instead.
            if knobs.range_probe() && (status == 405 || status == 501) {
                return Self::probe_open(
                    &request_uri,
                    scoped,
                    &knobs,
                    None,
                    &format!("after HEAD status {status}"),
                );
            }
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
            let retry_msg = retry_after_hint_of(head.headers());
            return Err(Error::other(format!(
                "HTTP HEAD {uri}: status {status}{retry_msg}"
            )));
        }
        let headers = head.headers();
        // RFC 9110 §8.4: "the representation is defined in terms of the
        // coded form, and all other metadata about the representation
        // is about the coded form unless otherwise noted". So if a
        // content coding is in effect, the Content-Length we are about
        // to record — and every byte-range offset we will later request
        // against it — describes the CODED bytes, not the media bytes a
        // demuxer expects. The driver decodes no content codings, so a
        // coded representation is unusable: refuse at open with the
        // coding names rather than hand a demuxer compressed bytes (or
        // a coded-length total) it would misparse downstream. The check
        // walks every Content-Encoding field line (the §8.4 `#` list
        // form may be split across lines per §5.6.1) and tolerates only
        // the redundant `identity` token. Obs-fold is normalised before
        // interpretation per RFC 7230 §3.2.4.
        let head_codings = non_identity_codings_in(headers);
        if !head_codings.is_empty() {
            return Err(Error::Unsupported(format!(
                "HTTP HEAD {uri}: representation carries Content-Encoding {head_codings:?} \
                 despite 'Accept-Encoding: identity' (RFC 9110 §12.5.3); per §8.4 the \
                 Content-Length and byte ranges then describe the coded form, which the \
                 driver does not decode"
            )));
        }
        let head_len = headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());
        let total_len = match head_len {
            Some(n) => n,
            // §9.3.2: "a server MAY omit header fields for which a
            // value is determined only while generating the content",
            // and its worked example names Content-Length as exactly
            // such a field on HEAD. The GET's own metadata is the
            // authoritative fallback when the caller opted in.
            None if knobs.range_probe() => {
                return Self::probe_open(
                    &request_uri,
                    scoped,
                    &knobs,
                    None,
                    "HEAD omitted Content-Length",
                );
            }
            None => {
                return Err(Error::Unsupported(format!(
                    "HTTP HEAD {uri}: missing Content-Length"
                )));
            }
        };
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
                // field." The header is advisory, not mandatory, even
                // for range-capable servers — with the probe opt-in we
                // exercise that MAY and let an actual 206 (validated
                // against the HEAD-observed length) prove support.
                if knobs.range_probe() {
                    return Self::probe_open(
                        &request_uri,
                        scoped,
                        &knobs,
                        Some(total_len),
                        "Accept-Ranges absent",
                    );
                }
                // Without the opt-in, preserve the historical refusal:
                // the driver's correctness model (validate the
                // Content-Range echo etc.) needs the server to
                // actually satisfy range requests, and a HEAD that
                // omits the hint is also far more likely to refuse.
                return Err(Error::Unsupported(format!(
                    "HTTP HEAD {uri}: server did not advertise Accept-Ranges (RFC 9110 §14.3)"
                )));
            }
        }
        let validator = validator_with_vary_check(&format!("HTTP HEAD {uri}"), headers)?;
        Ok(Self {
            uri: request_uri,
            total_len,
            pos: 0,
            agent: scoped,
            validator,
            body: None,
            body_remaining: 0,
            knobs,
        })
    }

    /// Learn the resource's metadata from a `Range: bytes=0-` GET
    /// probe instead of a HEAD — the opt-in fallback behind
    /// [`HttpConfig::range_probe`] for servers whose HEAD hand-shake
    /// is inconclusive (405/501, missing Content-Length, or no
    /// Accept-Ranges advertisement; RFC 9110 §15.5.6 / §15.6.2 /
    /// §9.3.2 / §14.3 respectively).
    ///
    /// A 206 answer proves byte-range support directly; §14.4 makes
    /// its Content-Range carry the complete-length, which replaces the
    /// HEAD-provided total (`head_total`, when known from a HEAD that
    /// succeeded but omitted Accept-Ranges, cross-checks it). The
    /// probe body becomes the initial read stream, so a successful
    /// probe costs no extra request. A 200 answer means the server
    /// exercised §14.2's "A server MAY ignore the Range header field"
    /// — useless for a seekable source, refused. A 416 with
    /// `bytes */0` is the CORRECT answer for an empty resource
    /// (§14.1.2: "When a selected representation has zero length, the
    /// only satisfiable form of range-spec in a GET request is a
    /// suffix-range with a non-zero suffix-length") and yields an
    /// empty source.
    fn probe_open(
        uri: &str,
        scoped: Option<Agent>,
        knobs: &HttpConfig,
        head_total: Option<u64>,
        why: &str,
    ) -> Result<Self> {
        let probe_agent: &Agent = scoped.as_ref().unwrap_or_else(|| agent());
        // The probe walks redirects like the HEAD it replaces. It is
        // not range-anchored: nothing has been read yet, so even a 303
        // hop (a *different* resource that answers indirectly,
        // RFC 9110 §15.4.4) is safe to follow — whatever the chain
        // ends at IS the representation this source will expose.
        let probe_walk = call_with_redirects(
            probe_agent,
            RequestMethod::Get,
            uri,
            &[("Range", "bytes=0-"), ("Accept-Encoding", "identity")],
            knobs,
            false,
            &format!("HTTP GET probe {uri} ({why})"),
        )
        .map_err(|e| Error::other(e.to_string()))?;
        let request_uri = probe_walk.next_request_uri;
        let resp = probe_walk.resp;
        let status = resp.status();
        if status == 416 {
            let cr_raw = resp
                .headers()
                .get("content-range")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let Some(cr) = cr_raw.as_deref() else {
                return Err(Error::other(format!(
                    "HTTP GET probe {uri} ({why}): 416 without Content-Range (RFC 9110 §14.4 \
                     SHOULD) — cannot distinguish an empty resource from a range refusal"
                )));
            };
            return match parse_byte_unsatisfied_range(cr) {
                // Zero-length representation: `bytes=0-` is
                // unsatisfiable by §14.1.2, so this 416 is range
                // support working correctly. No GET will ever be
                // issued (pos >= total holds from the start), so no
                // validator is needed.
                Ok(0) => Ok(Self {
                    uri: request_uri,
                    total_len: 0,
                    pos: 0,
                    agent: scoped,
                    validator: None,
                    body: None,
                    body_remaining: 0,
                    knobs: knobs.clone(),
                }),
                Ok(c) => Err(Error::other(format!(
                    "HTTP GET probe {uri} ({why}): 416 for 'bytes=0-' yet complete-length {c} \
                     — first-pos 0 is satisfiable against any non-empty representation \
                     (RFC 9110 §14.1.2)"
                ))),
                Err(e) => Err(Error::other(format!(
                    "HTTP GET probe {uri} ({why}): 416 with invalid Content-Range '{cr}': {e}"
                ))),
            };
        }
        if status == 200 {
            return Err(Error::Unsupported(format!(
                "HTTP GET probe {uri} ({why}): server ignored 'Range: bytes=0-' and answered \
                 200 (RFC 9110 §14.2: 'A server MAY ignore the Range header field') — a \
                 seekable byte source requires 206 range satisfaction"
            )));
        }
        if status != 206 {
            let retry_msg = retry_after_hint_of(resp.headers());
            return Err(Error::other(format!(
                "HTTP GET probe {uri} ({why}): status {status}{retry_msg}"
            )));
        }
        let headers = resp.headers();
        // Same representation-integrity gauntlet as the HEAD path +
        // the ranged-GET path: identity coding only (§8.4 / §12.5.3),
        // no multipart to a single-range request (§15.3.7.2 MUST NOT).
        let codings = non_identity_codings_in(headers);
        if !codings.is_empty() {
            return Err(Error::Unsupported(format!(
                "HTTP GET probe {uri} ({why}): representation carries Content-Encoding \
                 {codings:?} despite 'Accept-Encoding: identity' (RFC 9110 §12.5.3); per §8.4 \
                 the byte ranges then describe the coded form, which the driver does not decode"
            )));
        }
        let ct_raw = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if is_multipart_byteranges_content_type(ct_raw) {
            return Err(Error::other(format!(
                "HTTP GET probe {uri} ({why}): multipart/byteranges to a single-range request \
                 (RFC 9110 §15.3.7.2 MUST NOT). Content-Type: {ct_raw:?}"
            )));
        }
        // §15.3.7.1: a single-part 206 MUST carry Content-Range; §14.4
        // gives us the complete-length the HEAD never delivered.
        let cr_raw = headers
            .get("content-range")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .ok_or_else(|| {
                Error::other(format!(
                    "HTTP GET probe {uri} ({why}): 206 missing Content-Range \
                     (RFC 9110 §15.3.7.1 MUST)"
                ))
            })?;
        let parsed = parse_byte_content_range(&cr_raw).map_err(|e| {
            Error::other(format!(
                "HTTP GET probe {uri} ({why}): invalid Content-Range '{cr_raw}': {e}"
            ))
        })?;
        if parsed.first != 0 {
            return Err(Error::other(format!(
                "HTTP GET probe {uri} ({why}): Content-Range first-byte-pos {} != requested 0",
                parsed.first
            )));
        }
        let total_len = match (parsed.complete, head_total) {
            (Some(c), Some(t)) if c != t => {
                return Err(Error::other(format!(
                    "HTTP GET probe {uri} ({why}): Content-Range complete-length {c} != \
                     HEAD-observed Content-Length {t} (RFC 9110 §8.6)"
                )));
            }
            (Some(c), _) => c,
            // The probe server used the §14.4 '*' form but a
            // successful HEAD already measured the resource.
            (None, Some(t)) => t,
            (None, None) => {
                return Err(Error::Unsupported(format!(
                    "HTTP GET probe {uri} ({why}): Content-Range complete-length is '*' and no \
                     HEAD measurement exists — §14.4 permits '*' when the total is unknown, but \
                     a seekable source needs an authoritative length (SeekFrom::End, EOF)"
                )));
            }
        };
        if parsed.last >= total_len {
            return Err(Error::other(format!(
                "HTTP GET probe {uri} ({why}): Content-Range last-byte-pos {} >= total {total_len}",
                parsed.last
            )));
        }
        let span = parsed.last - parsed.first + 1;
        // §8.6: a 206's Content-Length is the byte count of THIS
        // message's content — for the single-part form, the span.
        let cl = headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        if let Some(cl) = cl {
            if cl != span {
                return Err(Error::other(format!(
                    "HTTP GET probe {uri} ({why}): Content-Length {cl} != Content-Range span \
                     {span} (RFC 9110 §8.6)"
                )));
            }
        }
        let validator = validator_with_vary_check(&format!("HTTP GET probe {uri}"), headers)?;
        // The probe response IS the first range response — hand its
        // body to the read path (with span accounting) instead of
        // discarding a perfectly good bytes 0-N transfer.
        let reader: Box<dyn Read + Send> = Box::new(resp.into_body().into_reader());
        Ok(Self {
            uri: request_uri,
            total_len,
            pos: 0,
            agent: scoped,
            validator,
            body: Some(reader),
            body_remaining: span,
            knobs: knobs.clone(),
        })
    }

    pub fn len(&self) -> u64 {
        self.total_len
    }

    pub fn is_empty(&self) -> bool {
        self.total_len == 0
    }

    /// The URI range GETs currently target: the open URI rewritten
    /// through any permanent (301/308) redirect prefix observed on the
    /// most recent request chain (RFC 9110 §15.4.2 / §15.4.9).
    /// Temporary redirects (302/303/307) never rewrite it.
    pub fn request_uri(&self) -> &str {
        &self.uri
    }

    fn agent_ref(&self) -> &Agent {
        self.agent.as_ref().unwrap_or_else(|| agent())
    }

    /// Consume exactly `n` bytes from the live body — the forward-seek
    /// drain path. The caller has already checked `n` against both the
    /// drain cap and the body's remaining declared span. Returns
    /// `true` on success; on a transport fault or early EOF the body
    /// is dropped and `false` is returned, and the caller falls back
    /// to a fresh range GET (whose read path owns §14.2 recovery).
    fn drain_forward(&mut self, mut n: u64) -> bool {
        let Some(body) = self.body.as_mut() else {
            return false;
        };
        let mut buf = [0u8; 8 * 1024];
        while n > 0 {
            let want = n.min(buf.len() as u64) as usize;
            match body.read(&mut buf[..want]) {
                Ok(got) if got > 0 => {
                    n -= got as u64;
                    self.body_remaining -= got as u64;
                }
                _ => {
                    self.body = None;
                    self.body_remaining = 0;
                    return false;
                }
            }
        }
        true
    }

    fn issue_range(&mut self) -> io::Result<()> {
        if self.pos >= self.total_len {
            self.body = None;
            self.body_remaining = 0;
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
        // RFC 9110 §12.5.3: list only `identity` so a conformant server
        // never applies a content coding — the byte offsets in `Range`
        // and the Content-Range echo must keep describing the same
        // bytes the demuxer reads (§8.4: representation metadata is
        // about the coded form). See the HEAD-side comment in
        // `open_impl` for the full rationale.
        let mut hdrs: Vec<(&str, &str)> = vec![("Range", &range), ("Accept-Encoding", "identity")];
        if let Some(v) = if_range.as_deref() {
            // The validator rides along on every hop: 301/302/307/308
            // targets are the same resource at a different URI
            // (RFC 9110 §15.4), so §13.1.5's mutation guard applies to
            // whichever origin finally serves the bytes. A 303 target
            // is a different resource — the walk below rejects it
            // (`range_anchored`).
            hdrs.push(("If-Range", v));
        }
        // Range GETs re-walk redirects per request: temporary hops
        // (302/307) were deliberately not baked into `self.uri`, and a
        // permanent hop observed now rewrites it for the next request.
        let walk = call_with_redirects(
            self.agent_ref(),
            RequestMethod::Get,
            &self.uri,
            &hdrs,
            &self.knobs,
            true,
            &format!("HTTP GET {} {}", self.uri, range),
        )?;
        let resp = walk.resp;
        // Error diagnostics below name the URI that actually answered.
        let uri = walk.final_uri;
        if walk.next_request_uri != self.uri {
            self.uri = walk.next_request_uri;
        }
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
                            uri, range, self.total_len, self.pos
                        )));
                    }
                    Err(e) => {
                        return Err(io::Error::other(format!(
                            "HTTP 416 {} {}: invalid Content-Range '{cr}': {e}",
                            uri, range
                        )));
                    }
                }
            }
            // §14.4 SHOULD, not MUST — a 416 with no Content-Range is
            // unusual but legal. Still treat it as a hard error since
            // the read can't proceed; just say so plainly.
            return Err(io::Error::other(format!(
                "HTTP 416 {} {}: server rejected range (no Content-Range body)",
                uri, range
            )));
        }
        if !(status == 206 || status == 200) {
            return Err(io::Error::other(format!(
                "HTTP GET {} {}: status {status}",
                uri, range
            )));
        }
        // RFC 9110 §8.4 + §12.5.3: we sent `Accept-Encoding: identity`,
        // so a response that nevertheless carries a real content coding
        // means the server ignored the field. Every byte the reader is
        // about to see — and the Content-Length / Content-Range
        // metadata validated below — would describe the coded form
        // (§8.4), so the read cannot proceed. Checked before any other
        // metadata is interpreted: a §8.6 length-mismatch diagnostic on
        // a gzip-coded body would name the symptom, not the cause.
        // §5.6.1: the `#` list may be split across field lines, so walk
        // them all; obs-fold normalised first per RFC 7230 §3.2.4.
        let mut get_codings: Vec<String> = Vec::new();
        for v in resp.headers().get_all("content-encoding") {
            match v.to_str() {
                Ok(s) => get_codings.extend(non_identity_content_codings(&normalize_obs_fold(s))),
                Err(_) => get_codings.push("<non-ASCII content-coding>".to_owned()),
            }
        }
        if !get_codings.is_empty() {
            return Err(io::Error::other(format!(
                "HTTP {status} {} {}: response carries Content-Encoding {get_codings:?} \
                 despite 'Accept-Encoding: identity' (RFC 9110 §12.5.3) — per §8.4 the \
                 body and byte-range metadata describe the coded form, not the media bytes",
                uri, range
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
                uri, range
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
        // Bytes the response body promises beyond the prefix drain. For
        // the 200 fallback that is the whole remainder of the
        // representation; the 206 branch below narrows it to the
        // Content-Range span (RFC 9110 §15.3.7: the response is
        // self-descriptive and may cover less than the requested
        // open-ended range).
        let mut span = total_len - pos;
        if status == 200 {
            if let Some(cl) = get_content_length {
                if cl != total_len {
                    return Err(io::Error::other(format!(
                        "HTTP 200 {} {}: Content-Length {cl} != HEAD-observed total {total_len} \
                         (RFC 9110 §8.6 — resource resized between HEAD and GET)",
                        uri, range
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
                    uri, range
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
                    io::Error::other(format!("HTTP 206 {} {}: missing Content-Range", uri, range))
                })?
                .to_str()
                .map_err(|_| {
                    io::Error::other(format!(
                        "HTTP 206 {} {}: non-ASCII Content-Range",
                        uri, range
                    ))
                })?
                .to_owned();
            let parsed = parse_byte_content_range(&cr_raw).map_err(|e| {
                io::Error::other(format!(
                    "HTTP 206 {} {}: invalid Content-Range '{cr_raw}': {e}",
                    uri, range
                ))
            })?;
            // first-byte-pos MUST match the position we asked for. The
            // server is allowed to satisfy a partial subrange, but
            // not to slide the start.
            if parsed.first != pos {
                return Err(io::Error::other(format!(
                    "HTTP 206 {} {}: Content-Range first-byte-pos {} != requested pos {}",
                    uri, range, parsed.first, pos
                )));
            }
            // complete-length, when concrete, must equal the size we
            // recorded at HEAD. A mid-stream resource resize is a
            // cache/origin mismatch we cannot recover from in-band.
            if let Some(complete) = parsed.complete {
                if complete != total_len {
                    return Err(io::Error::other(format!(
                        "HTTP 206 {} {}: Content-Range complete-length {complete} != known total {total_len}",
                        uri, range
                    )));
                }
            }
            // last-byte-pos must lie inside the representation we
            // expect.
            if parsed.last >= total_len {
                return Err(io::Error::other(format!(
                    "HTTP 206 {} {}: Content-Range last-byte-pos {} >= total {}",
                    uri, range, parsed.last, total_len
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
                        uri, range
                    )));
                }
            }
            // RFC 9110 §15.3.7: a 206 "may only partially satisfy" the
            // range request — the enclosed part is exactly what
            // Content-Range declares, and "additional requests" cover
            // the rest. Record the declared span so the read path can
            // (a) stop at the span boundary instead of trusting the
            // transport framing, and (b) re-request the remainder from
            // the new position (§14.2: byte ranges "support efficient
            // recovery from partially failed transfers and partial
            // retrieval").
            span = parsed.last - parsed.first + 1;
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
                            uri,
                            skip_prefix - remaining
                        ),
                    ));
                }
                remaining -= n as u64;
            }
        }
        self.body = Some(reader);
        self.body_remaining = span;
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

/// Classification of a HEAD response's `Vary` header for the driver's
/// content-negotiation stability check, per RFC 9110 §12.5.5.
///
/// The driver opens a resource with a single HEAD, records its length
/// and validator, then satisfies every later read with an independent
/// `Range` GET. That pattern silently assumes the origin maps the
/// target URI to *one* representation that stays put for the lifetime
/// of the source. `Vary` is exactly the signal that this assumption
/// can be false:
///
/// > To inform user agent recipients that this response was subject to
/// > content negotiation (§12) and a different representation might be
/// > sent in a subsequent request if other values are provided in the
/// > listed header fields (proactive negotiation). — §12.5.5
///
/// §12.5.5 ABNF: `Vary = #( "*" / field-name )` — a §5.6.1 list whose
/// members are either the wildcard `*` or request field-names.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Vary {
    /// The field was absent or listed only empty members. §12.5.5 does
    /// not require the field even on a negotiated resource, so this is
    /// "no warning", not "no negotiation".
    Absent,
    /// A list containing `*`. §12.5.5: this "signals that other aspects
    /// of the request might have played a role in selecting the response
    /// representation, possibly including aspects outside the message
    /// syntax (e.g., the client's network address)". The driver cannot
    /// reproduce such aspects deterministically across its HEAD and the
    /// later Range GETs, so the representation it ranges over is not
    /// guaranteed to be the one the HEAD measured.
    Wildcard,
    /// A list of concrete request field-names (the selecting header
    /// fields). The driver sends a fixed, identical header set on the
    /// HEAD and on every Range GET (`Accept-Encoding: identity`, no
    /// `Accept-Language`/`Accept` overrides, etc.), so as long as the
    /// origin negotiates purely on those request fields the selected
    /// representation is stable across the source's lifetime. Carries
    /// the lowercased field-names for diagnostics.
    Fields(Vec<String>),
}

/// Parse a `Vary` field value per RFC 9110 §12.5.5 ABNF
/// (`Vary = #( "*" / field-name )`).
///
/// `#` is the §5.6.1 list construction: comma-separated, OWS-tolerant
/// on each side of the comma, empty members dropped. A member of `*`
/// anywhere in the list makes the whole value a [`Vary::Wildcard`] —
/// §12.5.5 treats `*` as a list member, not a standalone form, and one
/// `*` poisons the determinism of every read regardless of the other
/// members. Otherwise each member is a `field-name` (a §5.6.2 token);
/// non-token members are dropped (a single malformed slot must not mask
/// a real selecting field next to it, mirroring `parse_accept_ranges`).
/// Field-names are case-insensitive (§5.1), so they are lowercased.
fn parse_vary(s: &str) -> Vary {
    let mut fields: Vec<String> = Vec::new();
    for part in s.split(',') {
        let tok = part.trim_matches(|c: char| c == ' ' || c == '\t');
        if tok.is_empty() {
            continue;
        }
        if tok == "*" {
            // §12.5.5: a list containing the member "*" — once seen, the
            // whole value is the wildcard form. Short-circuit so a later
            // garbage member can't downgrade it.
            return Vary::Wildcard;
        }
        if !is_token(tok) {
            continue;
        }
        fields.push(tok.to_ascii_lowercase());
    }
    if fields.is_empty() {
        Vary::Absent
    } else {
        Vary::Fields(fields)
    }
}

/// Parse a `Content-Encoding` field value per RFC 9110 §8.4
/// (`Content-Encoding = #content-coding`, `content-coding = token`)
/// and return the codings that actually transform the bytes — i.e.
/// every list element except the reserved `identity` token.
///
/// §8.4.1: "All content codings are case-insensitive", so each kept
/// element is lowercased. §12.5.3 defines `identity` as "a synonym
/// for 'no encoding'", and §8.4 says it "SHOULD NOT be included" in
/// Content-Encoding — a server that sends it anyway is therefore
/// tolerated as a no-op rather than rejected. §5.6.1 empty list
/// elements (`gzip,,`) are dropped.
///
/// Fail-direction note: unlike `parse_accept_ranges`, a non-`token`
/// list element is KEPT (trimmed + lowercased), not skipped. There,
/// skipping a garbage slot protects the legitimate `bytes` next to it
/// from being black-holed; here, skipping a garbage slot would
/// silently ACCEPT a response whose body was transformed by a coding
/// whose name we could not even parse — an unparseable coding is
/// still a coding the driver cannot undo, so it must surface in the
/// rejection diagnostic instead of vanishing.
///
/// An empty return means the representation is un-coded (or only
/// redundantly `identity`-coded) and the byte-offset model holds.
fn non_identity_content_codings(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let tok = part.trim_matches(|c: char| c == ' ' || c == '\t');
        if tok.is_empty() {
            // §5.6.1: empty list elements are tolerated and dropped.
            continue;
        }
        let lower = tok.to_ascii_lowercase();
        if lower == "identity" {
            continue;
        }
        out.push(lower);
    }
    out
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
    !s.is_empty() && s.bytes().all(is_tchar)
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

/// Parse a `comment` production per RFC 9110 §5.6.5 into its logical
/// text — the byte sequence between the outermost parentheses, with
/// every `quoted-pair` collapsed to the octet that followed the
/// backslash and the (balanced) nested-comment delimiters preserved
/// verbatim as part of the text.
///
/// ```text
/// comment = "(" *( ctext / quoted-pair / comment ) ")"
/// ctext   = HTAB / SP / %x21-27 / %x2A-5B / %x5D-7E / obs-text
/// ```
///
/// §5.6.5 only permits comments "in fields containing 'comment' as part
/// of their field value definition" — `User-Agent` / `Server` (§10.1.5
/// / §10.2.4 `product *( RWS ( product / comment ) )`), `Via`
/// (RFC 9110 §7.6.3), and the `Warning` field of RFC 7234 §5.5 all carry
/// a §5.6.5 `comment`. This crate issues unauthenticated `HEAD` / `Range`
/// requests and does not yet act on any of those response fields, so
/// there is no in-driver caller; the primitive completes the §5.6
/// generic-syntax family (§5.6.1 list, §5.6.2 token, §5.6.4
/// quoted-string, §5.6.6 parameters, §5.6.7 date are already present)
/// and is exported for the cargo-fuzz harness so any panic mode is
/// found by fuzzing.
///
/// Grammar notes the parser honours:
///
/// - The outermost `(` … `)` are required and stripped; the return is
///   the inner content. An empty comment `()` decodes to the empty
///   string.
/// - `ctext` is `HTAB / SP / %x21-27 / %x2A-5B / %x5D-7E / obs-text`.
///   Note the holes at `%x28` `(`, `%x29` `)`, and `%x5C` `\`: a bare
///   one of those characters is NOT `ctext` and only carries meaning
///   through the `comment` recursion (`(`/`)`) or the `quoted-pair`
///   escape (`\`).
/// - A `quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )` (§5.6.4) is
///   collapsed to the single octet after the backslash, mirroring the
///   §5.6.4 MUST applied by [`unquote_string`]. A bare `\` followed by
///   an octet outside that RHS (notably bare CR / LF, which would
///   unbalance the field line) is rejected.
/// - Nested comments recurse: `(a (b) c)` is one comment whose text is
///   `a (b) c` — the inner parentheses are preserved because they are
///   part of the comment's logical content, not stripped a second time.
///   Parentheses must be balanced; an unbalanced `(` or a `)` past the
///   matching close is rejected.
///
/// Returns `None` for any input that is not a single syntactically
/// valid `comment`: missing outer parens, content after the matching
/// close paren, an unbalanced paren, an illegal bare byte, or a
/// dangling / illegal `quoted-pair`. On the escape-free, single-level
/// happy path the return borrows the input slice (zero allocations);
/// only a `quoted-pair` forces the owned slow path.
///
/// The recursion depth is bounded by an explicit counter rather than
/// real call-stack recursion, so a deeply nested adversarial input
/// (`((((…))))`) cannot overflow the stack.
#[allow(dead_code)]
fn parse_comment(s: &str) -> Option<std::borrow::Cow<'_, str>> {
    use std::borrow::Cow;
    let bytes = s.as_bytes();
    // Must be paren-wrapped and at least two bytes for the empty `()`.
    if bytes.len() < 2 || bytes[0] != b'(' || bytes[bytes.len() - 1] != b')' {
        return None;
    }
    let inner = &bytes[1..bytes.len() - 1];
    // Fast pre-scan: validate every byte, track nesting depth, and
    // detect whether any quoted-pair is present. If none, the inner
    // slice can be returned borrowed.
    let mut i = 0usize;
    let mut depth: u32 = 0; // nesting below the outermost comment
    let mut has_escape = false;
    while i < inner.len() {
        let b = inner[i];
        match b {
            b'\\' => {
                // quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )
                // VCHAR = %x21-7E; obs-text = %x80-FF.
                let nxt = *inner.get(i + 1)?;
                let ok = nxt == 0x09 || nxt == 0x20 || (0x21..=0x7E).contains(&nxt) || nxt >= 0x80;
                if !ok {
                    return None;
                }
                has_escape = true;
                i += 2;
            }
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                if depth == 0 {
                    // A close paren at the top level ends the outermost
                    // comment early — there would be trailing content
                    // after the matching `)`, so the whole input is not
                    // a single comment.
                    return None;
                }
                depth -= 1;
                i += 1;
            }
            // ctext = HTAB / SP / %x21-27 / %x2A-5B / %x5D-7E / obs-text
            0x09 | 0x20 => i += 1,
            0x21..=0x27 | 0x2A..=0x5B | 0x5D..=0x7E => i += 1,
            _ if b >= 0x80 => i += 1, // obs-text
            _ => return None,         // bare control byte etc.
        }
    }
    // Every nested `(` opened in `inner` must have been closed before
    // the outermost `)` we stripped; otherwise the parens are
    // unbalanced.
    if depth != 0 {
        return None;
    }
    if !has_escape {
        // The inner slice is a substring of `s` bounded on both ends by
        // an ASCII byte (`(` / `)`), so [1, len-1] fall on UTF-8 code
        // point boundaries.
        return Some(Cow::Borrowed(
            std::str::from_utf8(inner).expect("inner slice is UTF-8 by construction"),
        ));
    }
    // Slow path: collapse each quoted-pair, preserving nested-comment
    // delimiters verbatim.
    let mut out: Vec<u8> = Vec::with_capacity(inner.len());
    let mut i = 0usize;
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
    // The escape's RHS may sever a multi-byte UTF-8 sequence boundary
    // if a sender backslash-escaped a single continuation byte, so run
    // a checked conversion rather than assume validity (same posture as
    // `unquote_string`).
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

/// A parsed §8.3.1 `media-type`: `(lowercased type, lowercased subtype,
/// §5.6.6 parameters)`.
type MediaType = (String, String, Vec<(String, String)>);

/// Parse a `media-type` field value per RFC 9110 §8.3.1 grammar:
///
/// ```text
/// media-type = type "/" subtype parameters
/// type       = token
/// subtype    = token
/// ```
///
/// (`parameters` is the §5.6.6 production already parsed by
/// [`parse_parameters`].)
///
/// Returns `Some((type, subtype, params))` where `type` and `subtype`
/// are the lowercased tokens — §8.3.1: "The type and subtype tokens are
/// case-insensitive." — and `params` is the §5.6.6 `Vec<(name, value)>`
/// of the trailing parameters (already lowercase-named and quoted-pair
/// decoded). Returns `None` when the value is not a syntactically valid
/// `media-type`: a missing `/`, an empty / non-`token` type or subtype,
/// or a slash that does not separate exactly one type from one subtype.
///
/// Parameter *values* are NOT case-folded here — §8.3.1: "Parameter
/// values might or might not be case-sensitive, depending on the
/// semantics of the parameter name." A consumer that knows a given
/// parameter is case-insensitive (e.g. `charset` per §8.3.2 / [RFC2046]
/// §4.1.2) folds the value itself.
///
/// The OWS posture matches the rest of the driver: leading / trailing
/// OWS on the whole value is trimmed, and OWS between the type/subtype
/// and the first `;` is tolerated (§8.3.1's `parameters` opens with
/// `*( OWS ";" OWS … )`, so the gap before the first `;` is OWS).
///
/// This is the §8.3.1 composition the §5.6.6 parameters helper was built
/// to enable — e.g. a `charset` extractor on `Content-Type` becomes a
/// `parse_media_type(ct)` then a case-insensitive `params` lookup for
/// `"charset"`, with the §8.3.2 case-insensitive fold applied by the
/// caller. No in-driver caller exists yet (the §15.3.7.2 multipart
/// rejection only needs the bare `type/subtype` prefix and uses the
/// narrower [`is_multipart_byteranges_content_type`]); the primitive is
/// in place ready to back any future per-parameter media-type
/// inspection.
#[allow(dead_code)]
fn parse_media_type(s: &str) -> Option<MediaType> {
    // §5.6.3 OWS strip on the whole value.
    let s = s.trim_matches([' ', '\t']);
    if s.is_empty() {
        return None;
    }
    // Split off the §5.6.6 `parameters` tail at the first *top-level*
    // `;`. A `;` cannot appear in `type` or `subtype` (both are `token`,
    // and `;` is not a `tchar` per §5.6.2), so the first `;` in the
    // value unambiguously opens the parameters tail — no quoted-string
    // awareness is needed at this split (the type/subtype part has no
    // quoted-strings).
    let (media, params_tail) = match s.split_once(';') {
        Some((m, rest)) => (m, Some(rest)),
        None => (s, None),
    };
    // `parameters` opens with `*( OWS ";" OWS … )`, so OWS between the
    // subtype and the first `;` is legal; trim it off the media part.
    let media = media.trim_end_matches([' ', '\t']);
    // §8.3.1: `type "/" subtype`. Exactly one `/` separating two tokens.
    let (ty, sub) = media.split_once('/')?;
    // A second `/` in the subtype would make it a non-`token` (`/` is
    // not a `tchar`), so `is_token(sub)` already rejects it; the
    // explicit `split_once` takes only the first `/`.
    if !is_token(ty) || !is_token(sub) {
        return None;
    }
    // §8.3.1: type and subtype are case-insensitive — normalise to
    // lowercase so a consumer can compare without re-folding.
    let ty = ty.to_ascii_lowercase();
    let sub = sub.to_ascii_lowercase();
    // §5.6.6 parameters tail (empty when there was no `;`). The helper
    // already tolerates a leading `;` / OWS, so the post-`;` remainder
    // is handed straight through.
    let params = match params_tail {
        Some(rest) => parse_parameters(rest),
        None => Vec::new(),
    };
    Some((ty, sub, params))
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

/// Walk every `Content-Encoding` field line of a response (the RFC
/// 9110 §8.4 `#` list may be split across lines per §5.6.1), normalise
/// obs-fold first (RFC 7230 §3.2.4), and collect every coding that is
/// not the §12.5.3 `identity` "no encoding" synonym. A field value
/// that cannot even be read as a string cannot name a coding we know
/// how to leave alone — it is reported as an opaque placeholder so the
/// caller fails toward rejection, never toward silent acceptance.
fn non_identity_codings_in(headers: &ureq::http::HeaderMap) -> Vec<String> {
    let mut codings: Vec<String> = Vec::new();
    for v in headers.get_all("content-encoding") {
        match v.to_str() {
            Ok(s) => codings.extend(non_identity_content_codings(&normalize_obs_fold(s))),
            Err(_) => codings.push("<non-ASCII content-coding>".to_owned()),
        }
    }
    codings
}

/// Render the RFC 9110 §10.2.3 `Retry-After` hint (if any) of a
/// non-success response for inclusion in an error message, with
/// obs-fold normalised prior to interpretation (RFC 7230 §3.2.4).
fn retry_after_hint_of(headers: &ureq::http::HeaderMap) -> String {
    let retry_after = headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .map(normalize_obs_fold);
    retry_after
        .as_deref()
        .map(format_retry_after_hint)
        .unwrap_or_default()
}

/// Capture a STRONG validator per RFC 9110 §13.1.5 from a metadata
/// response's headers, then run the §12.5.5 `Vary: *` stability check
/// against it. Shared by the HEAD open path and the `bytes=0-` GET
/// probe path; `ctx` names the request for error messages.
///
/// Validator: ETag takes precedence (§8.8.3 is "more reliable for
/// validation than a modification date" and the strong/weak
/// distinction is grammatical); fall back to Last-Modified only when
/// §8.8.2.2's "Date - Last-Modified >= 1s" rule promotes it from
/// implicitly-weak to strong.
///
/// Vary: §12.5.5's wildcard form "signals that other aspects of the
/// request might have played a role in selecting the response
/// representation, possibly including aspects outside the message
/// syntax (e.g., the client's network address)". The driver cannot
/// reproduce out-of-band aspects across requests, so a `Vary: *`
/// resource may serve a *different* representation on the very next
/// range GET — with a different length the recorded total no longer
/// describes, and different bytes a demuxer would silently misparse.
/// The §13.1.5 If-Range guard catches exactly this divergence, but
/// only when a strong validator exists to carry — so `Vary: *` is
/// fatal ONLY when no strong validator was captured. The
/// concrete-field-name form (§12.5.5 form 2) is always safe here: the
/// driver sends a fixed, identical request header set on the metadata
/// request and every range GET, so negotiation keyed on request
/// fields lands on the same representation each time. Obs-fold is
/// normalised before interpretation per RFC 7230 §3.2.4 (`Vary` is a
/// §5.6.1 comma list, a plausible obs-fold target for older
/// origins/proxies).
fn validator_with_vary_check(
    ctx: &str,
    headers: &ureq::http::HeaderMap,
) -> Result<Option<StrongValidator>> {
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
    let vary_owned = headers
        .get("vary")
        .and_then(|v| v.to_str().ok())
        .map(normalize_obs_fold);
    if let Some(vary_raw) = vary_owned.as_deref() {
        if parse_vary(vary_raw) == Vary::Wildcard && validator.is_none() {
            return Err(Error::Unsupported(format!(
                "{ctx}: response carries 'Vary: *' (RFC 9110 §12.5.5) with no \
                 strong validator (ETag / promotable Last-Modified) — the origin warns the \
                 representation may be selected on aspects outside the message syntax, so a \
                 later Range GET could serve a different representation the driver cannot \
                 detect (no If-Range guard per §13.1.5)"
            )));
        }
    }
    Ok(validator)
}

impl Read for HttpSource {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.pos >= self.total_len {
            return Ok(0);
        }
        // Transparent-resume budget for THIS call (RFC 9110 §14.2:
        // byte ranges "support efficient recovery from partially
        // failed transfers" — the recovery is a fresh `Range:
        // bytes=<pos>-` GET, guarded by `If-Range` when a strong
        // validator exists so a mutated representation cannot be
        // silently spliced onto the old bytes; §13.1.5). Any
        // successful read returns from the loop, so the budget
        // naturally resets once forward progress is made.
        let mut attempts: u32 = 0;
        loop {
            if self.body.is_none() {
                self.issue_range()?;
            }
            let body = self.body.as_mut().expect("body just issued");
            // Never read past the span the response declared. With
            // close-delimited framing (RFC 9112 §6.3 option 8) the
            // transport would otherwise happily hand us trailing bytes
            // beyond the Content-Range span, silently skewing `pos`
            // against the representation's byte offsets. §15.3.7 makes
            // the 206 self-descriptive: the span is the truth, not the
            // connection state.
            let want = out
                .len()
                .min(usize::try_from(self.body_remaining).unwrap_or(usize::MAX));
            if want == 0 {
                // Span exhausted with the representation not yet
                // finished: the server satisfied only part of the
                // open-ended range (permitted by §15.3.7 / §14.2 —
                // "it may only be possible (or efficient) to send a
                // portion of the requested ranges first, while
                // expecting the client to re-request the remaining
                // portions later"). Issue the follow-up range from the
                // new position. This is NOT a resume retry — the span
                // was fully delivered — so the budget is untouched.
                self.body = None;
                continue;
            }
            let truncation = match body.read(&mut out[..want]) {
                Ok(n) if n > 0 => {
                    self.pos += n as u64;
                    self.body_remaining -= n as u64;
                    return Ok(n);
                }
                // EOF before the declared span was delivered (§8.6:
                // the declared length is part of the message's
                // self-description; a shorter body means the message
                // was incomplete).
                Ok(_) => None,
                // A transport-shaped failure mid-body (peer reset /
                // drop) is the exact partially-failed-transfer case
                // §14.2 designed byte ranges to recover from.
                // Anything else (invalid data, interrupted-by-caller
                // semantics, timeout policy) is not ours to paper
                // over — propagate.
                Err(e) if is_transient_read_error(e.kind()) => Some(e),
                Err(e) => return Err(e),
            };
            self.body = None;
            let missing = self.body_remaining;
            self.body_remaining = 0;
            if attempts < self.knobs.read_retries() {
                // Resume: the next loop turn re-issues
                // `Range: bytes=<pos>-` (+ `If-Range` when we hold a
                // strong validator). `issue_range` failures — 416,
                // the §13.1.5 If-Range 200-fallback (mid-stream
                // mutation), metadata mismatches — stay fatal; only
                // the transport layer gets second chances.
                attempts += 1;
                continue;
            }
            let via = match truncation {
                Some(e) => format!(" ({e})"),
                None => String::new(),
            };
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "HTTP GET {}: body truncated at pos {}{via} — {missing} byte(s) of the \
                     declared span still owed after {attempts} transparent re-request(s) \
                     (RFC 9110 §15.3.7 Content-Range span / §8.6 / §14.2 recovery)",
                    self.uri, self.pos
                ),
            ));
        }
    }
}

/// Errors on the body stream that plausibly mean "the transfer
/// partially failed" (RFC 9110 §14.2) rather than "the data is bad" —
/// the only class the read path is willing to transparently resume
/// across with a fresh range request.
fn is_transient_read_error(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
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
            // A short forward hop inside the live body's declared span
            // is cheaper as a bounded drain than as a fresh range GET
            // (request round trip + connection churn); demuxers skip
            // small box/frame payloads constantly. RFC 9110 §14.2's
            // own efficiency motivation cuts both ways — ranges avoid
            // transferring the whole representation, but a range GET
            // per few-byte skip is the opposite waste. The stream
            // position is identical either way; only the request count
            // differs. Draining never crosses the span boundary
            // (§15.3.7: bytes beyond it were never promised) and never
            // exceeds `seek_drain_max`.
            let drained = new_pos > self.pos
                && self.body.is_some()
                && new_pos - self.pos <= self.knobs.seek_drain_max().min(self.body_remaining)
                && self.drain_forward(new_pos - self.pos);
            if !drained {
                // Backward seek, long hop, span overrun, or a drain
                // that hit a transport fault: drop the body and let
                // the next read issue `Range: bytes=<new_pos>-`.
                self.body = None;
                self.body_remaining = 0;
            }
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

/// The `delta-seconds` saturation value mandated by RFC 9111 §1.2.2.
///
/// §1.2.2: "If a cache receives a delta-seconds value greater than the
/// greatest integer it can represent, or if any of its subsequent
/// calculations overflows, the cache MUST consider the value to be
/// 2147483648 (2^31) or the greatest positive integer it can
/// conveniently represent." We store directive arguments in a `u64`
/// (comfortably wider than the §1.2.2 "at least 31 bits" floor), so the
/// only saturation path is an argument whose decimal digits overflow
/// `u64`; those clamp to this constant rather than being dropped.
pub const DELTA_SECONDS_MAX: u64 = 2_147_483_648;

/// Parse a `delta-seconds` argument (RFC 9111 §1.2.2 `delta-seconds =
/// 1*DIGIT`) with the §1.2.2 overflow-saturation rule applied.
///
/// Returns `Some(n)` for a non-empty all-ASCII-digit string, saturating
/// any value that exceeds `u64::MAX` to [`DELTA_SECONDS_MAX`] per the
/// §1.2.2 MUST. Returns `None` for the empty string or any non-digit
/// byte (a leading `+`/`-`, embedded space, or a quoted-string form) —
/// every directive that takes a `delta-seconds` argument is defined with
/// the token form only (§5.2.2.1 / §5.2.1.x: "A sender MUST NOT generate
/// the quoted-string form"), and §4.2.1 directs a recipient to treat a
/// directive "with non-integer content" as making the response stale, so
/// a non-numeric argument is reported as absent rather than silently
/// coerced.
fn parse_delta_seconds(arg: &str) -> Option<u64> {
    if arg.is_empty() || !arg.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // §1.2.2: detect overflow and saturate rather than wrap; an
    // out-of-range count must "not be treated as a negative value in
    // later calculations".
    Some(arg.parse::<u64>().unwrap_or(DELTA_SECONDS_MAX))
}

/// A parsed `Cache-Control` field value per RFC 9111 §5.2.
///
/// The §5.2 grammar `Cache-Control = #cache-directive` and
/// `cache-directive = token [ "=" ( token / quoted-string ) ]` is a
/// single production shared by request directives (§5.2.1) and response
/// directives (§5.2.2); a recipient parses the wire form the same way in
/// both roles and applies role-appropriate semantics afterwards, so this
/// one struct carries every §5.2.1 / §5.2.2 directive. Fields are `None`
/// / `false` / empty when the corresponding directive is absent.
///
/// §5.2.3: "A cache MUST ignore unrecognized cache directives." Any
/// directive token not defined in §5.2.1 / §5.2.2 is preserved in
/// [`extensions`](CacheControl::extensions) (so a behavioural-extension
/// consumer can still inspect it) rather than discarded — ignoring is a
/// behaviour, not a parse failure.
///
/// Duplicate-directive policy follows RFC 9111 §4.2.1: "When there is
/// more than one value present for a given directive … either the first
/// occurrence should be used or the response should be considered
/// stale." This parser takes the first-occurrence option for every
/// valued directive (later duplicates of `max-age`, `s-maxage`, etc. are
/// dropped). A boolean directive appearing more than once is idempotent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheControl {
    /// `max-age` (§5.2.1.1 request / §5.2.2.1 response) `delta-seconds`,
    /// §1.2.2-saturated. `None` when absent or carrying a non-`1*DIGIT`
    /// argument.
    pub max_age: Option<u64>,
    /// `s-maxage` (§5.2.2.10) `delta-seconds`, §1.2.2-saturated.
    pub s_maxage: Option<u64>,
    /// `max-stale` (§5.2.1.2). `Some(None)` is the no-argument form
    /// ("accept a stale response of any age"); `Some(Some(n))` carries
    /// the §1.2.2-saturated bound. `None` when the directive is absent.
    pub max_stale: Option<Option<u64>>,
    /// `min-fresh` (§5.2.1.3) `delta-seconds`, §1.2.2-saturated.
    pub min_fresh: Option<u64>,
    /// Unqualified `no-cache` — §5.2.1.4 (request) / the argument-free
    /// §5.2.2.4 (response) form. `true` whenever a `no-cache` directive
    /// is present without an argument.
    pub no_cache: bool,
    /// Qualified `no-cache="field1, field2"` field names (§5.2.2.4),
    /// lowercased ("Field names are case-insensitive"). Empty unless the
    /// quoted-string argument form is present.
    pub no_cache_fields: Vec<String>,
    /// `no-store` (§5.2.1.5 request / §5.2.2.5 response).
    pub no_store: bool,
    /// `no-transform` (§5.2.1.6 request / §5.2.2.6 response).
    pub no_transform: bool,
    /// `only-if-cached` (§5.2.1.7, request directive).
    pub only_if_cached: bool,
    /// `must-revalidate` (§5.2.2.2, response directive).
    pub must_revalidate: bool,
    /// `must-understand` (§5.2.2.3, response directive).
    pub must_understand: bool,
    /// Unqualified `private` (§5.2.2.7, response directive).
    pub private: bool,
    /// Qualified `private="field1, field2"` field names (§5.2.2.7),
    /// lowercased. Empty unless the quoted-string argument form is
    /// present.
    pub private_fields: Vec<String>,
    /// `proxy-revalidate` (§5.2.2.8, response directive).
    pub proxy_revalidate: bool,
    /// `public` (§5.2.2.9, response directive).
    pub public: bool,
    /// Unrecognized / extension directives (§5.2.3), preserved as
    /// `(lowercased token, optional decoded argument)` in wire order.
    pub extensions: Vec<(String, Option<String>)>,
}

/// Parse a `Cache-Control` field value per RFC 9111 §5.2.
///
/// ABNF (§5.2):
///
/// ```text
/// Cache-Control   = #cache-directive
/// cache-directive = token [ "=" ( token / quoted-string ) ]
/// ```
///
/// The `#`-list (RFC 9110 §5.6.1) is split on top-level commas with
/// quoted-string awareness (a comma inside a `"…"` argument does not end
/// a directive), empty elements are skipped per §5.6.1's "tolerate empty
/// list elements" recipient posture, and surrounding OWS (§5.6.3) is
/// trimmed from each element. An `obs-fold` (RFC 7230 §3.2.4) anywhere
/// in the value is normalised to a single SP before splitting.
///
/// §5.2: "Cache directives are identified by a token, to be compared
/// case-insensitively" — directive names are lowercased before
/// dispatch. "[Directives] have an optional argument that can use both
/// token and quoted-string syntax. For the directives defined below that
/// define arguments, recipients ought to accept both forms" — so the
/// argument is read via the §5.6.4 quoted-string unwrap when it opens
/// with DQUOTE, and as a bare token otherwise, regardless of which form
/// §5.2 nominally requires the *sender* to use.
///
/// Recognized directives populate the typed [`CacheControl`] fields;
/// `delta-seconds` arguments are validated and §1.2.2-saturated via
/// [`parse_delta_seconds`] (a non-numeric argument leaves the field
/// `None` — §4.2.1 stale-on-non-integer). The qualified `#field-name`
/// forms of `no-cache` / `private` (§5.2.2.4 / §5.2.2.7) split their
/// decoded quoted-string argument into lowercased field names. Unknown
/// directive tokens land in [`CacheControl::extensions`] (§5.2.3 "ignore
/// unrecognized" — preserved, not dropped). Duplicate valued directives
/// keep the first occurrence (§4.2.1).
///
/// This is always a structural parse: a malformed element (a bad token
/// name, OWS around the `=`, an unterminated quoted-string) is skipped,
/// never a hard error, matching the recipient robustness the rest of the
/// driver applies to §5.6.1 list fields.
pub fn parse_cache_control(s: &str) -> CacheControl {
    let normalized = normalize_obs_fold(s);
    let mut cc = CacheControl::default();
    for elem in split_directive_list(&normalized) {
        // cache-directive = token [ "=" ( token / quoted-string ) ].
        // Split on the FIRST `=`; a `=` inside the quoted-string body is
        // protected because the qstr only appears on the value side.
        let (raw_name, raw_arg) = match elem.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (elem, None),
        };
        // §5.6.3 OWS is not permitted around the `=` in a directive
        // (cache-directive has no OWS between token and "="); but a
        // recipient trimming the element edges is harmless and matches
        // the parse_one_parameter posture. Trim element-edge OWS only.
        let name = raw_name.trim_matches(|c: char| c == ' ' || c == '\t');
        if !is_token(name) {
            // Empty or non-token directive name — skip (e.g. a stray
            // comma element, or `"=foo"`).
            continue;
        }
        let lname = name.to_ascii_lowercase();
        // Decode the argument: quoted-string (§5.6.4 unwrap) when it
        // opens with DQUOTE, otherwise a bare token. A present-but-empty
        // or malformed argument decodes to None for that element.
        let arg: Option<String> = match raw_arg {
            None => None,
            Some(v) => {
                let v = v.trim_matches(|c: char| c == ' ' || c == '\t');
                if v.starts_with('"') {
                    // §5.6.4 quoted-string form: unwrap and collapse any
                    // quoted-pair. An unterminated qstr decodes to None.
                    unquote_string(v).map(|c| c.into_owned())
                } else if is_token(v) {
                    Some(v.to_owned())
                } else {
                    // Empty or non-token bare argument — treat the
                    // directive as argument-less for recognized booleans,
                    // and as a no-argument extension otherwise.
                    None
                }
            }
        };
        apply_directive(&mut cc, &lname, arg);
    }
    cc
}

/// Dispatch one parsed `(lowercased-name, optional-decoded-argument)`
/// directive into the typed [`CacheControl`] accumulator per RFC 9111
/// §5.2.1 / §5.2.2, honouring §4.2.1 first-occurrence-wins for valued
/// directives and §5.2.3 extension preservation.
fn apply_directive(cc: &mut CacheControl, name: &str, arg: Option<String>) {
    // delta-seconds helper: first-occurrence-wins (§4.2.1) on the
    // already-populated slot.
    fn set_delta(slot: &mut Option<u64>, arg: &Option<String>) {
        if slot.is_none() {
            if let Some(a) = arg {
                *slot = parse_delta_seconds(a);
            }
        }
    }
    // #field-name argument splitter for the qualified no-cache / private
    // forms (§5.2.2.4 / §5.2.2.7): a comma list of field-names, each a
    // token, lowercased ("Field names are case-insensitive").
    fn field_names(arg: &str) -> Vec<String> {
        arg.split(',')
            .map(|f| f.trim_matches(|c: char| c == ' ' || c == '\t'))
            .filter(|f| is_token(f))
            .map(|f| f.to_ascii_lowercase())
            .collect()
    }
    match name {
        "max-age" => set_delta(&mut cc.max_age, &arg),
        "s-maxage" => set_delta(&mut cc.s_maxage, &arg),
        "min-fresh" => set_delta(&mut cc.min_fresh, &arg),
        "max-stale" => {
            // §5.2.1.2: "If no value is assigned to max-stale, then the
            // client will accept a stale response of any age." Model
            // no-arg as Some(None), valued as Some(Some(n)). First
            // occurrence wins (§4.2.1).
            if cc.max_stale.is_none() {
                cc.max_stale = Some(arg.as_deref().and_then(parse_delta_seconds));
            }
        }
        "no-cache" => {
            // §5.2.2.4: unqualified (no arg) vs qualified (#field-name in
            // a quoted-string). A present argument is the qualified form.
            match arg {
                Some(a) => {
                    let names = field_names(&a);
                    if cc.no_cache_fields.is_empty() {
                        cc.no_cache_fields = names;
                    }
                }
                None => cc.no_cache = true,
            }
        }
        "private" => match arg {
            Some(a) => {
                let names = field_names(&a);
                if cc.private_fields.is_empty() {
                    cc.private_fields = names;
                }
            }
            None => cc.private = true,
        },
        "no-store" => cc.no_store = true,
        "no-transform" => cc.no_transform = true,
        "only-if-cached" => cc.only_if_cached = true,
        "must-revalidate" => cc.must_revalidate = true,
        "must-understand" => cc.must_understand = true,
        "proxy-revalidate" => cc.proxy_revalidate = true,
        "public" => cc.public = true,
        // §5.2.3: ignore unrecognized directives — preserved (not
        // dropped) so behavioural-extension consumers can still see them.
        _ => cc.extensions.push((name.to_owned(), arg)),
    }
}

/// Split a `Cache-Control` (or any RFC 9110 §5.6.1 `#`-list whose
/// elements may contain a quoted-string argument) value into trimmed,
/// non-empty elements on top-level commas.
///
/// A comma inside a `"…"` quoted-string (with `\`-escaped octets
/// honoured per §5.6.4 `quoted-pair`) does NOT split the list — this is
/// what lets `no-cache="x-foo, x-bar"` survive as one directive. Empty
/// elements (from `a,,b` or a leading/trailing comma) are dropped per
/// §5.6.1, and each surviving element is OWS-trimmed (§5.6.3).
fn split_directive_list(s: &str) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut out: Vec<&str> = Vec::new();
    let mut start = 0usize;
    let mut in_quote = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if in_quote {
            if b == b'\\' && i + 1 < bytes.len() {
                // quoted-pair: skip the escaped octet so a `\"` or `\,`
                // inside the body is not mistaken for a delimiter.
                i += 2;
                continue;
            } else if b == b'"' {
                in_quote = false;
            }
        } else if b == b'"' {
            in_quote = true;
        } else if b == b',' {
            let elem = s[start..i].trim_matches(|c: char| c == ' ' || c == '\t');
            if !elem.is_empty() {
                out.push(elem);
            }
            start = i + 1;
        }
        i += 1;
    }
    let elem = s[start..].trim_matches(|c: char| c == ' ' || c == '\t');
    if !elem.is_empty() {
        out.push(elem);
    }
    out
}

/// One parsed `challenge` from a `WWW-Authenticate` (or
/// `Proxy-Authenticate`) field value, per RFC 9110 §11.3:
///
/// ```text
/// challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// ```
///
/// A challenge is an authentication-scheme name optionally followed by
/// EITHER a single `token68` blob (the base64-ish form used by schemes
/// like Negotiate / NTLM) OR a comma-separated list of `auth-param`
/// name/value pairs (the form used by Basic / Digest, e.g.
/// `realm="…"`). The two argument shapes are mutually exclusive within
/// one challenge, so [`token68`](Challenge::token68) and
/// [`params`](Challenge::params) are never both populated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Challenge {
    /// `auth-scheme` (§11.1) — "a case-insensitive token to identify the
    /// authentication scheme", lowercased here so `Basic` / `basic`
    /// compare equal.
    pub scheme: String,
    /// The `token68` form (§11.2) when the scheme carried a single
    /// base64/base32/base16-style blob instead of `auth-param`s. `None`
    /// when the challenge had no argument or carried `auth-param`s.
    pub token68: Option<String>,
    /// `auth-param` list (§11.2) as `(lowercased-name, decoded-value)`
    /// pairs in wire order. Names are matched case-insensitively (§11.2);
    /// values are read through the §5.6.4 quoted-string unwrap when
    /// DQUOTE-wrapped and kept verbatim when in `token` form (value
    /// case-sensitivity is scheme-specific, so the value case is not
    /// folded). Empty when the challenge had no argument or carried a
    /// `token68`.
    pub params: Vec<(String, String)>,
}

/// Parse a `WWW-Authenticate` / `Proxy-Authenticate` field value into a
/// list of [`Challenge`]s, per RFC 9110 §11.6.1:
///
/// ```text
/// WWW-Authenticate = #challenge
/// challenge        = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
/// auth-scheme      = token
/// auth-param       = token BWS "=" BWS ( token / quoted-string )
/// token68          = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~"
///                        / "+" / "/" ) *"="
/// ```
///
/// ## The §11.6.1 list ambiguity
///
/// Both the challenge list AND the `auth-param` list inside a challenge
/// are comma-separated, so a flat top-level comma split cannot by itself
/// tell "next challenge" from "next `auth-param` of the current
/// challenge". §11.6.1 spells out the worked example:
///
/// ```text
/// WWW-Authenticate: Basic realm="simple", Newauth realm="apps",
///                   type=1, title="Login to \"apps\""
/// ```
///
/// which is **two** challenges: `Basic` with `realm="simple"`, and
/// `Newauth` with `realm="apps", type=1, title="Login to \"apps\""`.
///
/// The disambiguation rule this parser applies, after a quoted-string-
/// aware top-level comma split (§5.6.1 `#`-list, so a comma inside a
/// `"…"` value never splits): each list element is classified as either
///
/// - a **bare `auth-param`** (`token BWS "=" …`) — it has NO scheme of
///   its own, so it attaches to the challenge currently being built; or
/// - a **challenge head** (`auth-scheme` alone, or `auth-scheme 1*SP
///   <arg>`) — it starts a new challenge.
///
/// An element is a bare `auth-param` when its first `token` is
/// immediately followed (modulo §11.2 BWS around `=`) by `=` with no
/// intervening `1*SP` scheme/argument boundary. Everything else opens a
/// new challenge, whose first whitespace-delimited token is the
/// `auth-scheme` and whose remainder (if any) is the first `token68` or
/// first `auth-param`.
///
/// ## Token68 vs auth-param within a challenge
///
/// §11.2's `token68` may end in `*"="`, which collides with the
/// `auth-param` `=`. The parser treats a challenge argument as
/// `token68` only when it is one whitespace-free run whose body is all
/// `token68` characters with any `=` confined to a trailing pad run AND
/// it is not of `name=value` `auth-param` shape; otherwise the
/// remainder is parsed as the `#auth-param` list. Once a challenge has
/// committed to `auth-param`s, subsequent bare `auth-param` elements
/// attach to it.
///
/// ## Robustness
///
/// Matching the rest of the driver's §5.6.1 list handling, malformed
/// pieces are skipped rather than failing the whole parse: an empty
/// list element (the §11.6.1 "comma, whitespace, comma" note calls this
/// harmless), an `auth-param` slot that is not `token = (token /
/// quoted-string)`, or a leading bare `auth-param` with no challenge to
/// attach to are all dropped while the surrounding well-formed
/// challenges survive. An `obs-fold` (RFC 7230 §3.2.4) anywhere in the
/// value is normalised to a single SP before parsing.
///
/// The same grammar backs `Proxy-Authenticate` (§11.7.1) and, with the
/// `credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`
/// production being identical, a single `Authorization` /
/// `Proxy-Authorization` value (which carries exactly one challenge-
/// shaped `credentials`); a caller wanting just the credentials reads
/// the first element of the returned `Vec`.
pub fn parse_www_authenticate(s: &str) -> Vec<Challenge> {
    let normalized = normalize_obs_fold(s);
    // §5.6.1 `#`-list: quoted-string-aware top-level comma split. We
    // reuse split_directive_list — its quoted-string awareness and
    // §5.6.3 OWS-trim / empty-drop are exactly the §11.6.1 list posture.
    let elements = split_directive_list(&normalized);
    let mut out: Vec<Challenge> = Vec::new();

    for elem in elements {
        // Classify: does this element start a new challenge, or is it a
        // bare auth-param attaching to the current one?
        if let Some((scheme, rest)) = split_challenge_head(elem) {
            // New challenge. `scheme` is the auth-scheme token; `rest`
            // (already OWS-trimmed) is the first token68 / first
            // auth-param, or empty.
            let mut ch = Challenge {
                scheme: scheme.to_ascii_lowercase(),
                token68: None,
                params: Vec::new(),
            };
            if !rest.is_empty() {
                if let Some(t68) = as_token68(rest) {
                    ch.token68 = Some(t68.to_owned());
                } else if let Some(pair) = parse_one_auth_param(rest) {
                    ch.params.push(pair);
                }
                // A non-empty rest that is neither a token68 nor a valid
                // auth-param is dropped (malformed first argument); the
                // scheme survives so a caller still sees the challenge.
            }
            out.push(ch);
        } else {
            // Bare auth-param: attach to the challenge in progress. A
            // challenge that committed to token68 cannot also take
            // auth-params (§11.3 mutual exclusivity); in that case, and
            // when there is no current challenge at all, the orphan slot
            // is dropped.
            if let Some(cur) = out.last_mut() {
                if cur.token68.is_none() {
                    if let Some(pair) = parse_one_auth_param(elem) {
                        cur.params.push(pair);
                    }
                }
            }
        }
    }
    out
}

/// Classify a §5.6.1 list element as a challenge head.
///
/// Returns `Some((auth-scheme, rest))` when the element opens a new
/// challenge — i.e. its first `token` is the `auth-scheme` and is NOT
/// immediately followed (modulo §11.2 BWS) by `=` (which would make the
/// element a bare `auth-param` of the *current* challenge). `rest` is the
/// OWS-trimmed remainder after the `1*SP` that separates the scheme from
/// its first `token68` / `auth-param` (empty when the challenge is just a
/// bare scheme).
///
/// Returns `None` when the element is a bare `auth-param`
/// (`token BWS "=" …`) or has no leading `token` at all.
fn split_challenge_head(elem: &str) -> Option<(&str, &str)> {
    let bytes = elem.as_bytes();
    // The element is already OWS-trimmed by split_directive_list, so it
    // starts at the first non-OWS byte. Read the leading token run.
    let mut i = 0usize;
    while i < bytes.len() && is_tchar(bytes[i]) {
        i += 1;
    }
    if i == 0 {
        // No leading token (starts with `=`, a quote, whitespace, …):
        // not a challenge head.
        return None;
    }
    let head = &elem[..i];
    // What follows the leading token?
    //   - end of element        -> bare scheme, no argument.
    //   - 1*SP then more        -> scheme + (token68 / first auth-param).
    //   - [BWS] "=" …           -> bare auth-param (NOT a challenge head).
    // Peek past optional BWS (SP / HTAB — §11.2 allows "bad" whitespace
    // around the `=`).
    let mut j = i;
    while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
        j += 1;
    }
    if j >= bytes.len() {
        // Bare scheme (possibly with trailing whitespace already trimmed).
        return Some((head, ""));
    }
    if bytes[j] == b'=' {
        // `token [BWS] "="` — this element is an auth-param, not a
        // challenge head. Defer to the caller's bare-auth-param branch.
        return None;
    }
    if j == i {
        // No SP/HTAB separator and the abutting byte is not `=`: a
        // non-tchar byte directly follows the leading token run (e.g.
        // `bad()` or `Basic"x"`). This is neither a clean `auth-scheme`
        // (which would have consumed the whole run as one token) nor a
        // bare `auth-param` (`token [BWS] "="`), so it is malformed. Defer
        // to the caller's bare-auth-param branch, which will drop it (it
        // has no valid `token = value` shape) rather than fabricating a
        // spurious challenge from the truncated leading token.
        return None;
    }
    // There was at least one SP/HTAB before a non-`=` byte: this is the
    // `auth-scheme 1*SP <arg>` form.
    let rest = elem[j..].trim_matches(|c: char| c == ' ' || c == '\t');
    Some((head, rest))
}

/// `token68` recogniser (RFC 9110 §11.2):
///
/// ```text
/// token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
/// ```
///
/// Returns `Some(s)` when `s` is a non-empty `token68`: a `1*` run of the
/// 66 unreserved-plus characters followed by an optional trailing run of
/// `=` pad octets, AND `s` is NOT of `auth-param` `name=value` shape
/// (which the §11.6.1 ambiguity note resolves toward auth-param). A
/// `token68` never contains whitespace or an interior `=` that is
/// followed by a non-`=` octet.
fn as_token68(s: &str) -> Option<&str> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    // Count the leading body run (no `=`).
    let mut i = 0usize;
    while i < bytes.len() && is_token68_body(bytes[i]) {
        i += 1;
    }
    if i == 0 {
        // token68 requires 1* body chars before the pad.
        return None;
    }
    // Everything from i on MUST be `=` (the `*"="` pad).
    if bytes[i..].iter().all(|&b| b == b'=') {
        Some(s)
    } else {
        None
    }
}

/// Single `auth-param` parser (RFC 9110 §11.2):
///
/// ```text
/// auth-param = token BWS "=" BWS ( token / quoted-string )
/// ```
///
/// Returns `Some((lowercased-name, decoded-value))` on a well-formed
/// `auth-param`. Unlike the §5.6.6 `parameter` (which forbids whitespace
/// around `=`), §11.2 explicitly allows BWS ("bad" whitespace) on BOTH
/// sides of the `=`, so this parser trims SP/HTAB around the separator.
/// The value is read through the §5.6.4 quoted-string unwrap when
/// DQUOTE-wrapped and kept verbatim as a `token` otherwise. Returns
/// `None` for a missing `=`, a non-`token` name, or a value that is
/// neither a valid `token` nor a valid `quoted-string`.
fn parse_one_auth_param(slot: &str) -> Option<(String, String)> {
    let slot = slot.trim_matches(|c: char| c == ' ' || c == '\t');
    let eq = slot.find('=')?;
    // §11.2 BWS: trim SP/HTAB around `=` on both sides.
    let name = slot[..eq].trim_matches(|c: char| c == ' ' || c == '\t');
    let value = slot[eq + 1..].trim_matches(|c: char| c == ' ' || c == '\t');
    if !is_token(name) {
        return None;
    }
    let lname = name.to_ascii_lowercase();
    if value.starts_with('"') {
        // §5.6.4 quoted-string: unwrap + collapse quoted-pair. An
        // unterminated / malformed quoted-string yields None (slot
        // dropped).
        let decoded = unquote_string(value)?.into_owned();
        Some((lname, decoded))
    } else if is_token(value) {
        Some((lname, value.to_owned()))
    } else {
        None
    }
}

/// `tchar` (RFC 9110 §5.6.2) membership test on a single byte — the
/// byte-level companion to [`is_token`].
fn is_tchar(b: u8) -> bool {
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
}

/// `token68` body-character (RFC 9110 §11.2, excluding the trailing `=`
/// pad) membership test on a single byte.
fn is_token68_body(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
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
    /// Fuzz-only wrapper for [`super::parse_vary`] (RFC 9110 §12.5.5
    /// `Vary = #( "*" / field-name )`). Returns a small integer tag
    /// (0=Absent, 1=Wildcard, 2=Fields) so the fuzzer can drive every
    /// classification branch.
    pub fn parse_vary(s: &str) -> u8 {
        match super::parse_vary(s) {
            super::Vary::Absent => 0,
            super::Vary::Wildcard => 1,
            super::Vary::Fields(_) => 2,
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
    /// Fuzz-only wrapper for [`super::parse_comment`] — exercises the
    /// RFC 9110 §5.6.5 `comment` grammar (outer-paren strip, nested
    /// comment recursion with balanced-paren tracking, `quoted-pair`
    /// collapse) on arbitrary input. Returns the decoded comment text
    /// when the input is a single valid comment, `None` otherwise —
    /// both outcomes must be reachable without a panic (and without a
    /// stack overflow on deeply nested `((((…))))` input), and any
    /// returned string must be valid UTF-8.
    pub fn parse_comment(s: &str) -> Option<String> {
        super::parse_comment(s).map(|c| c.into_owned())
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
    /// Fuzz-only wrapper for [`super::parse_media_type`] — exercises the
    /// RFC 9110 §8.3.1 `media-type = type "/" subtype parameters` grammar
    /// on arbitrary input. Returns `Some(parameter-count)` when the value
    /// is a syntactically valid media-type, `None` otherwise — both
    /// outcomes must be reachable without a panic, and any returned
    /// `(type, subtype, params)` strings must be valid UTF-8.
    pub fn non_identity_content_codings(s: &str) -> usize {
        super::non_identity_content_codings(s).len()
    }

    pub fn parse_media_type(s: &str) -> Option<usize> {
        super::parse_media_type(s).map(|(_, _, p)| p.len())
    }
    /// Fuzz-only wrapper for [`super::parse_cache_control`] — exercises
    /// the RFC 9111 §5.2 `Cache-Control = #cache-directive` grammar
    /// (quoted-string-aware comma splitting, token/quoted-string
    /// arguments, §1.2.2 delta-seconds saturation, §5.2.3 extension
    /// preservation) on arbitrary input. Returns the total count of
    /// populated directive slots so the fuzzer can drive both the empty
    /// and many-directive branches; the parser must never panic and any
    /// returned strings must be valid UTF-8.
    pub fn parse_cache_control(s: &str) -> usize {
        let cc = super::parse_cache_control(s);
        let mut n = cc.extensions.len()
            + cc.no_cache_fields.len()
            + cc.private_fields.len()
            + usize::from(cc.max_age.is_some())
            + usize::from(cc.s_maxage.is_some())
            + usize::from(cc.max_stale.is_some())
            + usize::from(cc.min_fresh.is_some());
        for flag in [
            cc.no_cache,
            cc.no_store,
            cc.no_transform,
            cc.only_if_cached,
            cc.must_revalidate,
            cc.must_understand,
            cc.private,
            cc.proxy_revalidate,
            cc.public,
        ] {
            n += usize::from(flag);
        }
        n
    }
    /// Fuzz-only wrapper for [`super::parse_www_authenticate`] —
    /// exercises the RFC 9110 §11.6.1 `WWW-Authenticate = #challenge`
    /// grammar (the §11.6.1 challenge/auth-param comma ambiguity, the
    /// §11.2 `token68` vs `auth-param` discrimination, BWS-around-`=`
    /// tolerance, quoted-string-aware splitting, §5.6.4 value unwrap) on
    /// arbitrary input. Returns the count of recognised challenges so the
    /// fuzzer can drive both the empty and many-challenge branches; the
    /// parser must never panic and every returned scheme / param / token68
    /// string must be valid UTF-8.
    pub fn parse_www_authenticate(s: &str) -> usize {
        super::parse_www_authenticate(s).len()
    }

    /// Fuzz-only wrapper for the RFC 3986 [`crate::uri`] module's
    /// strict path: Appendix A charset validation, §5.3 recomposition,
    /// §6.2.2/§6.2.3 (+ RFC 9110 §4.2.3) normalization, and §5.2
    /// resolution against the §5.4 example base. Contract: never
    /// panics; a strictly-parsed reference recomposes byte-identically;
    /// the normal form of a strictly-valid reference is itself strictly
    /// valid and a normalization fixpoint.
    pub fn uri_reference(s: &str) -> bool {
        let Ok(u) = crate::uri::UriRef::parse(s) else {
            return false;
        };
        assert_eq!(u.to_string(), s, "§5.3 recomposition round-trip");
        let n = u.normalized();
        let reparsed = crate::uri::UriRef::parse(&n).expect("normal form must stay in-grammar");
        assert_eq!(reparsed.normalized(), n, "normalization fixpoint");
        let base = crate::uri::UriRef::parse("http://a/b/c/d;p?q").expect("static base");
        if let Ok(t) = base.resolve(&u) {
            let _ = t.to_string();
            let _ = t.normalized();
            let _ = t.without_fragment();
        }
        true
    }

    /// Fuzz-only wrapper for [`crate::uri`]'s lenient path (the
    /// caller-URI posture: structural checks only). Contract: never
    /// panics; an accepted reference recomposes byte-identically and
    /// its authority splits without panicking.
    pub fn uri_reference_lenient(s: &str) -> bool {
        let Ok(u) = crate::uri::UriRef::parse_lenient(s) else {
            return false;
        };
        assert_eq!(u.to_string(), s, "§5.3 recomposition round-trip");
        let _ = u.authority_parts();
        let _ = u.normalized();
        let _ = u.without_fragment();
        true
    }

    /// Fuzz-only wrapper for RFC 3986 §5.2 reference resolution with a
    /// fuzzer-chosen base: both sides strict-parsed, resolution (when
    /// the base is absolute) must not panic and its output must
    /// recompose and normalize without panicking.
    pub fn uri_resolve(base: &str, reference: &str) {
        let (Ok(b), Ok(r)) = (
            crate::uri::UriRef::parse(base),
            crate::uri::UriRef::parse(reference),
        ) else {
            return;
        };
        if let Ok(t) = b.resolve(&r) {
            let _ = t.to_string();
            let _ = t.normalized();
        }
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
        assert!(c.follow_redirects());
        assert_eq!(c.max_redirects(), 10);
        assert!(c.max_redirects_will_error());
        assert_eq!(c.redirect_auth_policy(), RedirectAuthPolicy::Never);
        assert_eq!(c.redirect_scheme_policy(), RedirectSchemePolicy::Any);
        assert!(!c.redirect_same_host_only());
        assert_eq!(c.user_agent(), None);
        assert!(!c.https_only());
        assert_eq!(c.timeout_global(), None);
        assert_eq!(c.timeout_connect(), None);
        assert_eq!(c.read_retries(), 2);
        assert_eq!(c.seek_drain_max(), 64 * 1024);
        assert!(!c.range_probe());
    }

    #[test]
    fn http_config_builder_threads_values_through() {
        let c = HttpConfig::builder()
            .follow_redirects(false)
            .max_redirects(3)
            .max_redirects_will_error(false)
            .redirect_auth_policy(RedirectAuthPolicy::SameHost)
            .redirect_scheme_policy(RedirectSchemePolicy::Same)
            .redirect_same_host_only(true)
            .user_agent("oxideav-test/0.0")
            .https_only(true)
            .timeout_global(Some(Duration::from_secs(30)))
            .timeout_connect(Some(Duration::from_secs(5)))
            .read_retries(7)
            .seek_drain_max(123)
            .range_probe(true)
            .build();
        assert!(!c.follow_redirects());
        assert_eq!(c.max_redirects(), 3);
        assert!(!c.max_redirects_will_error());
        assert_eq!(c.redirect_auth_policy(), RedirectAuthPolicy::SameHost);
        assert_eq!(c.redirect_scheme_policy(), RedirectSchemePolicy::Same);
        assert!(c.redirect_same_host_only());
        assert_eq!(c.user_agent(), Some("oxideav-test/0.0"));
        assert!(c.https_only());
        assert_eq!(c.timeout_global(), Some(Duration::from_secs(30)));
        assert_eq!(c.timeout_connect(), Some(Duration::from_secs(5)));
        assert_eq!(c.read_retries(), 7);
        assert_eq!(c.seek_drain_max(), 123);
        assert!(c.range_probe());
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

    /// Spawn a minimal HTTP/1.1 server that serves one scripted
    /// response per accepted connection, in order, then stops
    /// accepting. Each raw request head is logged on the returned
    /// channel so tests can assert on request COUNT (no request
    /// storms, no redundant range GETs) and request CONTENT (Range /
    /// If-Range field values). Every scripted response should carry
    /// `Connection: close` so the client opens a fresh connection per
    /// request and the per-connection script stays aligned.
    fn spawn_script_server(responses: Vec<Vec<u8>>) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel::<String>();
        thread::spawn(move || {
            for resp in responses {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut buf = [0u8; 4096];
                use std::io::Read as _;
                let n = stream.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    continue;
                }
                let _ = tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
                let _ = stream.write_all(&resp);
                let _ = stream.flush();
                // Dropping the stream closes the connection — the
                // close-delimited responses in these tests rely on it
                // as their end-of-body marker (RFC 9112 §6.3 option 8).
            }
        });
        (format!("http://127.0.0.1:{port}/x"), rx)
    }

    // -- RFC 9110 §15.3.7 span accounting on the read path -------------------

    #[test]
    fn local_server_partial_206_reissues_for_remainder() {
        // §15.3.7: "A server ... might want to send only a subset of
        // the data requested"; "the client can still understand a
        // response that only partially satisfies its range request"
        // and §14.2 expects it to "re-request the remaining portions
        // later". We ask bytes=0-, the server sends only 0-4/10; the
        // driver must consume exactly that span and follow up with
        // bytes=5-.
        let (uri, reqs) = spawn_script_server(vec![
            HEAD_10B_BYTES.to_vec(),
            make_get_206("bytes 0-4/10", b"01234"),
            make_get_206("bytes 5-9/10", b"56789"),
        ]);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        assert_eq!(&buf, b"0123456789");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 3, "expected HEAD + 2 GETs, got {log:#?}");
        assert!(
            log[2].to_ascii_lowercase().contains("range: bytes=5-"),
            "follow-up GET must resume at the span boundary: {:?}",
            log[2]
        );
    }

    #[test]
    fn local_server_close_framed_206_stops_at_declared_span() {
        // A close-delimited 206 (no Content-Length — RFC 9112 §6.3
        // option 8) whose connection carries junk beyond the declared
        // Content-Range span. §15.3.7 makes the 206 self-descriptive:
        // the span is the truth, not the transport framing. The junk
        // must never reach the reader; the driver re-requests the
        // remainder instead.
        let mut get1 = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Range: bytes 0-4/10\r\n\
            Connection: close\r\n\
            \r\n"
            .to_vec();
        get1.extend_from_slice(b"01234JUNKJUNKJUNK");
        let (uri, reqs) = spawn_script_server(vec![
            HEAD_10B_BYTES.to_vec(),
            get1,
            make_get_206("bytes 5-9/10", b"56789"),
        ]);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        assert_eq!(&buf, b"0123456789");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 3, "expected HEAD + 2 GETs, got {log:#?}");
    }

    #[test]
    fn local_server_truncated_206_body_is_unexpected_eof() {
        // Close-delimited 206 declaring bytes 0-9/10 but delivering
        // only 4 body bytes before the connection closes. §8.6 makes
        // the declared span part of the message's self-description —
        // EOF before the span is delivered is a truncated message, not
        // a clean end-of-body. Resume disabled (`read_retries(0)`) so
        // the FIRST truncation must surface as the error.
        let mut get = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Range: bytes 0-9/10\r\n\
            Connection: close\r\n\
            \r\n"
            .to_vec();
        get.extend_from_slice(b"0123");
        let (uri, reqs) = spawn_script_server(vec![HEAD_10B_BYTES.to_vec(), get]);
        let cfg = HttpConfig::builder().read_retries(0).build();
        let mut src = HttpSource::open_with_config(&uri, &cfg).expect("open");
        let mut buf = [0u8; 10];
        let err = std::io::Read::read_exact(&mut src, &mut buf).unwrap_err();
        assert_eq!(
            err.kind(),
            io::ErrorKind::UnexpectedEof,
            "wrong kind: {err}"
        );
        assert!(err.to_string().contains("truncated"), "wrong error: {err}");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(
            log.len(),
            2,
            "read_retries(0) must not re-issue the range: {log:#?}"
        );
    }

    #[test]
    fn local_server_empty_206_body_errors_without_request_storm() {
        // A server that repeatedly answers a valid 206 header block
        // followed by an immediately-closed, empty body used to spin
        // the read loop into an unbounded GET storm (re-issue on EOF,
        // zero forward progress each time). With the default resume
        // budget of 2 (§14.2 recovery), the read must give up after
        // exactly 1 + 2 ranged GETs and surface one truncation error.
        let empty_206 = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Range: bytes 0-9/10\r\n\
            Connection: close\r\n\
            \r\n"
            .to_vec();
        let (uri, reqs) = spawn_script_server(vec![
            HEAD_10B_BYTES.to_vec(),
            empty_206.clone(),
            empty_206.clone(),
            empty_206.clone(),
            empty_206,
        ]);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        let err = std::io::Read::read_exact(&mut src, &mut buf).unwrap_err();
        assert_eq!(
            err.kind(),
            io::ErrorKind::UnexpectedEof,
            "wrong kind: {err}"
        );
        assert!(
            err.to_string().contains("after 2 transparent re-request"),
            "error must name the exhausted budget: {err}"
        );
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(
            log.len(),
            4,
            "expected HEAD + initial GET + 2 resume GETs, got {log:#?}"
        );
    }

    // -- RFC 9110 §14.2 transparent resume after transport drops -------------

    const HEAD_10B_BYTES_ETAG: &[u8] = b"HTTP/1.1 200 OK\r\n\
        Content-Length: 10\r\n\
        Accept-Ranges: bytes\r\n\
        ETag: \"v1\"\r\n\
        Connection: close\r\n\
        \r\n";

    /// A close-delimited 206 covering `bytes 0-9/10` that delivers only
    /// the first 4 body bytes before the connection closes.
    fn truncated_206_prefix() -> Vec<u8> {
        let mut get = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Range: bytes 0-9/10\r\n\
            Connection: close\r\n\
            \r\n"
            .to_vec();
        get.extend_from_slice(b"0123");
        get
    }

    #[test]
    fn local_server_resume_after_truncation_completes_read() {
        // §14.2: byte ranges "support efficient recovery from
        // partially failed transfers". The first GET is truncated
        // after 4 of 10 declared bytes; the driver must re-request
        // `bytes=4-` and splice the remainder seamlessly.
        let (uri, reqs) = spawn_script_server(vec![
            HEAD_10B_BYTES.to_vec(),
            truncated_206_prefix(),
            make_get_206("bytes 4-9/10", b"456789"),
        ]);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        assert_eq!(&buf, b"0123456789");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 3, "expected HEAD + 2 GETs, got {log:#?}");
        assert!(
            log[2].to_ascii_lowercase().contains("range: bytes=4-"),
            "resume GET must start at the truncation point: {:?}",
            log[2]
        );
    }

    #[test]
    fn local_server_resume_carries_if_range_validator() {
        // §13.1.5: the resume GET must carry the strong validator
        // captured at HEAD so a representation mutated between the
        // drop and the resume cannot be silently spliced onto the
        // bytes already delivered.
        let (uri, reqs) = spawn_script_server(vec![
            HEAD_10B_BYTES_ETAG.to_vec(),
            truncated_206_prefix(),
            make_get_206("bytes 4-9/10", b"456789"),
        ]);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        assert_eq!(&buf, b"0123456789");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 3, "expected HEAD + 2 GETs, got {log:#?}");
        assert!(
            log[2].to_ascii_lowercase().contains("if-range: \"v1\""),
            "resume GET must carry If-Range: {:?}",
            log[2]
        );
    }

    #[test]
    fn local_server_mutation_during_resume_is_fatal() {
        // The §13.1.5 guard in action across a resume: the server
        // answers the resume GET (which carries If-Range) with a 200 —
        // meaning the validator no longer matches and the
        // representation was replaced mid-stream. Splicing the new
        // bytes after the 4 old ones would hand the demuxer a chimera;
        // the driver must fail loudly instead, and must NOT spend
        // further resume budget on a non-transport error.
        static GET_200_NEW: &[u8] = b"HTTP/1.1 200 OK\r\n\
            Content-Length: 10\r\n\
            Connection: close\r\n\
            \r\n\
            ABCDEFGHIJ";
        let (uri, reqs) = spawn_script_server(vec![
            HEAD_10B_BYTES_ETAG.to_vec(),
            truncated_206_prefix(),
            GET_200_NEW.to_vec(),
        ]);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        let err = std::io::Read::read_exact(&mut src, &mut buf).unwrap_err();
        assert!(
            err.to_string().contains("If-Range validator did not match"),
            "wrong error: {err}"
        );
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(
            log.len(),
            3,
            "a §13.1.5 mutation is fatal, not retryable: {log:#?}"
        );
    }

    #[test]
    fn local_server_resume_after_content_length_framed_drop() {
        // Same drop, but the truncated response is Content-Length
        // framed (RFC 9112 §6.3 option 5): the transport layer itself
        // notices the short body and surfaces an error rather than a
        // clean EOF. That error is transport-shaped, so the §14.2
        // resume path must treat it exactly like the close-framed
        // truncation and re-request `bytes=4-`.
        let mut get1 = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Length: 10\r\n\
            Content-Range: bytes 0-9/10\r\n\
            Connection: close\r\n\
            \r\n"
            .to_vec();
        get1.extend_from_slice(b"0123");
        let (uri, reqs) = spawn_script_server(vec![
            HEAD_10B_BYTES.to_vec(),
            get1,
            make_get_206("bytes 4-9/10", b"456789"),
        ]);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        assert_eq!(&buf, b"0123456789");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 3, "expected HEAD + 2 GETs, got {log:#?}");
    }

    // -- Forward-seek drain over the live body --------------------------------

    #[test]
    fn local_server_small_forward_seek_drains_live_body() {
        // Read 2 bytes, hop forward 3 (well under the 64 KiB default
        // drain cap), read the rest. The hop must be satisfied by
        // draining the live body — exactly ONE ranged GET on the wire.
        let (uri, reqs) = spawn_script_server(vec![
            HEAD_10B_BYTES.to_vec(),
            make_get_206("bytes 0-9/10", b"0123456789"),
        ]);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut two = [0u8; 2];
        std::io::Read::read_exact(&mut src, &mut two).expect("read prefix");
        assert_eq!(&two, b"01");
        std::io::Seek::seek(&mut src, SeekFrom::Current(3)).expect("seek");
        let mut rest = [0u8; 5];
        std::io::Read::read_exact(&mut src, &mut rest).expect("read rest");
        assert_eq!(&rest, b"56789");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(
            log.len(),
            2,
            "forward hop within the drain cap must not re-issue: {log:#?}"
        );
    }

    #[test]
    fn local_server_forward_seek_beyond_drain_cap_reissues() {
        // With the cap tightened to 2 bytes, a 6-byte hop must drop
        // the body and issue a fresh range GET at the target position.
        let (uri, reqs) = spawn_script_server(vec![
            HEAD_10B_BYTES.to_vec(),
            make_get_206("bytes 0-9/10", b"0123456789"),
            make_get_206("bytes 8-9/10", b"89"),
        ]);
        let cfg = HttpConfig::builder().seek_drain_max(2).build();
        let mut src = HttpSource::open_with_config(&uri, &cfg).expect("open");
        let mut two = [0u8; 2];
        std::io::Read::read_exact(&mut src, &mut two).expect("read prefix");
        std::io::Seek::seek(&mut src, SeekFrom::Start(8)).expect("seek");
        let mut rest = [0u8; 2];
        std::io::Read::read_exact(&mut src, &mut rest).expect("read rest");
        assert_eq!(&rest, b"89");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 3, "expected HEAD + 2 GETs, got {log:#?}");
        assert!(
            log[2].to_ascii_lowercase().contains("range: bytes=8-"),
            "re-issue must target the seek destination: {:?}",
            log[2]
        );
    }

    #[test]
    fn local_server_backward_seek_always_reissues() {
        // Bytes already consumed are gone — a backward seek can never
        // drain and must issue a fresh range GET at the target.
        let (uri, reqs) = spawn_script_server(vec![
            HEAD_10B_BYTES.to_vec(),
            make_get_206("bytes 0-9/10", b"0123456789"),
            make_get_206("bytes 1-9/10", b"123456789"),
        ]);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut five = [0u8; 5];
        std::io::Read::read_exact(&mut src, &mut five).expect("read prefix");
        std::io::Seek::seek(&mut src, SeekFrom::Start(1)).expect("seek");
        std::io::Read::read_exact(&mut src, &mut five).expect("re-read");
        assert_eq!(&five, b"12345");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 3, "expected HEAD + 2 GETs, got {log:#?}");
        assert!(
            log[2].to_ascii_lowercase().contains("range: bytes=1-"),
            "re-issue must target the seek destination: {:?}",
            log[2]
        );
    }

    #[test]
    fn local_server_forward_seek_never_drains_past_declared_span() {
        // The live body only covers bytes 0-4 (partial 206, §15.3.7);
        // a hop to byte 6 exceeds its remaining span even though it is
        // far below the drain cap. Bytes beyond the span were never
        // promised — the driver must re-issue at the target instead of
        // blocking on a drain the body cannot satisfy.
        let (uri, reqs) = spawn_script_server(vec![
            HEAD_10B_BYTES.to_vec(),
            make_get_206("bytes 0-4/10", b"01234"),
            make_get_206("bytes 6-9/10", b"6789"),
        ]);
        let mut src = HttpSource::open(&uri).expect("open");
        // Materialise the partial body (span 0-4) by consuming byte 0.
        let mut one = [0u8; 1];
        std::io::Read::read_exact(&mut src, &mut one).expect("read byte 0");
        assert_eq!(&one, b"0");
        // Hop to 6: delta 5 exceeds the body's remaining span of 4.
        std::io::Seek::seek(&mut src, SeekFrom::Start(6)).expect("seek");
        let mut rest = [0u8; 4];
        std::io::Read::read_exact(&mut src, &mut rest).expect("read");
        assert_eq!(&rest, b"6789");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 3, "expected HEAD + 2 GETs, got {log:#?}");
        assert!(
            log[2].to_ascii_lowercase().contains("range: bytes=6-"),
            "re-issue must target the seek destination: {:?}",
            log[2]
        );
    }

    #[test]
    fn local_server_drain_hitting_truncated_body_falls_back_to_reissue() {
        // The body declares bytes 0-9/10 but the connection dies after
        // 2 body bytes. A 3-byte forward hop starts draining, hits the
        // truncation, and must fall back to a fresh range GET at the
        // seek target — seek itself never errors on a transport fault.
        let mut get1 = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Range: bytes 0-9/10\r\n\
            Connection: close\r\n\
            \r\n"
            .to_vec();
        get1.extend_from_slice(b"01");
        let (uri, reqs) = spawn_script_server(vec![
            HEAD_10B_BYTES.to_vec(),
            get1,
            make_get_206("bytes 3-9/10", b"3456789"),
        ]);
        let mut src = HttpSource::open(&uri).expect("open");
        // Materialise the body without consuming it past byte 0.
        let mut one = [0u8; 1];
        std::io::Read::read_exact(&mut src, &mut one).expect("read");
        assert_eq!(&one, b"0");
        std::io::Seek::seek(&mut src, SeekFrom::Start(3)).expect("seek");
        let mut rest = [0u8; 7];
        std::io::Read::read_exact(&mut src, &mut rest).expect("read rest");
        assert_eq!(&rest, b"3456789");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 3, "expected HEAD + 2 GETs, got {log:#?}");
    }

    // -- RFC 9112 §7.1 chunked framing composed with the driver --------------
    //
    // The transport layer owns dechunking; these tests pin that every
    // driver invariant (span accounting, prefix drain, §14.2 resume,
    // storm bounds) composes correctly with chunked-framed responses,
    // including the §7.1.1 extension and §7.1.2 trailer constructs and
    // the §8 incomplete-body rule.

    #[test]
    fn local_server_chunked_206_with_extensions_and_trailer() {
        // §7.1.1: "A recipient MUST ignore unrecognized chunk
        // extensions"; §7.1.2 allows a trailer section. Neither may
        // leak into the byte stream or disturb the span accounting.
        static GET: &[u8] = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Range: bytes 0-9/10\r\n\
            Transfer-Encoding: chunked\r\n\
            Connection: close\r\n\
            \r\n\
            4;sig=abc\r\n\
            0123\r\n\
            6\r\n\
            456789\r\n\
            0\r\n\
            x-check: ok\r\n\
            \r\n";
        let (uri, reqs) = spawn_script_server(vec![HEAD_10B_BYTES.to_vec(), GET.to_vec()]);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        assert_eq!(&buf, b"0123456789");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 2, "expected HEAD + 1 GET, got {log:#?}");
    }

    #[test]
    fn local_server_chunked_206_incomplete_body_resumes() {
        // RFC 9112 §8: "A message body that uses the chunked transfer
        // coding is incomplete if the zero-sized chunk that terminates
        // the encoding has not been received." The dechunker surfaces
        // that as a transport fault; the §14.2 resume path must
        // re-request bytes=4- and splice.
        static GET1: &[u8] = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Range: bytes 0-9/10\r\n\
            Transfer-Encoding: chunked\r\n\
            Connection: close\r\n\
            \r\n\
            4\r\n\
            0123\r\n";
        let (uri, reqs) = spawn_script_server(vec![
            HEAD_10B_BYTES.to_vec(),
            GET1.to_vec(),
            make_get_206("bytes 4-9/10", b"456789"),
        ]);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        assert_eq!(&buf, b"0123456789");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 3, "expected HEAD + 2 GETs, got {log:#?}");
        assert!(
            log[2].to_ascii_lowercase().contains("range: bytes=4-"),
            "resume must start at the incomplete-body point: {:?}",
            log[2]
        );
    }

    #[test]
    fn local_server_chunked_200_fallback_prefix_drain() {
        // A range-ignoring server (RFC 7233 §3.1 200 fallback) that
        // also frames with chunked: the prefix drain must operate on
        // the DECODED bytes.
        static GET: &[u8] = b"HTTP/1.1 200 OK\r\n\
            Transfer-Encoding: chunked\r\n\
            Connection: close\r\n\
            \r\n\
            a\r\n\
            0123456789\r\n\
            0\r\n\
            \r\n";
        let (uri, _reqs) = spawn_script_server(vec![HEAD_10B_BYTES.to_vec(), GET.to_vec()]);
        let mut src = HttpSource::open(&uri).expect("open");
        std::io::Seek::seek(&mut src, SeekFrom::Start(4)).expect("seek");
        let mut buf = [0u8; 6];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        assert_eq!(&buf, b"456789");
    }

    #[test]
    fn local_server_chunked_206_excess_decoded_bytes_stop_at_span() {
        // Chunked framing carries 16 decoded bytes but Content-Range
        // declares a 10-byte span. §15.3.7 makes the 206
        // self-descriptive — the 6 excess bytes must never reach the
        // reader.
        static GET: &[u8] = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Range: bytes 0-9/10\r\n\
            Transfer-Encoding: chunked\r\n\
            Connection: close\r\n\
            \r\n\
            10\r\n\
            0123456789ABCDEF\r\n\
            0\r\n\
            \r\n";
        let (uri, _reqs) = spawn_script_server(vec![HEAD_10B_BYTES.to_vec(), GET.to_vec()]);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut src, &mut buf).expect("read");
        assert_eq!(buf, b"0123456789");
    }

    #[test]
    fn local_server_hostile_chunk_size_errors_without_storm() {
        // §7.1: "recipients MUST anticipate potentially large
        // hexadecimal numerals and prevent parsing errors due to
        // integer conversion overflows". The transport layer rejects
        // the 17-hex-digit chunk size; the driver must surface an
        // error with a BOUNDED number of requests (a transient-classed
        // fault may consume the resume budget, but never more).
        static GET: &[u8] = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Range: bytes 0-9/10\r\n\
            Transfer-Encoding: chunked\r\n\
            Connection: close\r\n\
            \r\n\
            FFFFFFFFFFFFFFFF1\r\n\
            junk";
        let (uri, reqs) = spawn_script_server(vec![
            HEAD_10B_BYTES.to_vec(),
            GET.to_vec(),
            GET.to_vec(),
            GET.to_vec(),
        ]);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        let err = std::io::Read::read_exact(&mut src, &mut buf).unwrap_err();
        let log: Vec<String> = reqs.try_iter().collect();
        assert!(
            (2..=4).contains(&log.len()),
            "bounded requests required (got {} — {err}): {log:#?}",
            log.len()
        );
    }

    // -- EOF / bounds edges: no wasted wire ----------------------------------

    const HEAD_0B_BYTES: &[u8] = b"HTTP/1.1 200 OK\r\n\
        Content-Length: 0\r\n\
        Accept-Ranges: bytes\r\n\
        Connection: close\r\n\
        \r\n";

    #[test]
    fn local_server_zero_length_resource_reads_eof_without_get() {
        // A zero-length representation admits no satisfiable
        // `bytes=N-` range at all (RFC 9110 §14.1.2), so the driver
        // must answer every read with EOF from the HEAD metadata alone
        // — issuing a range GET would only harvest a 416.
        let (uri, reqs) = spawn_script_server(vec![HEAD_0B_BYTES.to_vec()]);
        let mut src = HttpSource::open(&uri).expect("open");
        assert_eq!(src.len(), 0);
        assert!(src.is_empty());
        let mut buf = [0u8; 8];
        assert_eq!(std::io::Read::read(&mut src, &mut buf).expect("read"), 0);
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 1, "EOF must not touch the wire: {log:#?}");
    }

    #[test]
    fn local_server_seek_to_end_and_past_end_edges() {
        // SeekFrom::End(0) positions at EOF: reads yield 0 without a
        // request. Seeking past the HEAD-observed total is refused
        // client-side (InvalidInput), again without a request.
        let (uri, reqs) = spawn_script_server(vec![HEAD_10B_BYTES.to_vec()]);
        let mut src = HttpSource::open(&uri).expect("open");
        assert_eq!(
            std::io::Seek::seek(&mut src, SeekFrom::End(0)).expect("seek"),
            10
        );
        let mut buf = [0u8; 4];
        assert_eq!(std::io::Read::read(&mut src, &mut buf).expect("read"), 0);
        let err = std::io::Seek::seek(&mut src, SeekFrom::Start(11))
            .expect_err("expected seek past end to fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "wrong kind: {err}");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 1, "EOF/bounds handling is wire-free: {log:#?}");
    }

    #[test]
    fn local_server_empty_read_buffer_touches_no_wire() {
        let (uri, reqs) = spawn_script_server(vec![HEAD_10B_BYTES.to_vec()]);
        let mut src = HttpSource::open(&uri).expect("open");
        assert_eq!(std::io::Read::read(&mut src, &mut []).expect("read"), 0);
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 1, "empty buffer must not open a body: {log:#?}");
    }

    #[test]
    fn local_server_consecutive_drain_hops_share_one_get() {
        // Demuxer-shaped access: read a header byte, skip a payload,
        // repeat. Every hop fits the drain cap and the live span, so
        // the whole walk must ride ONE ranged GET.
        let (uri, reqs) = spawn_script_server(vec![
            HEAD_10B_BYTES.to_vec(),
            make_get_206("bytes 0-9/10", b"0123456789"),
        ]);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut one = [0u8; 1];
        for expected in *b"036" {
            std::io::Read::read_exact(&mut src, &mut one).expect("read");
            assert_eq!(one[0], expected);
            std::io::Seek::seek(&mut src, SeekFrom::Current(2)).expect("seek");
        }
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 2, "hop-walk must share one GET: {log:#?}");
    }

    // -- GET range-probe fallback (§15.5.6 / §15.6.2 / §9.3.2 / §14.3) -------

    const HEAD_405: &[u8] = b"HTTP/1.1 405 Method Not Allowed\r\n\
        Allow: GET\r\n\
        Content-Length: 0\r\n\
        Connection: close\r\n\
        \r\n";

    fn probe_cfg() -> HttpConfig {
        HttpConfig::builder().range_probe(true).build()
    }

    #[test]
    fn probe_disabled_head_405_stays_fatal() {
        // Default config: no probing — a HEAD-hostile server is
        // refused at open exactly as before, after a single request.
        let (uri, reqs) = spawn_script_server(vec![HEAD_405.to_vec()]);
        let err = HttpSource::open(&uri).err().expect("expected open to fail");
        assert!(err.to_string().contains("status 405"), "wrong error: {err}");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 1, "no probe without the opt-in: {log:#?}");
    }

    #[test]
    fn probe_after_head_405_learns_total_and_reuses_body() {
        // §15.5.6: a 405 says the METHOD is unsupported, nothing about
        // range support. The probe's 206 carries the complete-length
        // (§14.4) and its body doubles as the initial read stream — so
        // the whole open + full read costs exactly 2 requests.
        let (uri, reqs) = spawn_script_server(vec![
            HEAD_405.to_vec(),
            make_get_206("bytes 0-9/10", b"0123456789"),
        ]);
        let mut src = HttpSource::open_with_config(&uri, &probe_cfg()).expect("open");
        assert_eq!(src.len(), 10);
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        assert_eq!(&buf, b"0123456789");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 2, "probe body must be reused: {log:#?}");
        assert!(
            log[1].to_ascii_lowercase().contains("range: bytes=0-"),
            "probe must be a ranged GET: {:?}",
            log[1]
        );
    }

    #[test]
    fn probe_after_head_without_content_length() {
        // §9.3.2: "a server MAY omit header fields for which a value
        // is determined only while generating the content" — its
        // worked example names Content-Length on HEAD. The probe's
        // Content-Range supplies the total instead.
        static HEAD_NO_CL: &[u8] = b"HTTP/1.1 200 OK\r\n\
            Accept-Ranges: bytes\r\n\
            Connection: close\r\n\
            \r\n";
        let (uri, reqs) = spawn_script_server(vec![
            HEAD_NO_CL.to_vec(),
            make_get_206("bytes 0-9/10", b"0123456789"),
        ]);
        let mut src = HttpSource::open_with_config(&uri, &probe_cfg()).expect("open");
        assert_eq!(src.len(), 10);
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        assert_eq!(&buf, b"0123456789");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 2, "expected HEAD + probe GET, got {log:#?}");
    }

    #[test]
    fn probe_after_absent_accept_ranges_cross_checks_head_total() {
        // §14.3: "A client MAY generate range requests regardless of
        // having received an Accept-Ranges field." HEAD measured 10
        // bytes; the probe's complete-length must agree.
        static HEAD_NO_AR: &[u8] = b"HTTP/1.1 200 OK\r\n\
            Content-Length: 10\r\n\
            Connection: close\r\n\
            \r\n";
        let (uri, _reqs) = spawn_script_server(vec![
            HEAD_NO_AR.to_vec(),
            make_get_206("bytes 0-9/10", b"0123456789"),
        ]);
        let mut src = HttpSource::open_with_config(&uri, &probe_cfg()).expect("open");
        assert_eq!(src.len(), 10);
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        assert_eq!(&buf, b"0123456789");

        // Disagreement is a §8.6 violation — refuse.
        let (uri2, _reqs2) = spawn_script_server(vec![
            HEAD_NO_AR.to_vec(),
            make_get_206("bytes 0-19/20", b"0123456789abcdefghij"),
        ]);
        let err = HttpSource::open_with_config(&uri2, &probe_cfg())
            .err()
            .expect("expected open to fail");
        assert!(
            err.to_string().contains("complete-length 20"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn probe_200_answer_is_unsupported() {
        // §14.2: "A server MAY ignore the Range header field." A 200
        // to the probe means it did — the resource is readable but not
        // seekable, so the driver refuses it.
        static GET_200: &[u8] = b"HTTP/1.1 200 OK\r\n\
            Content-Length: 10\r\n\
            Connection: close\r\n\
            \r\n\
            0123456789";
        let (uri, _reqs) = spawn_script_server(vec![HEAD_405.to_vec(), GET_200.to_vec()]);
        let err = HttpSource::open_with_config(&uri, &probe_cfg())
            .err()
            .expect("expected open to fail");
        assert!(err.to_string().contains("ignored"), "wrong error: {err}");
    }

    #[test]
    fn probe_star_complete_without_head_total_is_unsupported() {
        // §14.4 permits `*` for an unknown complete-length, but with
        // no successful HEAD either, nothing authoritative anchors
        // SeekFrom::End — refuse rather than guess.
        let (uri, _reqs) = spawn_script_server(vec![
            HEAD_405.to_vec(),
            make_get_206("bytes 0-9/*", b"0123456789"),
        ]);
        let err = HttpSource::open_with_config(&uri, &probe_cfg())
            .err()
            .expect("expected open to fail");
        assert!(
            err.to_string().contains("complete-length is '*'"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn probe_star_complete_with_head_total_is_accepted() {
        // HEAD succeeded (10 bytes) but omitted Accept-Ranges; the
        // probe 206 uses the `*` form. The HEAD measurement anchors
        // the total.
        static HEAD_NO_AR: &[u8] = b"HTTP/1.1 200 OK\r\n\
            Content-Length: 10\r\n\
            Connection: close\r\n\
            \r\n";
        let (uri, _reqs) = spawn_script_server(vec![
            HEAD_NO_AR.to_vec(),
            make_get_206("bytes 0-9/*", b"0123456789"),
        ]);
        let mut src = HttpSource::open_with_config(&uri, &probe_cfg()).expect("open");
        assert_eq!(src.len(), 10);
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        assert_eq!(&buf, b"0123456789");
    }

    #[test]
    fn probe_416_zero_complete_is_empty_source() {
        // §14.1.2: "When a selected representation has zero length,
        // the only satisfiable form of range-spec in a GET request is
        // a suffix-range with a non-zero suffix-length" — so 416 with
        // `bytes */0` (§14.4) is range support working CORRECTLY on an
        // empty resource.
        static GET_416_EMPTY: &[u8] = b"HTTP/1.1 416 Range Not Satisfiable\r\n\
            Content-Range: bytes */0\r\n\
            Content-Length: 0\r\n\
            Connection: close\r\n\
            \r\n";
        let (uri, reqs) = spawn_script_server(vec![HEAD_405.to_vec(), GET_416_EMPTY.to_vec()]);
        let mut src = HttpSource::open_with_config(&uri, &probe_cfg()).expect("open");
        assert_eq!(src.len(), 0);
        assert!(src.is_empty());
        let mut buf = [0u8; 4];
        let n = std::io::Read::read(&mut src, &mut buf).expect("read");
        assert_eq!(n, 0, "empty resource reads as immediate EOF");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 2, "EOF must not touch the wire: {log:#?}");
    }

    #[test]
    fn probe_416_nonzero_complete_is_error() {
        // A 416 claiming complete-length 5 contradicts itself:
        // first-pos 0 is satisfiable against any non-empty
        // representation (§14.1.2).
        static GET_416_5: &[u8] = b"HTTP/1.1 416 Range Not Satisfiable\r\n\
            Content-Range: bytes */5\r\n\
            Content-Length: 0\r\n\
            Connection: close\r\n\
            \r\n";
        let (uri, _reqs) = spawn_script_server(vec![HEAD_405.to_vec(), GET_416_5.to_vec()]);
        let err = HttpSource::open_with_config(&uri, &probe_cfg())
            .err()
            .expect("expected open to fail");
        assert!(
            err.to_string().contains("satisfiable"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn probe_503_surfaces_retry_after_hint() {
        // The probe's non-success path shares the HEAD path's RFC 9110
        // §10.2.3 Retry-After surfacing, so a caller wiring back-off
        // gets the parsed delay without re-fishing the header.
        static GET_503: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
            Retry-After: 120\r\n\
            Content-Length: 0\r\n\
            Connection: close\r\n\
            \r\n";
        let (uri, _reqs) = spawn_script_server(vec![HEAD_405.to_vec(), GET_503.to_vec()]);
        let err = HttpSource::open_with_config(&uri, &probe_cfg())
            .err()
            .expect("expected open to fail");
        let msg = err.to_string();
        assert!(msg.contains("status 503"), "wrong error: {msg}");
        assert!(
            msg.contains("(Retry-After: 120 s)"),
            "missing §10.2.3 hint: {msg}"
        );
    }

    #[test]
    fn probe_captured_validator_guards_resume() {
        // The probe response's ETag must feed the same §13.1.5
        // machinery as a HEAD's: when the probe body is truncated, the
        // resume GET carries If-Range with the probe-captured
        // validator.
        let mut probe_206 = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Range: bytes 0-9/10\r\n\
            ETag: \"v1\"\r\n\
            Connection: close\r\n\
            \r\n"
            .to_vec();
        probe_206.extend_from_slice(b"0123");
        let (uri, reqs) = spawn_script_server(vec![
            HEAD_405.to_vec(),
            probe_206,
            make_get_206("bytes 4-9/10", b"456789"),
        ]);
        let mut src = HttpSource::open_with_config(&uri, &probe_cfg()).expect("open");
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        assert_eq!(&buf, b"0123456789");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 3, "expected HEAD + probe + resume, got {log:#?}");
        assert!(
            log[2].to_ascii_lowercase().contains("if-range: \"v1\""),
            "resume must carry the probe-captured validator: {:?}",
            log[2]
        );
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

    // -- RFC 9110 §12.5.5 Vary parser ----------------------------------------

    #[test]
    fn vary_absent_on_empty_or_whitespace() {
        // No usable members → Absent (no negotiation warning).
        assert_eq!(parse_vary(""), Vary::Absent);
        assert_eq!(parse_vary("   "), Vary::Absent);
        // §5.6.1 empty list members are dropped; all-empty → Absent.
        assert_eq!(parse_vary(",,,"), Vary::Absent);
        assert_eq!(parse_vary(" , , "), Vary::Absent);
    }

    #[test]
    fn vary_wildcard_bare_and_in_list() {
        // §12.5.5: "A list containing the member '*' signals that other
        // aspects of the request might have played a role..." — bare or
        // mixed, the value is the wildcard form.
        assert_eq!(parse_vary("*"), Vary::Wildcard);
        assert_eq!(parse_vary("Accept-Encoding, *"), Vary::Wildcard);
        assert_eq!(parse_vary("*, Accept-Language"), Vary::Wildcard);
        // OWS around the wildcard member is tolerated per §5.6.1.
        assert_eq!(parse_vary("  *  "), Vary::Wildcard);
    }

    #[test]
    fn vary_wildcard_short_circuits_past_garbage() {
        // Once `*` is seen, a later malformed member cannot downgrade
        // the classification away from the unsafe wildcard form.
        assert_eq!(parse_vary("*, foo bar"), Vary::Wildcard);
    }

    #[test]
    fn vary_field_names_are_lowercased_and_listed() {
        // §12.5.5 form 2: a list of selecting request field-names.
        // §5.1 field-names are case-insensitive → lowercased.
        match parse_vary("Accept-Encoding, Accept-Language") {
            Vary::Fields(v) => {
                assert_eq!(v, vec!["accept-encoding", "accept-language"]);
            }
            other => panic!("expected Fields, got {other:?}"),
        }
    }

    #[test]
    fn vary_non_token_members_are_skipped_not_fatal() {
        // A malformed slot (space inside a would-be token) must not
        // black-hole the legitimate field-name next to it — mirrors
        // the §5.6.2-token discipline in parse_accept_ranges.
        match parse_vary("accept-encoding, foo bar") {
            Vary::Fields(v) => assert_eq!(v, vec!["accept-encoding"]),
            other => panic!("expected Fields, got {other:?}"),
        }
        // A list of only garbage members falls through to Absent, not a
        // panic and not a spurious wildcard.
        assert_eq!(parse_vary("foo bar, baz qux"), Vary::Absent);
    }

    #[test]
    fn vary_quoted_star_is_a_field_name_not_wildcard() {
        // §12.5.5's wildcard member is the bare token `*`. A member that
        // merely contains `*` as part of a longer token (e.g. `x-*`) is
        // a (peculiar) field-name, not the wildcard form. `*` itself is
        // a valid §5.6.2 tchar, so `x-*` parses as a Fields member.
        match parse_vary("x-*") {
            Vary::Fields(v) => assert_eq!(v, vec!["x-*"]),
            other => panic!("expected Fields for x-*, got {other:?}"),
        }
    }

    // -- Content-Encoding (RFC 9110 §8.4 / §12.5.3) --------------------------

    #[test]
    fn content_codings_empty_and_absent_are_acceptable() {
        // No header value (or one that is all empty §5.6.1 list slots)
        // means no coding — the byte-offset model holds.
        assert!(non_identity_content_codings("").is_empty());
        assert!(non_identity_content_codings("   ").is_empty());
        assert!(non_identity_content_codings(",,,").is_empty());
    }

    #[test]
    fn content_codings_identity_is_tolerated_as_no_op() {
        // §12.5.3: identity is "a synonym for 'no encoding'". §8.4 says
        // it SHOULD NOT appear in Content-Encoding, but a server that
        // sends it anyway has not coded anything — tolerate, don't
        // reject.
        assert!(non_identity_content_codings("identity").is_empty());
        assert!(non_identity_content_codings("Identity").is_empty());
        assert!(non_identity_content_codings("identity, identity").is_empty());
    }

    #[test]
    fn content_codings_real_codings_are_reported_lowercased() {
        // §8.4.1: "All content codings are case-insensitive."
        assert_eq!(non_identity_content_codings("gzip"), ["gzip"]);
        assert_eq!(non_identity_content_codings("GZIP"), ["gzip"]);
        // §8.4.1.3 names x-gzip as a SHOULD-equivalent of gzip; the
        // driver decodes neither, so it is simply reported under its
        // own (lowercased) name.
        assert_eq!(non_identity_content_codings("x-gzip"), ["x-gzip"]);
        assert_eq!(non_identity_content_codings("compress"), ["compress"]);
        assert_eq!(non_identity_content_codings("deflate"), ["deflate"]);
    }

    #[test]
    fn content_codings_list_preserves_application_order() {
        // §8.4: the sender MUST list codings "in the order in which
        // they were applied" — preserve that order in the diagnostic.
        assert_eq!(
            non_identity_content_codings("gzip, deflate"),
            ["gzip", "deflate"]
        );
        // identity slots vanish; the real codings keep their order.
        assert_eq!(
            non_identity_content_codings("identity, gzip , identity, compress"),
            ["gzip", "compress"]
        );
        // §5.6.1 empty slots are dropped without eating neighbours.
        assert_eq!(non_identity_content_codings(",gzip,,"), ["gzip"]);
    }

    #[test]
    fn content_codings_non_token_garbage_is_kept_not_skipped() {
        // Opposite fail-direction from parse_accept_ranges: a coding
        // name we cannot even parse is still a transformation we
        // cannot undo, so it must surface in the rejection diagnostic
        // rather than be silently skipped (which would ACCEPT the
        // coded body).
        assert_eq!(non_identity_content_codings("gzip stream"), ["gzip stream"]);
        assert_eq!(non_identity_content_codings("identity, ???"), ["???"]);
    }

    #[test]
    fn local_server_head_with_content_encoding_gzip_is_unsupported() {
        // §8.4: representation metadata describes the coded form, so a
        // coded representation's Content-Length (and any byte range
        // against it) counts compressed bytes the demuxer cannot use.
        // The driver must refuse at open, naming the coding + cite.
        const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\n\
            Content-Length: 10\r\n\
            Accept-Ranges: bytes\r\n\
            Content-Encoding: gzip\r\n\
            Connection: close\r\n\
            \r\n";
        const GET: &[u8] = b"HTTP/1.1 200 OK\r\n\
            Content-Length: 10\r\n\
            Connection: close\r\n\
            \r\n\
            0123456789";
        let (uri, _done) = spawn_server(HEAD, GET);
        let err = match HttpSource::open(&uri) {
            Ok(_) => panic!("open must refuse a content-coded representation"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(msg.contains("gzip"), "missing coding name: {msg}");
        assert!(msg.contains("8.4"), "missing §8.4 cite: {msg}");
        assert!(
            matches!(err, Error::Unsupported(_)),
            "expected Unsupported, got: {err:?}"
        );
    }

    #[test]
    fn local_server_head_with_content_encoding_identity_is_accepted() {
        // §12.5.3 identity = "no encoding"; §8.4 SHOULD NOT send it,
        // but tolerating it costs nothing and the bytes are un-coded.
        const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\n\
            Content-Length: 10\r\n\
            Accept-Ranges: bytes\r\n\
            Content-Encoding: identity\r\n\
            Connection: close\r\n\
            \r\n";
        static GET: &[u8] = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Length: 10\r\n\
            Content-Range: bytes 0-9/10\r\n\
            Connection: close\r\n\
            \r\n\
            0123456789";
        let (uri, _done) = spawn_server(HEAD, GET);
        let mut src = HttpSource::open(&uri).expect("identity coding must be tolerated");
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        assert_eq!(&buf, b"0123456789");
    }

    #[test]
    fn local_server_206_with_content_encoding_gzip_is_rejected() {
        // The HEAD was clean but the GET came back coded — the server
        // ignored our `Accept-Encoding: identity`. The reader must
        // never see the coded bytes.
        static GET: &[u8] = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Length: 10\r\n\
            Content-Range: bytes 0-9/10\r\n\
            Content-Encoding: gzip\r\n\
            Connection: close\r\n\
            \r\n\
            0123456789";
        let (uri, _done) = spawn_server(HEAD_10B_BYTES, GET);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        let err = std::io::Read::read_exact(&mut src, &mut buf).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Content-Encoding"), "wrong error: {msg}");
        assert!(msg.contains("gzip"), "missing coding name: {msg}");
    }

    #[test]
    fn local_server_200_fallback_with_content_encoding_gzip_is_rejected() {
        // Same offence on the RFC 7233 §3.1 full-body fallback: the
        // §3.1 prefix drain counts representation bytes, which a
        // coding would silently redefine.
        static GET: &[u8] = b"HTTP/1.1 200 OK\r\n\
            Content-Length: 10\r\n\
            Content-Encoding: gzip\r\n\
            Connection: close\r\n\
            \r\n\
            0123456789";
        let (uri, _done) = spawn_server(HEAD_10B_BYTES, GET);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        let err = std::io::Read::read_exact(&mut src, &mut buf).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Content-Encoding"), "wrong error: {msg}");
    }

    #[test]
    fn local_server_get_request_carries_accept_encoding_identity() {
        // §12.5.3: the request side of the contract — every range GET
        // must list only `identity` so a conformant server never
        // applies a coding in the first place.
        static GET: &[u8] = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Length: 10\r\n\
            Content-Range: bytes 0-9/10\r\n\
            Connection: close\r\n\
            \r\n\
            0123456789";
        let (uri, captured) = spawn_server_capturing_get(HEAD_10B_BYTES, GET);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        let req = captured.recv().expect("captured GET request");
        let s = String::from_utf8_lossy(&req).to_ascii_lowercase();
        assert!(
            s.contains("accept-encoding: identity"),
            "GET did not carry Accept-Encoding: identity; got:\n{s}"
        );
    }

    #[test]
    fn local_server_head_request_carries_accept_encoding_identity() {
        // Same contract on the opening HEAD: the Content-Length we
        // record must be negotiated over the un-coded representation.
        static GET: &[u8] = b"HTTP/1.1 206 Partial Content\r\n\
            Content-Length: 10\r\n\
            Content-Range: bytes 0-9/10\r\n\
            Connection: close\r\n\
            \r\n\
            0123456789";
        let (uri, captured) = spawn_server_capturing_all(HEAD_10B_BYTES, GET);
        let _src = HttpSource::open(&uri).expect("open");
        let req = captured.recv().expect("captured HEAD request");
        let s = String::from_utf8_lossy(&req).to_ascii_lowercase();
        assert!(
            s.starts_with("head "),
            "first captured request not HEAD:\n{s}"
        );
        assert!(
            s.contains("accept-encoding: identity"),
            "HEAD did not carry Accept-Encoding: identity; got:\n{s}"
        );
    }

    /// Variant of `spawn_server` that captures EVERY request's bytes
    /// (HEAD and GET alike) so a test can inspect the opening HEAD.
    fn spawn_server_capturing_all(
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
                let _ = tx.send(req.to_vec());
                let resp = if req.starts_with(b"HEAD ") {
                    head_resp
                } else {
                    get_resp
                };
                let _ = stream.write_all(resp);
                let _ = stream.flush();
            }
        });
        (format!("http://127.0.0.1:{port}/x"), rx)
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
        let cr = *b"\"a\\\rb\"";
        assert!(unquote_string(std::str::from_utf8(&cr).unwrap()).is_none());
        let lf = *b"\"a\\\nb\"";
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

    // --- §5.6.5 comment -----------------------------------------------

    #[test]
    fn parse_comment_empty_decodes_to_empty_borrowed() {
        // §5.6.5 `comment = "(" *( … ) ")"` — an empty comment `()`
        // is well-formed and its logical text is the empty string. No
        // escapes ⇒ borrowed.
        let v = parse_comment("()").unwrap();
        assert_eq!(&*v, "");
        assert!(matches!(v, std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn parse_comment_escape_free_returns_cow_borrowed() {
        // A flat comment with only `ctext` returns a borrow of the
        // inner slice (zero allocation on the happy path).
        let v = parse_comment("(gzip is fine)").unwrap();
        assert_eq!(&*v, "gzip is fine");
        assert!(matches!(v, std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn parse_comment_nested_preserves_inner_parens() {
        // §5.6.5 recursion: `(a (b) c)` is ONE comment whose logical
        // text is `a (b) c` — only the outermost parens are stripped;
        // the inner pair is part of the content.
        let v = parse_comment("(a (b) c)").unwrap();
        assert_eq!(&*v, "a (b) c");
        // Deeper nesting balances correctly.
        let v = parse_comment("(x ((y)) z)").unwrap();
        assert_eq!(&*v, "x ((y)) z");
    }

    #[test]
    fn parse_comment_quoted_pair_collapsed_per_5_6_4() {
        // §5.6.5 admits `quoted-pair` inside a comment; §5.6.4's
        // `quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )` is
        // collapsed to the escaped octet. Here the escaped `(` and `)`
        // and `\` are literal text, not comment/escape syntax.
        let v = parse_comment("(a \\( b \\) c \\\\ d)").unwrap();
        assert_eq!(&*v, "a ( b ) c \\ d");
        assert!(matches!(v, std::borrow::Cow::Owned(_)));
    }

    #[test]
    fn parse_comment_user_agent_shape() {
        // The most common in-the-wild §5.6.5 comment is the parenthical
        // in a `User-Agent` / `Server` `product *( RWS comment )` value.
        let v = parse_comment("(Macintosh; Intel Mac OS X 10_15)").unwrap();
        assert_eq!(&*v, "Macintosh; Intel Mac OS X 10_15");
    }

    #[test]
    fn parse_comment_missing_outer_parens_rejected() {
        assert!(parse_comment("no parens").is_none());
        assert!(parse_comment("(unclosed").is_none());
        assert!(parse_comment("unopened)").is_none());
        // A single byte cannot carry both `(` and `)`.
        assert!(parse_comment("(").is_none());
        assert!(parse_comment(")").is_none());
        assert!(parse_comment("").is_none());
    }

    #[test]
    fn parse_comment_unbalanced_parens_rejected() {
        // One extra opener: depth never returns to zero.
        assert!(parse_comment("(a (b)").is_none());
        // A top-level closer ends the comment early, leaving trailing
        // content after the matching `)`.
        assert!(parse_comment("(a) b)").is_none());
        assert!(parse_comment("(a)(b)").is_none());
    }

    #[test]
    fn parse_comment_bare_control_byte_rejected() {
        // §5.6.5 `ctext` excludes the controls below HTAB/SP except the
        // two it lists (HTAB, SP). A bare CR / LF / NUL is not ctext.
        assert!(parse_comment("(a\rb)").is_none());
        assert!(parse_comment("(a\nb)").is_none());
        assert!(parse_comment("(a\u{0}b)").is_none());
        // HTAB and SP ARE ctext.
        assert_eq!(&*parse_comment("(a\tb c)").unwrap(), "a\tb c");
    }

    #[test]
    fn parse_comment_dangling_or_illegal_quoted_pair_rejected() {
        // Trailing lone `\` with nothing to escape.
        assert!(parse_comment("(abc\\)").is_none());
        // `\` followed by a bare CR/LF is outside the §5.6.4
        // quoted-pair RHS (would unbalance the field line).
        assert!(parse_comment("(a\\\rb)").is_none());
        assert!(parse_comment("(a\\\nb)").is_none());
    }

    #[test]
    fn parse_comment_obs_text_byte_accepted() {
        // §5.6.5 `ctext` admits obs-text (%x80-FF). A UTF-8 multibyte
        // sequence is all obs-text bytes and survives unescaped.
        let v = parse_comment("(café)").unwrap();
        assert_eq!(&*v, "café");
        // And as an escaped octet, the obs-text byte is emitted verbatim
        // (here the escaped multibyte forms valid UTF-8 in aggregate).
        let v = parse_comment("(a \\é b)").unwrap();
        assert_eq!(&*v, "a é b");
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

    // --- RFC 9110 §8.3.1 media-type (parse_media_type) ----------------

    #[test]
    fn parse_media_type_bare_type_subtype_no_parameters() {
        // §8.3.1 `media-type = type "/" subtype parameters` with an
        // empty parameters tail.
        let (ty, sub, params) = parse_media_type("text/html").unwrap();
        assert_eq!(ty, "text");
        assert_eq!(sub, "html");
        assert!(params.is_empty());
    }

    #[test]
    fn parse_media_type_lowercases_type_and_subtype_per_8_3_1() {
        // §8.3.1: "The type and subtype tokens are case-insensitive."
        // `Text/HTML` and `text/html` describe the same media type.
        let (ty, sub, _) = parse_media_type("Text/HTML").unwrap();
        assert_eq!(ty, "text");
        assert_eq!(sub, "html");
    }

    #[test]
    fn parse_media_type_canonical_charset_example() {
        // §8.3.1 worked example: `text/html;charset=utf-8`.
        let (ty, sub, params) = parse_media_type("text/html;charset=utf-8").unwrap();
        assert_eq!(ty, "text");
        assert_eq!(sub, "html");
        assert_eq!(params, vec![("charset".to_owned(), "utf-8".to_owned())]);
    }

    #[test]
    fn parse_media_type_quoted_charset_example() {
        // §8.3.1 worked example: `text/html; charset="utf-8"` — the
        // quoted value unwraps to the same logical octets per §5.6.4,
        // and OWS after the `;` is tolerated by the §5.6.6 helper.
        let (ty, sub, params) = parse_media_type("text/html; charset=\"utf-8\"").unwrap();
        assert_eq!(ty, "text");
        assert_eq!(sub, "html");
        assert_eq!(params, vec![("charset".to_owned(), "utf-8".to_owned())]);
    }

    #[test]
    fn parse_media_type_does_not_case_fold_parameter_value() {
        // §8.3.1: "Parameter values might or might not be
        // case-sensitive." The helper preserves the value verbatim;
        // the §8.3.2 case-insensitive charset fold is the caller's job.
        let (_, _, params) = parse_media_type("text/html;charset=UTF-8").unwrap();
        assert_eq!(params, vec![("charset".to_owned(), "UTF-8".to_owned())]);
    }

    #[test]
    fn parse_media_type_lowercases_parameter_name_per_5_6_6() {
        // §5.6.6: parameter-name is case-insensitive (the §5.6.6 helper
        // lowercases it); the §8.3.1 worked example `Charset` folds.
        let (_, _, params) = parse_media_type("Text/HTML;Charset=\"utf-8\"").unwrap();
        assert_eq!(params, vec![("charset".to_owned(), "utf-8".to_owned())]);
    }

    #[test]
    fn parse_media_type_multiple_parameters_preserved_in_order() {
        let (ty, sub, params) =
            parse_media_type("application/dash+xml; profiles=\"a,b\"; foo=bar").unwrap();
        assert_eq!(ty, "application");
        assert_eq!(sub, "dash+xml");
        assert_eq!(
            params,
            vec![
                ("profiles".to_owned(), "a,b".to_owned()),
                ("foo".to_owned(), "bar".to_owned()),
            ]
        );
    }

    #[test]
    fn parse_media_type_ows_around_value_and_before_semicolon_tolerated() {
        // Leading/trailing OWS on the whole value is trimmed, and the
        // OWS between the subtype and the first `;` is part of the
        // §8.3.1 `parameters` `*( OWS ";" OWS … )` opener.
        let (ty, sub, params) =
            parse_media_type("  multipart/byteranges ; boundary=ABC  ").unwrap();
        assert_eq!(ty, "multipart");
        assert_eq!(sub, "byteranges");
        assert_eq!(params, vec![("boundary".to_owned(), "ABC".to_owned())]);
    }

    #[test]
    fn parse_media_type_boundary_with_quoted_semicolon_preserved() {
        // The §5.6.6 splitter is quoted-string-aware: a `;` inside the
        // boundary value is part of the value, not a new slot.
        let (_, _, params) = parse_media_type("multipart/byteranges; boundary=\"a;b\"").unwrap();
        assert_eq!(params, vec![("boundary".to_owned(), "a;b".to_owned())]);
    }

    #[test]
    fn parse_media_type_missing_slash_rejected() {
        // §8.3.1 requires `type "/" subtype` — no `/` is not a
        // media-type.
        assert!(parse_media_type("text").is_none());
        assert!(parse_media_type("text;charset=utf-8").is_none());
    }

    #[test]
    fn parse_media_type_empty_type_or_subtype_rejected() {
        // `type` / `subtype` are `token`, and `is_token` rejects empty.
        assert!(parse_media_type("/html").is_none());
        assert!(parse_media_type("text/").is_none());
        assert!(parse_media_type("/").is_none());
    }

    #[test]
    fn parse_media_type_non_token_type_or_subtype_rejected() {
        // A second `/` makes the subtype a non-`token` (`/` is not a
        // `tchar` per §5.6.2); a space inside either token is likewise
        // not a `tchar`.
        assert!(parse_media_type("text/ht/ml").is_none());
        assert!(parse_media_type("te xt/html").is_none());
        assert!(parse_media_type("text/ht ml").is_none());
    }

    #[test]
    fn parse_media_type_empty_and_whitespace_input_rejected() {
        assert!(parse_media_type("").is_none());
        assert!(parse_media_type("   ").is_none());
        assert!(parse_media_type("\t").is_none());
    }

    #[test]
    fn parse_media_type_garbage_parameter_slots_skipped_media_survives() {
        // The §5.6.6 helper's defensive posture flows through: a
        // garbage parameter slot is dropped, but the type/subtype and
        // the legitimate sibling parameter survive.
        let (ty, sub, params) = parse_media_type("text/plain; =novalue; charset=utf-8").unwrap();
        assert_eq!(ty, "text");
        assert_eq!(sub, "plain");
        assert_eq!(params, vec![("charset".to_owned(), "utf-8".to_owned())]);
    }

    #[test]
    fn parse_media_type_coupling_with_is_multipart_byteranges() {
        // Coupling test: the narrow §15.3.7.2 multipart predicate and
        // the general §8.3.1 parser must agree on the type/subtype of a
        // boundary-bearing multipart/byteranges value.
        let ct = "multipart/byteranges; boundary=END";
        assert!(is_multipart_byteranges_content_type(ct));
        let (ty, sub, _) = parse_media_type(ct).unwrap();
        assert_eq!(format!("{ty}/{sub}"), "multipart/byteranges");
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

    // -- RFC 9111 §5.2 Cache-Control parser ----------------------------------

    #[test]
    fn cache_control_empty_value_yields_default() {
        assert_eq!(parse_cache_control(""), CacheControl::default());
        assert_eq!(parse_cache_control("   "), CacheControl::default());
        // §5.6.1: empty list elements are skipped.
        assert_eq!(parse_cache_control(",,"), CacheControl::default());
    }

    #[test]
    fn cache_control_boolean_directives_set_flags() {
        let cc = parse_cache_control(
            "no-store, no-transform, only-if-cached, must-revalidate, \
             must-understand, proxy-revalidate, public",
        );
        assert!(cc.no_store);
        assert!(cc.no_transform);
        assert!(cc.only_if_cached);
        assert!(cc.must_revalidate);
        assert!(cc.must_understand);
        assert!(cc.proxy_revalidate);
        assert!(cc.public);
        // No valued / qualified slots were touched.
        assert!(cc.max_age.is_none());
        assert!(cc.no_cache_fields.is_empty());
        assert!(cc.extensions.is_empty());
    }

    #[test]
    fn cache_control_directive_names_are_case_insensitive() {
        // §5.2: "identified by a token, to be compared case-insensitively".
        let cc = parse_cache_control("No-Store, MAX-AGE=60, Public");
        assert!(cc.no_store);
        assert_eq!(cc.max_age, Some(60));
        assert!(cc.public);
    }

    #[test]
    fn cache_control_max_age_token_argument() {
        // §5.2.2.1: token form `max-age=5`.
        let cc = parse_cache_control("max-age=300");
        assert_eq!(cc.max_age, Some(300));
        assert_eq!(parse_cache_control("max-age=0").max_age, Some(0));
    }

    #[test]
    fn cache_control_s_maxage_and_min_fresh() {
        let cc = parse_cache_control("s-maxage=120, min-fresh=20");
        assert_eq!(cc.s_maxage, Some(120));
        assert_eq!(cc.min_fresh, Some(20));
    }

    #[test]
    fn cache_control_delta_seconds_overflow_saturates() {
        // §1.2.2: a delta-seconds that overflows MUST clamp to 2^31,
        // never wrap or be treated as negative.
        let huge = "max-age=99999999999999999999999999999";
        assert_eq!(parse_cache_control(huge).max_age, Some(DELTA_SECONDS_MAX));
    }

    #[test]
    fn cache_control_non_integer_delta_seconds_is_absent() {
        // §4.2.1: a directive "with non-integer content" makes the
        // response stale — we report the slot as absent rather than
        // coercing a garbage argument.
        assert!(parse_cache_control("max-age=abc").max_age.is_none());
        assert!(parse_cache_control("max-age=-5").max_age.is_none());
        assert!(parse_cache_control("max-age=").max_age.is_none());
        assert!(parse_cache_control("max-age").max_age.is_none());
    }

    #[test]
    fn cache_control_delta_seconds_accepts_quoted_argument_on_receipt() {
        // §5.2: senders MUST use the token form, but "recipients ought to
        // accept both forms".
        assert_eq!(parse_cache_control("max-age=\"60\"").max_age, Some(60));
    }

    #[test]
    fn cache_control_max_stale_no_arg_vs_valued() {
        // §5.2.1.2: bare max-stale accepts a stale response of any age.
        assert_eq!(parse_cache_control("max-stale").max_stale, Some(None));
        assert_eq!(
            parse_cache_control("max-stale=10").max_stale,
            Some(Some(10))
        );
        assert_eq!(parse_cache_control("").max_stale, None);
    }

    #[test]
    fn cache_control_no_cache_unqualified_vs_qualified() {
        // §5.2.2.4: unqualified no-cache.
        let bare = parse_cache_control("no-cache");
        assert!(bare.no_cache);
        assert!(bare.no_cache_fields.is_empty());
        // Qualified form: quoted #field-name list, names lowercased.
        let qual = parse_cache_control("no-cache=\"Set-Cookie, X-Foo\"");
        assert!(!qual.no_cache);
        assert_eq!(qual.no_cache_fields, vec!["set-cookie", "x-foo"]);
    }

    #[test]
    fn cache_control_private_unqualified_vs_qualified() {
        // §5.2.2.7.
        assert!(parse_cache_control("private").private);
        let qual = parse_cache_control("private=\"Authorization\"");
        assert!(!qual.private);
        assert_eq!(qual.private_fields, vec!["authorization"]);
    }

    #[test]
    fn cache_control_quoted_comma_does_not_split_directive() {
        // The comma inside the quoted #field-name argument must not end
        // the no-cache directive and start a new one.
        let cc = parse_cache_control("no-cache=\"a, b\", max-age=5");
        assert_eq!(cc.no_cache_fields, vec!["a", "b"]);
        assert_eq!(cc.max_age, Some(5));
    }

    #[test]
    fn cache_control_unknown_directive_preserved_as_extension() {
        // §5.2.3: ignore unrecognized directives — preserved here so an
        // extension consumer can still inspect them.
        let cc = parse_cache_control("immutable, community=\"UCI\", max-age=1");
        assert_eq!(cc.max_age, Some(1));
        assert_eq!(
            cc.extensions,
            vec![
                ("immutable".to_owned(), None),
                ("community".to_owned(), Some("UCI".to_owned())),
            ]
        );
    }

    #[test]
    fn cache_control_duplicate_valued_directive_keeps_first() {
        // §4.2.1: first occurrence is used for a repeated valued directive.
        assert_eq!(
            parse_cache_control("max-age=10, max-age=99").max_age,
            Some(10)
        );
        assert_eq!(
            parse_cache_control("max-stale=1, max-stale=2").max_stale,
            Some(Some(1))
        );
    }

    #[test]
    fn cache_control_ows_around_elements_tolerated() {
        // §5.6.3 OWS around each #-list element.
        let cc = parse_cache_control("  no-store ,  max-age=7  ");
        assert!(cc.no_store);
        assert_eq!(cc.max_age, Some(7));
    }

    #[test]
    fn cache_control_obs_fold_normalised_before_split() {
        // RFC 7230 §3.2.4: an obs-fold becomes SP before list splitting.
        let cc = parse_cache_control("max-age=30,\r\n no-cache");
        assert_eq!(cc.max_age, Some(30));
        assert!(cc.no_cache);
    }

    #[test]
    fn cache_control_malformed_element_skipped_not_fatal() {
        // A non-token name and a bare `=value` element are skipped; the
        // surrounding good directives still parse.
        let cc = parse_cache_control("no-store, =bad, ba()d=x, public");
        assert!(cc.no_store);
        assert!(cc.public);
        assert!(cc.extensions.is_empty());
    }

    #[test]
    fn parse_delta_seconds_boundary() {
        assert_eq!(parse_delta_seconds("0"), Some(0));
        assert_eq!(parse_delta_seconds("2147483648"), Some(DELTA_SECONDS_MAX));
        assert_eq!(parse_delta_seconds(""), None);
        assert_eq!(parse_delta_seconds("+1"), None);
        assert_eq!(parse_delta_seconds("1 "), None);
    }

    // ----------------------------------------------------------------
    // RFC 9110 §11.6.1 WWW-Authenticate challenge-list parser.
    // ----------------------------------------------------------------

    fn ch(scheme: &str, params: &[(&str, &str)]) -> Challenge {
        Challenge {
            scheme: scheme.to_owned(),
            token68: None,
            params: params
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn www_auth_empty_yields_no_challenges() {
        assert!(parse_www_authenticate("").is_empty());
        assert!(parse_www_authenticate("   ").is_empty());
        // The §11.6.1 "comma, whitespace, comma" harmless-empty note.
        assert!(parse_www_authenticate(", ,").is_empty());
    }

    #[test]
    fn www_auth_bare_scheme_no_args() {
        assert_eq!(
            parse_www_authenticate("Negotiate"),
            vec![ch("negotiate", &[])]
        );
    }

    #[test]
    fn www_auth_scheme_lowercased_case_insensitive() {
        // §11.1: auth-scheme is a case-insensitive token.
        assert_eq!(
            parse_www_authenticate("BASIC realm=\"x\""),
            vec![ch("basic", &[("realm", "x")])]
        );
    }

    #[test]
    fn www_auth_single_challenge_one_param() {
        assert_eq!(
            parse_www_authenticate("Basic realm=\"simple\""),
            vec![ch("basic", &[("realm", "simple")])]
        );
    }

    #[test]
    fn www_auth_token68_form() {
        // §11.2: token68 carries a base64-ish blob (here with `=` pad).
        let got = parse_www_authenticate("Negotiate a87421bK3m");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].scheme, "negotiate");
        assert_eq!(got[0].token68.as_deref(), Some("a87421bK3m"));
        assert!(got[0].params.is_empty());
    }

    #[test]
    fn www_auth_token68_with_trailing_pad() {
        let got = parse_www_authenticate("Negotiate TlRMTVNTUAACAAAA==");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].token68.as_deref(), Some("TlRMTVNTUAACAAAA=="));
    }

    #[test]
    fn www_auth_rfc_worked_example_two_challenges() {
        // The canonical §11.6.1 example: two challenges, the second with
        // three auth-params including a quoted-pair-escaped DQUOTE.
        let got = parse_www_authenticate(
            "Basic realm=\"simple\", Newauth realm=\"apps\", type=1, title=\"Login to \\\"apps\\\"\"",
        );
        assert_eq!(
            got,
            vec![
                ch("basic", &[("realm", "simple")]),
                ch(
                    "newauth",
                    &[
                        ("realm", "apps"),
                        ("type", "1"),
                        ("title", "Login to \"apps\""),
                    ],
                ),
            ]
        );
    }

    #[test]
    fn www_auth_param_name_lowercased_value_case_preserved() {
        // §11.2: param names case-insensitive (lowercased); value case is
        // scheme-specific so it is preserved verbatim.
        let got = parse_www_authenticate("Digest Realm=\"MixedCase\"");
        assert_eq!(got, vec![ch("digest", &[("realm", "MixedCase")])]);
    }

    #[test]
    fn www_auth_bws_around_equals_tolerated() {
        // §11.2: auth-param permits BWS on both sides of `=`, unlike the
        // §5.6.6 parameter production.
        assert_eq!(
            parse_www_authenticate("Basic realm = \"x\""),
            vec![ch("basic", &[("realm", "x")])]
        );
    }

    #[test]
    fn www_auth_token_value_form() {
        // auth-param value may be a bare token (here `type=1`).
        assert_eq!(
            parse_www_authenticate("Newauth type=1"),
            vec![ch("newauth", &[("type", "1")])]
        );
    }

    #[test]
    fn www_auth_quoted_comma_does_not_split() {
        // A comma inside a quoted-string value is part of the value, not a
        // list delimiter.
        assert_eq!(
            parse_www_authenticate("Basic realm=\"a, b\""),
            vec![ch("basic", &[("realm", "a, b")])]
        );
    }

    #[test]
    fn www_auth_two_basic_realms_distinct_challenges() {
        // §11.5: a response can carry multiple challenges with the same
        // scheme but different realms.
        assert_eq!(
            parse_www_authenticate("Basic realm=\"a\", Basic realm=\"b\""),
            vec![
                ch("basic", &[("realm", "a")]),
                ch("basic", &[("realm", "b")]),
            ]
        );
    }

    #[test]
    fn www_auth_malformed_param_skipped_challenge_survives() {
        // A param slot that is not token=(token/quoted-string) is dropped;
        // the challenge and its good sibling params survive.
        assert_eq!(
            parse_www_authenticate("Digest realm=\"r\", bad(), nonce=\"n\""),
            vec![ch("digest", &[("realm", "r"), ("nonce", "n")])]
        );
    }

    #[test]
    fn www_auth_unterminated_quoted_string_param_dropped() {
        // An unterminated quoted-string value cannot be a slot delimiter
        // boundary either; the splitter keeps it as one element and the
        // per-slot parser drops the malformed value.
        let got = parse_www_authenticate("Basic realm=\"oops");
        assert_eq!(got, vec![ch("basic", &[])]);
    }

    #[test]
    fn www_auth_leading_bare_param_with_no_challenge_dropped() {
        // A bare auth-param with no preceding challenge has nothing to
        // attach to; it is dropped.
        assert!(parse_www_authenticate("realm=\"orphan\"").is_empty());
    }

    #[test]
    fn www_auth_param_after_token68_challenge_dropped() {
        // §11.3 mutual exclusivity: a challenge that committed to token68
        // cannot also take auth-params. The stray param is dropped.
        let got = parse_www_authenticate("Negotiate abc123, realm=\"x\"");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].token68.as_deref(), Some("abc123"));
        assert!(got[0].params.is_empty());
    }

    #[test]
    fn www_auth_obs_fold_normalised_before_parse() {
        // RFC 7230 §3.2.4: an obs-fold becomes SP before list splitting.
        assert_eq!(
            parse_www_authenticate("Basic realm=\"a\",\r\n Digest realm=\"b\""),
            vec![
                ch("basic", &[("realm", "a")]),
                ch("digest", &[("realm", "b")]),
            ]
        );
    }

    #[test]
    fn www_auth_scheme_then_first_param_then_more() {
        // Scheme + first auth-param on the head element, then trailing
        // auth-params attach to that same challenge.
        assert_eq!(
            parse_www_authenticate("Digest realm=\"r\", qop=\"auth\", nonce=\"n\""),
            vec![ch(
                "digest",
                &[("realm", "r"), ("qop", "auth"), ("nonce", "n")]
            )]
        );
    }

    #[test]
    fn www_auth_token68_not_confused_with_param() {
        // A `name=value`-shaped first argument is an auth-param, never a
        // token68 (the §11.6.1 ambiguity resolves toward auth-param).
        let got = parse_www_authenticate("Custom foo=bar");
        assert_eq!(got, vec![ch("custom", &[("foo", "bar")])]);
    }

    #[test]
    fn as_token68_recogniser() {
        assert_eq!(as_token68("abcXYZ09-._~+/"), Some("abcXYZ09-._~+/"));
        assert_eq!(as_token68("abc=="), Some("abc=="));
        assert_eq!(as_token68("=abc"), None); // pad-before-body
        assert_eq!(as_token68("ab=cd"), None); // interior `=` then body
        assert_eq!(as_token68(""), None);
        assert_eq!(as_token68("a b"), None); // whitespace excluded
    }

    #[test]
    fn parse_one_auth_param_shapes() {
        assert_eq!(
            parse_one_auth_param("Realm=\"x\""),
            Some(("realm".to_string(), "x".to_string()))
        );
        assert_eq!(
            parse_one_auth_param("type = 1"),
            Some(("type".to_string(), "1".to_string()))
        );
        assert_eq!(parse_one_auth_param("noequals"), None);
        assert_eq!(parse_one_auth_param("=novalue"), None);
        assert_eq!(parse_one_auth_param("bad()=x"), None);
        assert_eq!(parse_one_auth_param("k=\"unterminated"), None);
    }

    // -- Driver-owned redirects (RFC 9110 §15.4 / §10.2.2, RFC 3986 §5) ------

    fn redirect_bytes(status: u16, location: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status} Redirect\r\n\
             Location: {location}\r\n\
             Content-Length: 0\r\n\
             Connection: close\r\n\
             \r\n"
        )
        .into_bytes()
    }

    #[test]
    fn redirect_class_covers_the_15_4_taxonomy() {
        // §15.4.2 / §15.4.9 — permanent; §15.4.3 / §15.4.4 / §15.4.8
        // — temporary (303's target is "not considered equivalent to
        // the target URI", so it must never rewrite future requests).
        assert_eq!(redirect_class(301), Some(HopKind::Permanent));
        assert_eq!(redirect_class(308), Some(HopKind::Permanent));
        assert_eq!(redirect_class(302), Some(HopKind::Temporary));
        assert_eq!(redirect_class(303), Some(HopKind::Temporary));
        assert_eq!(redirect_class(307), Some(HopKind::Temporary));
        // §15.4.1 (reactive negotiation), §15.4.5 (cache signal),
        // §15.4.6/§15.4.7 (deprecated/reserved) are not auto-followed.
        for s in [300, 304, 305, 306, 200, 206, 404] {
            assert_eq!(redirect_class(s), None, "status {s}");
        }
    }

    #[test]
    fn redirect_hop_policy_gates_scheme_host_and_userinfo() {
        let u = |s: &str| uri::UriRef::parse(s).expect("parse");
        let any = HttpConfig::default();
        let upgrade = HttpConfig::builder()
            .redirect_scheme_policy(RedirectSchemePolicy::UpgradeOnly)
            .build();
        let same = HttpConfig::builder()
            .redirect_scheme_policy(RedirectSchemePolicy::Same)
            .build();
        let host_pin = HttpConfig::builder().redirect_same_host_only(true).build();
        let https_only = HttpConfig::builder().https_only(true).build();

        // Scheme policy matrix.
        assert!(hop_policy_check(&any, &u("https://h/a"), &u("http://h/b")).is_ok());
        assert!(hop_policy_check(&upgrade, &u("http://h/a"), &u("https://h/b")).is_ok());
        assert!(hop_policy_check(&upgrade, &u("http://h/a"), &u("http://h/b")).is_ok());
        let e = hop_policy_check(&upgrade, &u("https://h/a"), &u("http://h/b")).unwrap_err();
        assert!(e.contains("UpgradeOnly"), "{e}");
        let e = hop_policy_check(&same, &u("http://h/a"), &u("https://h/b")).unwrap_err();
        assert!(e.contains("Same"), "{e}");
        assert!(hop_policy_check(&same, &u("https://h/a"), &u("https://h/b")).is_ok());

        // https_only refuses plain-http hops even under Any.
        let e = hop_policy_check(&https_only, &u("https://h/a"), &u("http://h/b")).unwrap_err();
        assert!(e.contains("https_only"), "{e}");

        // Host pinning: case-insensitive (RFC 3986 §6.2.2.1), port
        // changes allowed, host changes refused.
        assert!(hop_policy_check(
            &host_pin,
            &u("http://Host.example/a"),
            &u("http://host.EXAMPLE/b")
        )
        .is_ok());
        assert!(hop_policy_check(&host_pin, &u("http://h:1/a"), &u("http://h:2/b")).is_ok());
        let e = hop_policy_check(&host_pin, &u("http://a.example/"), &u("http://b.example/"))
            .unwrap_err();
        assert!(e.contains("redirect_same_host_only"), "{e}");

        // Non-http(s) target scheme refused under every policy.
        let e = hop_policy_check(&any, &u("http://h/a"), &u("ftp://h/b")).unwrap_err();
        assert!(e.contains("http/https only"), "{e}");

        // Empty host: RFC 9110 §4.2.1/§4.2.2 MUST reject.
        let e = hop_policy_check(&any, &u("http://h/a"), &u("http:///p")).unwrap_err();
        assert!(e.contains("empty host"), "{e}");

        // Userinfo target: §4.2.4 treat-as-error.
        let e = hop_policy_check(&any, &u("http://h/a"), &u("http://u:p@h/b")).unwrap_err();
        assert!(e.contains("userinfo") && e.contains("4.2.4"), "{e}");
    }

    #[test]
    fn redirect_301_rewrites_future_requests_to_the_new_uri() {
        // §15.4.2: "any future references to this resource ought to
        // use one of the enclosed URIs" — after a permanent hop at
        // open, range GETs go straight to the new URI, no re-hop.
        let (uri, reqs) = spawn_script_server(vec![
            redirect_bytes(301, "/moved"),
            HEAD_10B_BYTES.to_vec(),
            make_get_206("bytes 0-9/10", b"0123456789"),
        ]);
        let mut src = HttpSource::open(&uri).expect("open");
        assert!(
            src.request_uri().ends_with("/moved"),
            "permanent hop must rewrite the request URI: {}",
            src.request_uri()
        );
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        assert_eq!(&buf, b"0123456789");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 3, "{log:#?}");
        assert!(log[0].starts_with("HEAD /x "), "{:?}", log[0]);
        assert!(log[1].starts_with("HEAD /moved "), "{:?}", log[1]);
        assert!(log[2].starts_with("GET /moved "), "{:?}", log[2]);
    }

    #[test]
    fn redirect_302_keeps_original_uri_and_rewalks_per_request() {
        // §15.4.3: "the client ought to continue to use the target
        // URI for future requests" — the GET re-asks the original URI
        // and follows the hop again.
        let (uri, reqs) = spawn_script_server(vec![
            redirect_bytes(302, "/tmp"),
            HEAD_10B_BYTES.to_vec(),
            redirect_bytes(302, "/tmp"),
            make_get_206("bytes 0-9/10", b"0123456789"),
        ]);
        let mut src = HttpSource::open(&uri).expect("open");
        assert!(
            src.request_uri().ends_with("/x"),
            "temporary hop must NOT rewrite the request URI: {}",
            src.request_uri()
        );
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        assert_eq!(&buf, b"0123456789");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 4, "{log:#?}");
        assert!(log[2].starts_with("GET /x "), "{:?}", log[2]);
        assert!(log[3].starts_with("GET /tmp "), "{:?}", log[3]);
    }

    #[test]
    fn redirect_permanent_prefix_rewrite_freezes_at_first_temporary_hop() {
        // 308 (permanent) then 307 (temporary): the rewrite advances
        // through the permanent link and freezes there — future
        // requests start at the 308 target and re-walk the 307.
        let (uri, reqs) = spawn_script_server(vec![
            redirect_bytes(308, "/a"),
            redirect_bytes(307, "/b"),
            HEAD_10B_BYTES.to_vec(),
            redirect_bytes(307, "/b"),
            make_get_206("bytes 0-9/10", b"0123456789"),
        ]);
        let mut src = HttpSource::open(&uri).expect("open");
        assert!(src.request_uri().ends_with("/a"), "{}", src.request_uri());
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 5, "{log:#?}");
        assert!(log[3].starts_with("GET /a "), "{:?}", log[3]);
        assert!(log[4].starts_with("GET /b "), "{:?}", log[4]);
    }

    #[test]
    fn redirect_303_at_open_follows_with_head_and_rebases_the_anchor() {
        // §15.4.4: the user agent performs "a retrieval request
        // targeting that URI (a GET or HEAD request if using HTTP)" —
        // HEAD is already a retrieval request, so the method rides
        // through unchanged. The 303 target is a *different* resource
        // and the only one with a transferable representation, so the
        // source anchors future range GETs there — re-asking /x for
        // byte ranges would ask a resource the origin said it cannot
        // transfer.
        let (uri, reqs) = spawn_script_server(vec![
            redirect_bytes(303, "/other"),
            HEAD_10B_BYTES.to_vec(),
            make_get_206("bytes 0-9/10", b"0123456789"),
        ]);
        let mut src = HttpSource::open(&uri).expect("open");
        assert!(
            src.request_uri().ends_with("/other"),
            "{}",
            src.request_uri()
        );
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        assert_eq!(&buf, b"0123456789");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 3, "{log:#?}");
        assert!(log[1].starts_with("HEAD /other "), "{:?}", log[1]);
        assert!(log[2].starts_with("GET /other "), "{:?}", log[2]);
    }

    #[test]
    fn redirect_relative_location_resolves_per_rfc3986_section_5() {
        // "moved" against ".../x" → "/moved" (§5.2.3 merge), then
        // "sub/./a/../b" against "/moved" → "/sub/b" (§5.2.4
        // remove_dot_segments).
        let (uri, reqs) = spawn_script_server(vec![
            redirect_bytes(301, "moved"),
            redirect_bytes(301, "sub/./a/../b"),
            HEAD_10B_BYTES.to_vec(),
            make_get_206("bytes 0-9/10", b"0123456789"),
        ]);
        let mut src = HttpSource::open(&uri).expect("open");
        assert!(
            src.request_uri().ends_with("/sub/b"),
            "{}",
            src.request_uri()
        );
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 4, "{log:#?}");
        assert!(log[1].starts_with("HEAD /moved "), "{:?}", log[1]);
        assert!(log[2].starts_with("HEAD /sub/b "), "{:?}", log[2]);
        assert!(log[3].starts_with("GET /sub/b "), "{:?}", log[3]);
    }

    #[test]
    fn redirect_location_fragment_never_reaches_the_wire() {
        // A fragment is client-side only (RFC 9110 §4.2.5); the hop
        // target is requested without it.
        let (uri, reqs) = spawn_script_server(vec![
            redirect_bytes(301, "/y#s5.4"),
            HEAD_10B_BYTES.to_vec(),
            make_get_206("bytes 0-9/10", b"0123456789"),
        ]);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 3, "{log:#?}");
        assert!(log[1].starts_with("HEAD /y "), "{:?}", log[1]);
        assert!(!log[1].contains('#'), "{:?}", log[1]);
    }

    #[test]
    fn redirect_follow_disabled_surfaces_the_3xx_status() {
        let (uri, reqs) = spawn_script_server(vec![redirect_bytes(301, "/moved")]);
        let cfg = HttpConfig::builder().follow_redirects(false).build();
        let err = HttpSource::open_with_config(&uri, &cfg)
            .err()
            .expect("must fail");
        assert!(err.to_string().contains("status 301"), "{err}");
        assert_eq!(reqs.try_iter().count(), 1, "no hop may be followed");
    }

    #[test]
    fn redirect_cap_exceeded_errors_by_default() {
        let (uri, reqs) = spawn_script_server(vec![
            redirect_bytes(301, "/a"),
            redirect_bytes(301, "/b"),
            redirect_bytes(301, "/c"),
        ]);
        let cfg = HttpConfig::builder().max_redirects(2).build();
        let err = HttpSource::open_with_config(&uri, &cfg)
            .err()
            .expect("must fail");
        assert!(err.to_string().contains("max_redirects=2"), "{err}");
        assert_eq!(reqs.try_iter().count(), 3, "initial request + 2 hops");
    }

    #[test]
    fn redirect_cap_with_will_error_false_surfaces_last_3xx() {
        let (uri, reqs) =
            spawn_script_server(vec![redirect_bytes(301, "/a"), redirect_bytes(301, "/b")]);
        let cfg = HttpConfig::builder()
            .max_redirects(1)
            .max_redirects_will_error(false)
            .build();
        let err = HttpSource::open_with_config(&uri, &cfg)
            .err()
            .expect("must fail");
        assert!(err.to_string().contains("status 301"), "{err}");
        assert_eq!(reqs.try_iter().count(), 2);
    }

    #[test]
    fn redirect_300_multiple_choices_is_not_auto_followed() {
        // §15.4.1: following the optional Location of a 300 is a MAY
        // this driver declines — picking a representation variant
        // blind defeats byte-exactness.
        let (uri, reqs) = spawn_script_server(vec![redirect_bytes(300, "/preferred")]);
        let err = HttpSource::open(&uri).err().expect("must fail");
        assert!(err.to_string().contains("status 300"), "{err}");
        assert_eq!(reqs.try_iter().count(), 1);
    }

    #[test]
    fn redirect_range_get_carries_if_range_across_the_hop() {
        // A permanent hop mid-walk targets the same resource at a new
        // URI (§15.4.2), so the §13.1.5 validator must ride along and
        // guard the final origin's answer.
        let (uri, reqs) = spawn_script_server(vec![
            HEAD_10B_BYTES_ETAG.to_vec(),
            redirect_bytes(301, "/moved"),
            make_get_206("bytes 0-9/10", b"0123456789"),
        ]);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        assert_eq!(&buf, b"0123456789");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 3, "{log:#?}");
        assert!(log[2].starts_with("GET /moved "), "{:?}", log[2]);
        assert!(
            log[2].to_ascii_lowercase().contains("if-range: \"v1\""),
            "hop request must carry If-Range: {:?}",
            log[2]
        );
        assert!(
            log[2].to_ascii_lowercase().contains("range: bytes=0-"),
            "{:?}",
            log[2]
        );
        assert!(
            src.request_uri().ends_with("/moved"),
            "mid-stream permanent hop rewrites future requests: {}",
            src.request_uri()
        );
    }

    #[test]
    fn redirect_303_mid_stream_is_fatal_for_range_anchored_requests() {
        // §15.4.4: a 303 target "is not considered equivalent to the
        // target URI" — re-anchoring byte offsets of an already-open
        // representation against a *different* resource is exactly
        // the misalignment the §13.1.5 machinery exists to prevent.
        let (uri, reqs) = spawn_script_server(vec![
            HEAD_10B_BYTES.to_vec(),
            make_get_206("bytes 0-3/10", b"0123"),
            redirect_bytes(303, "/elsewhere"),
        ]);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 4];
        std::io::Read::read_exact(&mut src, &mut buf).expect("first span");
        let err = std::io::Read::read_exact(&mut src, &mut [0u8; 6]).unwrap_err();
        assert!(
            err.to_string().contains("303") && err.to_string().contains("not considered"),
            "{err}"
        );
        assert_eq!(
            reqs.try_iter().count(),
            3,
            "the 303 target must never be contacted"
        );
    }

    // -- Hostile redirect chains ----------------------------------------------

    #[test]
    fn redirect_self_loop_is_detected_on_the_first_hop() {
        // §15.4: "A client SHOULD detect and intervene in cyclical
        // redirections". Location → the request's own URI: caught by
        // the normalized-URI visited set before any second request.
        let (uri, reqs) = spawn_script_server(vec![redirect_bytes(301, "/x")]);
        let err = HttpSource::open(&uri).err().expect("must fail");
        assert!(err.to_string().contains("cyclical"), "{err}");
        assert_eq!(reqs.try_iter().count(), 1);
    }

    #[test]
    fn redirect_two_node_loop_is_detected() {
        let (uri, reqs) =
            spawn_script_server(vec![redirect_bytes(301, "/b"), redirect_bytes(302, "/x")]);
        let err = HttpSource::open(&uri).err().expect("must fail");
        assert!(err.to_string().contains("cyclical"), "{err}");
        assert_eq!(reqs.try_iter().count(), 2, "loop caught before request 3");
    }

    #[test]
    fn redirect_loop_detection_sees_through_normalization() {
        // The loop key is the RFC 9110 §4.2.3 normal form, so a
        // Location that spells the same resource with dot segments
        // and percent-encoded unreserved bytes cannot evade
        // detection: "/a/../%78" ≡ "/x" (§6.2.2.2 + §6.2.2.3).
        let (uri, reqs) = spawn_script_server(vec![redirect_bytes(301, "/a/../%78")]);
        let err = HttpSource::open(&uri).err().expect("must fail");
        assert!(err.to_string().contains("cyclical"), "{err}");
        assert_eq!(reqs.try_iter().count(), 1);
    }

    #[test]
    fn redirect_empty_location_value_is_a_self_loop() {
        // `Location:` with an empty value is a valid URI-reference
        // that resolves to the request URI itself (RFC 3986 §5.2.2's
        // empty-path branch) — cyclical, not followable.
        let (uri, reqs) = spawn_script_server(vec![b"HTTP/1.1 301 Moved\r\n\
              Location: \r\n\
              Content-Length: 0\r\n\
              Connection: close\r\n\
              \r\n"
            .to_vec()]);
        let err = HttpSource::open(&uri).err().expect("must fail");
        assert!(err.to_string().contains("cyclical"), "{err}");
        assert_eq!(reqs.try_iter().count(), 1);
    }

    #[test]
    fn redirect_oversized_chain_stops_at_the_default_cap() {
        // Twelve distinct hops against the default cap of 10: the
        // walk must stop after the initial request + 10 hops (11
        // requests) with a bounded, precise error.
        let responses: Vec<Vec<u8>> = (0..12)
            .map(|i| redirect_bytes(301, &format!("/hop{i}")))
            .collect();
        let (uri, reqs) = spawn_script_server(responses);
        let err = HttpSource::open(&uri).err().expect("must fail");
        assert!(err.to_string().contains("max_redirects=10"), "{err}");
        assert_eq!(reqs.try_iter().count(), 11, "initial request + 10 hops");
    }

    #[test]
    fn redirect_userinfo_location_is_refused_without_contact() {
        // RFC 9110 §4.2.4: userinfo in a reference from an untrusted
        // source is "likely being used to obscure the authority for
        // the sake of phishing attacks" — refuse before any
        // connection to the smuggled authority.
        let (uri, reqs) = spawn_script_server(vec![redirect_bytes(
            301,
            "http://127.0.0.1:1@127.0.0.1:2/y",
        )]);
        let err = HttpSource::open(&uri).err().expect("must fail");
        let msg = err.to_string();
        assert!(msg.contains("userinfo") && msg.contains("4.2.4"), "{msg}");
        assert_eq!(reqs.try_iter().count(), 1);
    }

    #[test]
    fn redirect_malformed_location_values_are_refused() {
        // §10.2.2 permits recovery from invalid Location references
        // but does not mandate it; the driver refuses, each with the
        // grammar-level reason.
        for (loc, want) in [
            ("http://exa mple/", "invalid Location"), // raw space
            ("/y%zz", "invalid Location"),            // broken pct-encoding
            ("http://h:80x/y", "invalid Location"),   // non-digit port
            ("ftp://h/y", "http/https only"),         // wrong scheme
            ("http:///y", "empty host"),              // §4.2.1 MUST reject
            ("http://[::1/y", "invalid Location"),    // unterminated IP-literal
        ] {
            let (uri, reqs) = spawn_script_server(vec![redirect_bytes(301, loc)]);
            let err = HttpSource::open(&uri).err().expect("must fail");
            assert!(
                err.to_string().contains(want),
                "Location {loc:?}: wanted {want:?} in: {err}"
            );
            assert_eq!(reqs.try_iter().count(), 1, "Location {loc:?}");
        }
    }

    #[test]
    fn redirect_without_location_surfaces_the_status() {
        // §15.4: "If a Location header field is provided, the user
        // agent MAY automatically redirect" — without one there is
        // nothing to follow; the 3xx is the final answer.
        let (uri, reqs) = spawn_script_server(vec![b"HTTP/1.1 301 Moved\r\n\
              Content-Length: 0\r\n\
              Connection: close\r\n\
              \r\n"
            .to_vec()]);
        let err = HttpSource::open(&uri).err().expect("must fail");
        assert!(err.to_string().contains("status 301"), "{err}");
        assert_eq!(reqs.try_iter().count(), 1);
    }

    #[test]
    fn redirect_multiple_location_lines_are_refused() {
        // §10.2.2 note: a Location value cannot be a list; multiple
        // field lines come from an invalid message and recovery "is
        // difficult and not interoperable" — refuse rather than pick.
        let (uri, reqs) = spawn_script_server(vec![b"HTTP/1.1 301 Moved\r\n\
              Location: /a\r\n\
              Location: /b\r\n\
              Content-Length: 0\r\n\
              Connection: close\r\n\
              \r\n"
            .to_vec()]);
        let err = HttpSource::open(&uri).err().expect("must fail");
        assert!(err.to_string().contains("multiple"), "{err}");
        assert_eq!(
            reqs.try_iter().count(),
            1,
            "neither target may be contacted"
        );
    }

    #[test]
    fn redirect_cross_host_hop_denied_without_contact() {
        // The policy check runs before any connection: the target
        // host here is unreachable (port 1), so a policy-shaped error
        // proves the wire was never touched.
        let cfg = HttpConfig::builder().redirect_same_host_only(true).build();
        let (uri, reqs) = spawn_script_server(vec![redirect_bytes(301, "http://localhost:1/y")]);
        let err = HttpSource::open_with_config(&uri, &cfg)
            .err()
            .expect("must fail");
        assert!(err.to_string().contains("redirect_same_host_only"), "{err}");
        assert_eq!(reqs.try_iter().count(), 1);
    }

    #[test]
    fn https_only_refuses_the_initial_plain_http_request() {
        let cfg = HttpConfig::builder().https_only(true).build();
        let (uri, reqs) = spawn_script_server(vec![]);
        let err = HttpSource::open_with_config(&uri, &cfg)
            .err()
            .expect("must fail");
        assert!(err.to_string().contains("https_only"), "{err}");
        assert_eq!(reqs.try_iter().count(), 0, "no request may be issued");
    }

    #[test]
    fn redirect_hop_transport_error_names_the_hop() {
        // A hop target that refuses the connection must be reported
        // as that hop, not as a failure of the original URI.
        let (uri, reqs) = spawn_script_server(vec![redirect_bytes(301, "http://127.0.0.1:1/y")]);
        let err = HttpSource::open(&uri).err().expect("must fail");
        assert!(err.to_string().contains("redirect hop 1"), "{err}");
        assert_eq!(reqs.try_iter().count(), 1);
    }

    #[test]
    fn redirect_location_query_survives_to_the_wire() {
        // query = *( pchar / "/" / "?" ) is part of the resolved
        // target (RFC 3986 §5.2.2 sets T.query = R.query); it must
        // ride into the hop's request target.
        let (uri, reqs) = spawn_script_server(vec![
            redirect_bytes(301, "/y?tok=abc&v=1"),
            HEAD_10B_BYTES.to_vec(),
            make_get_206("bytes 0-9/10", b"0123456789"),
        ]);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 3, "{log:#?}");
        assert!(log[1].starts_with("HEAD /y?tok=abc&v=1 "), "{:?}", log[1]);
        assert!(log[2].starts_with("GET /y?tok=abc&v=1 "), "{:?}", log[2]);
    }

    #[test]
    fn redirect_seek_reissues_against_the_rewritten_uri() {
        // After a permanent hop, a backward seek's fresh range GET
        // must target the rewritten URI directly, with the new
        // offset.
        let (uri, reqs) = spawn_script_server(vec![
            redirect_bytes(308, "/moved"),
            HEAD_10B_BYTES.to_vec(),
            make_get_206("bytes 0-9/10", b"0123456789"),
            make_get_206("bytes 1-9/10", b"123456789"),
        ]);
        let mut src = HttpSource::open(&uri).expect("open");
        let mut buf4 = [0u8; 4];
        std::io::Read::read_exact(&mut src, &mut buf4).expect("first read");
        assert_eq!(&buf4, b"0123");
        std::io::Seek::seek(&mut src, SeekFrom::Start(1)).expect("seek");
        let mut buf9 = [0u8; 9];
        std::io::Read::read_exact(&mut src, &mut buf9).expect("second read");
        assert_eq!(&buf9, b"123456789");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(log.len(), 4, "{log:#?}");
        assert!(log[3].starts_with("GET /moved "), "{:?}", log[3]);
        assert!(
            log[3].to_ascii_lowercase().contains("range: bytes=1-"),
            "{:?}",
            log[3]
        );
    }

    #[test]
    fn redirect_probe_open_walks_hops_like_the_head_it_replaces() {
        // HEAD-hostile origin: HEAD answers 405, the opt-in probe GET
        // is redirected, and the probe's 206 at the target supplies
        // total length, validator surface, and the initial body.
        static HEAD_405: &[u8] = b"HTTP/1.1 405 Method Not Allowed\r\n\
            Content-Length: 0\r\n\
            Connection: close\r\n\
            \r\n";
        let (uri, reqs) = spawn_script_server(vec![
            HEAD_405.to_vec(),
            redirect_bytes(301, "/m"),
            make_get_206("bytes 0-9/10", b"0123456789"),
        ]);
        let cfg = probe_cfg();
        let mut src = HttpSource::open_with_config(&uri, &cfg).expect("open");
        assert_eq!(src.len(), 10);
        assert!(src.request_uri().ends_with("/m"), "{}", src.request_uri());
        let mut buf = [0u8; 10];
        std::io::Read::read_exact(&mut src, &mut buf).expect("read");
        assert_eq!(&buf, b"0123456789");
        let log: Vec<String> = reqs.try_iter().collect();
        assert_eq!(
            log.len(),
            3,
            "probe body is reused — no extra GET: {log:#?}"
        );
        assert!(log[1].starts_with("GET /x "), "{:?}", log[1]);
        assert!(log[2].starts_with("GET /m "), "{:?}", log[2]);
    }
}
