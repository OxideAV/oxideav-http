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
        // ureq 3: Body owns the stream; into_body().into_reader() yields
        // a `Read` that pulls from the wire as bytes are requested.
        let reader = resp.into_body().into_reader();
        self.body = Some(Box::new(reader));
        Ok(())
    }
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
}
