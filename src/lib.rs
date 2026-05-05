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

use std::io::{self, Read, Seek, SeekFrom};
use std::sync::OnceLock;

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

fn agent() -> &'static Agent {
    static A: OnceLock<Agent> = OnceLock::new();
    A.get_or_init(|| Agent::config_builder().build().new_agent())
}

/// `ReadSeek` over an HTTP/HTTPS resource, using `Range` requests.
pub struct HttpSource {
    uri: String,
    total_len: u64,
    pos: u64,
    /// Active response body for the current contiguous read run, if any.
    body: Option<Box<dyn Read + Send>>,
}

impl HttpSource {
    pub fn open(uri: &str) -> Result<Self> {
        let head = agent()
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
            body: None,
        })
    }

    pub fn len(&self) -> u64 {
        self.total_len
    }

    pub fn is_empty(&self) -> bool {
        self.total_len == 0
    }

    fn issue_range(&mut self) -> io::Result<()> {
        if self.pos >= self.total_len {
            self.body = None;
            return Ok(());
        }
        let range = format!("bytes={}-", self.pos);
        let resp = agent()
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
}
