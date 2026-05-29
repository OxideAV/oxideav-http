# oxideav-http

HTTP/HTTPS source driver for oxideav (pure-Rust via ureq + rustls + webpki-roots).

Registers as a `BytesSource` on the new typed `SourceRegistry`, so
`reg.open(uri)` yields `SourceOutput::Bytes(_)` ready for any container
demuxer.

Part of the [oxideav](https://github.com/OxideAV/oxideav-workspace) framework — a pure-Rust media transcoding and streaming stack. Codec, container, and filter crates are implemented from the spec (no C codec libraries linked or wrapped, no `*-sys` crates). Optional hardware-engine crates (`oxideav-videotoolbox` / `-audiotoolbox` / `-vaapi` / `-vdpau` / `-nvidia` / `-vulkan-video`) bridge to OS APIs via runtime `libloading`; pass `--no-hwaccel` (or omit the `hwaccel` feature) to opt out.

## Usage

```toml
[dependencies]
oxideav-http = "0.0"
```

```rust
let mut ctx = oxideav_core::RuntimeContext::new();
ctx.sources = oxideav_source::with_defaults();
oxideav_http::register(&mut ctx); // installs http:// + https://
let _r = ctx.sources.open("https://example.com/clip.mp4")?;
```

## Configuring the agent

The default agent uses `ureq` defaults. To tighten policy (cap redirects,
strip `Authorization` on cross-host redirects, require https, set a
custom `User-Agent`, bound connect/global timeouts) build an
`HttpConfig` and either install it process-wide or scope it to one
source:

```rust
use std::time::Duration;
use oxideav_http::{HttpConfig, RedirectAuthPolicy, HttpSource, install_default_config};

let cfg = HttpConfig::builder()
    .max_redirects(5)
    .redirect_auth_policy(RedirectAuthPolicy::SameHost)
    .user_agent("my-app/1.0")
    .https_only(true)
    .timeout_connect(Some(Duration::from_secs(5)))
    .timeout_global(Some(Duration::from_secs(60)))
    .build();

// (A) install once at startup so every registry-dispatched open()
//     uses these settings:
install_default_config(cfg.clone()).ok();

// (B) or scope per-call without touching the global agent:
let _src = HttpSource::open_with_config("https://example.com/clip.mp4", &cfg)?;
```

`install_default_config` is one-shot — it returns `ConfigAlreadyInstalled`
once the process-wide agent has materialised. Call it before the first
`ctx.sources.open(...)` if you need it to take effect on
registry-dispatched opens.

## Range-response validation

Every 206 (Partial Content) response is validated against RFC 7233
§4.2 before any byte is exposed to the reader:

- `Content-Range` header MUST be present.
- Range unit MUST be `bytes` (case-insensitive).
- `first-byte-pos` MUST equal the byte position we asked for —
  a cache / CDN that slides the start would otherwise silently
  misalign every subsequent demuxer read.
- `last-byte-pos >= first-byte-pos`.
- `complete-length`, when concrete, MUST equal the `Content-Length`
  observed at HEAD construction — a mid-stream resource resize is a
  fatal origin/cache disagreement.
- `last-byte-pos < complete-length`.
- `*` complete-length is accepted (§4.2 explicitly permits it when
  the server doesn't know the total).
- `bytes */N` unsatisfied-range payloads are rejected on a 206 (they
  are a 416 payload, never a 206 payload).

If a server ignores the `Range` header and responds with `200 OK`
plus the full body (§3.1 permits this), the prefix `[0, self.pos)`
is drained in 8 KiB chunks before bytes reach the reader, so the
demuxer's file-offset view stays consistent.

## 416 Range Not Satisfiable

A 416 response is treated as a distinct error path per RFC 9110
§15.5.17. When the server includes the `Content-Range: bytes
*/<complete-length>` body that §14.4 SHOULDs for 416 responses,
the parser extracts the server's authoritative resource length and
the resulting `io::Error` surfaces BOTH the server's reported length
AND the length observed at HEAD construction. That lets a caller
tell "I asked past EOF" apart from "the resource shrank between the
HEAD and the GET" — the latter is a cache/origin disagreement worth
reporting upstream.

If the 416 omits the SHOULD'd Content-Range, the error still names
the status cleanly. If the 416 carries a malformed Content-Range,
the parse error surfaces rather than a fabricated length.

## License

MIT — see [LICENSE](LICENSE).
