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

## License

MIT — see [LICENSE](LICENSE).
