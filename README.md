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

## License

MIT — see [LICENSE](LICENSE).
