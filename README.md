# oxideav-http

HTTP/HTTPS source driver for oxideav (pure-Rust via ureq + rustls + webpki-roots).

Registers as a `BytesSource` on the new typed `SourceRegistry`, so
`reg.open(uri)` yields `SourceOutput::Bytes(_)` ready for any container
demuxer.

Part of the [oxideav](https://github.com/OxideAV/oxideav-workspace) framework — a
100% pure Rust media transcoding and streaming stack. No C libraries, no FFI
wrappers, no `*-sys` crates.

## Usage

```toml
[dependencies]
oxideav-http = "0.0"
```

## License

MIT — see [LICENSE](LICENSE).
