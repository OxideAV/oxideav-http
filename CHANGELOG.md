# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `HttpConfig` + `HttpConfigBuilder` policy struct for the underlying
  `ureq` agent, exposing `max_redirects`, `max_redirects_will_error`,
  `redirect_auth_policy` (`Never` / `SameHost`), `user_agent`,
  `https_only`, `timeout_global`, `timeout_connect`. Crate surface stays
  independent of which client we wire in.
- `install_default_config(cfg)` — one-shot installer for the
  process-wide agent used by `register` / `register_source` / the
  `http://` + `https://` scheme handlers on `SourceRegistry`. Returns
  `ConfigAlreadyInstalled` once the global agent has materialised.
- `HttpSource::open_with_config(uri, &cfg)` — per-call override that
  builds a one-off `ureq::Agent` owned by the returned `HttpSource`,
  leaving the process default untouched.
- 6 new unit tests cover default surface, builder thread-through, every
  `RedirectAuthPolicy` variant lighting up the `agent_from` path,
  one-shot install semantics, and the `ConfigAlreadyInstalled`
  `std::error::Error` impl.
- RFC 7233 §4.2 `Content-Range` validation on 206 responses: every 206
  must echo a `Content-Range: bytes <first>-<last>/<complete|*>` whose
  `first` equals the byte position we requested, whose `last >= first`,
  whose `complete` (when concrete) equals the `Content-Length` we
  observed at HEAD, and whose `last < complete`. Missing Content-Range,
  non-`bytes` units, unsatisfied-range (`bytes */N`) payloads, and
  resource-resize disagreements all fail the read with a descriptive
  `io::Error` instead of silently misaligning the demuxer. 8 new parser
  unit tests cover canonical form, `*` complete-length acceptance,
  case-insensitive unit, and every §4.2 invalidity rule.
- RFC 7233 §3.1 fallback for servers that ignore `Range` and reply 200
  with the full body: the prefix `[0, self.pos)` is now drained in
  8 KiB chunks before bytes are exposed to the reader, so the
  file-offset view stays consistent with the demuxer's expectation.
- Local-TCP end-to-end tests (`std::net::TcpListener` on
  `127.0.0.1:0`): canonical 206, missing Content-Range, wrong
  first-byte-pos, complete-length disagreement, `*` complete-length
  acceptance, and 200-fallback prefix-drop. No external network
  reachability required.
- RFC 9110 §15.5.17 + §14.4 `416 Range Not Satisfiable` handling:
  when the server responds 416 with a `Content-Range: bytes
  */<complete-length>` body the driver parses out the server's
  authoritative resource length and the resulting `io::Error`
  surfaces BOTH the server's reported length AND the length
  observed at HEAD construction, letting a caller distinguish
  "asked past EOF" from "resource shrank mid-stream" (a
  cache/origin disagreement). A 416 with no Content-Range or with
  a malformed Content-Range still errors cleanly with a
  status-naming message. 5 new unsatisfied-range parser unit
  tests + 3 new local-TCP end-to-end tests (canonical 416,
  Content-Range-less 416, malformed-Content-Range 416).

### Changed

- Default agent is now lazily built from `DEFAULT_CONFIG` (or library
  defaults if none is installed) instead of an unparameterised
  `Agent::config_builder().build().new_agent()`. No behaviour change
  when `install_default_config` is not called.

## [0.0.6](https://github.com/OxideAV/oxideav-http/compare/v0.0.5...v0.0.6) - 2026-05-06

### Other

- reframe FFI claim — HW-engine crates use OS FFI by necessity
- drop dead `linkme` dep
- auto-register via oxideav_core::register! macro (linkme distributed slice)
- tidy after rebase atop release-plz 0.0.5 ([#502](https://github.com/OxideAV/oxideav-http/pull/502))
- unify entry point on register(&mut RuntimeContext) ([#502](https://github.com/OxideAV/oxideav-http/pull/502))

### Changed

- **Breaking**: Unified entry point on `register(&mut RuntimeContext)`
  to match the convention every sibling crate now follows (#502). The
  previous `register(reg: &mut SourceRegistry)` was renamed to
  `register_source(reg: &mut SourceRegistry)`; `register(ctx)` calls
  `register_source(&mut ctx.sources)` internally. Direct
  `oxideav_http::register(&mut some_source_registry)` callers must
  switch to either `register(&mut ctx)` (preferred) or the renamed
  `register_source(&mut some_source_registry)`.

## [0.0.5](https://github.com/OxideAV/oxideav-http/compare/v0.0.4...v0.0.5) - 2026-05-03

### Other

- replace never-match regex with semver_check = false
- migrate to centralized OxideAV/.github reusable workflows
- stay on 0.1.x during heavy dev (semver_check=false)
- Migrate http(s):// driver to SourceRegistry typed-bytes API
- pin release-plz to patch-only bumps

## [0.0.4](https://github.com/OxideAV/oxideav-http/compare/v0.0.3...v0.0.4) - 2026-04-25

### Fixed

- use oxideav_source::with_defaults free fn

### Other

- drop oxideav-codec/oxideav-container shims, import from oxideav-core
- bump oxideav-source dep to "0.1"
- bump oxideav-container dep to "0.1"
