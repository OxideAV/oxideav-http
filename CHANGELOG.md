# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Breaking**: Migrated to the new typed `SourceRegistry` API in
  `oxideav-core`. `register(&mut SourceRegistry)` now calls
  `register_bytes("http", open_http)` and `register_bytes("https",
  open_http)` (was `register(…)`); `open_http` returns
  `Box<dyn BytesSource>` (was `Box<dyn ReadSeek>`). `HttpSource`
  itself is unchanged — it continues to satisfy `Read + Seek + Send`,
  so the blanket `BytesSource` impl in `oxideav-core` picks it up
  automatically.

## [0.0.4](https://github.com/OxideAV/oxideav-http/compare/v0.0.3...v0.0.4) - 2026-04-25

### Fixed

- use oxideav_source::with_defaults free fn

### Other

- drop oxideav-codec/oxideav-container shims, import from oxideav-core
- bump oxideav-source dep to "0.1"
- bump oxideav-container dep to "0.1"
