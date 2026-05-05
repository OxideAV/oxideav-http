# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
