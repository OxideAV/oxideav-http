# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- RFC 9110 §8.4 `Content-Encoding` rejection on every response path.
  - Every `HEAD` and every range `GET` now sends
    `Accept-Encoding: identity` (§12.5.3), telling the origin we cannot
    accept compressed octets behind a `Content-Length` /
    `Content-Range` that would no longer correspond to media byte
    offsets.
  - A new internal `parse_content_encoding(Option<&str>) ->
    ContentEncodingState` classifies the response field per §8.4 +
    §5.6.1: absent header, all-empty list elements, and the reserved
    `identity` token (alone or mixed with empties) all classify as
    `Identity`; any other §5.6.2 token (`gzip`, `compress`, `deflate`,
    `br`, `zstd`, `x-gzip`, …) and any malformed list element
    (containing non-`tchar` characters) classify as `NonIdentity`,
    carrying the original field value verbatim into the error surface.
  - All three response paths now reject `NonIdentity`:
    - Opening `HEAD` returns `Error::Unsupported` with the field
      value + §8.4 cite.
    - 200-fallback (§3.1) GET returns `io::Error::other` before any
      prefix-drain.
    - 206 GET returns `io::Error::other` before any byte reaches the
      reader.
  - 14 new unit tests cover the parser (absent, identity-only,
    case-insensitivity, empty-list-element tolerance, named
    compression codings — including spec-named `compress` / `deflate`
    / `gzip` and registry-listed `br` / `zstd` — list with any
    non-identity member, list of only identity tokens, OWS
    whitespace, non-token characters including non-ASCII, total-on-
    arbitrary-input smoke test) plus `is_token` boundary coverage.
  - 4 new local-TCP end-to-end tests cover the wire path: HEAD with
    `Content-Encoding: gzip` rejected at open, HEAD with explicit
    `identity` accepted, 206 with `Content-Encoding: gzip` rejected
    on read, 200-fallback with `Content-Encoding: deflate` rejected
    on read, and 206 with explicit `identity` accepted.
  - Fuzz harness gains a `parse_content_encoding` wrapper driving
    both the `Some(_)` and the `None` arms, plus three new seed
    corpus entries (`content_encoding_identity`, `content_encoding_gzip`,
    `content_encoding_list`).
- RFC 9110 §10.2.3 `Retry-After` header parser. New public
  `parse_retry_after(&str) -> Option<RetryAfter>` consumes the
  `HTTP-date / delay-seconds` grammar and returns a typed
  `RetryAfter` enum — `Delay(Duration)` for the
  `delay-seconds = 1*DIGIT` form, `Date { year, month, day, hour,
  minute, second }` for the HTTP-date form. All three §5.6.7
  receiver-side date forms are accepted (matching the §5.6.7 MUST).
  The driver itself does not act on `Retry-After` — interpreting
  an absolute UTC date requires a clock the source does not own,
  and back-off strategy belongs in the caller — but exposing the
  parser lets consumers honour 503 / 429 / 3xx-with-Retry-After
  responses without rewriting the §10.2.3 grammar themselves.
  - The grammar is intentionally strict: a leading `+`/`-`, a
    fractional or hex literal, an all-digit value that overflows
    `u64` (≈ 584 billion years), or a unit-bearing form (`"120s"`)
    all yield `None`. The disjoint nature of `delay-seconds` vs
    `HTTP-date` (the former is pure-digit, every accepted
    HTTP-date form opens with an alphabetic weekday) is exploited
    to disambiguate without trial-parsing both branches.
  - 15 new unit tests cover both §10.2.3 spec example values
    (`120` and `Fri, 31 Dec 1999 23:59:59 GMT`), the zero-delay
    edge, large-but-in-range u64 delays, OWS trimming, the three
    §5.6.7 date forms (IMF-fixdate / rfc850-date / asctime-date),
    every documented rejection path (empty, signed, decimal,
    hex, trailing units, u64 overflow, malformed date), and the
    pure-digit disambiguation case (`"1994"` parses as 1994
    seconds, not the year 1994).
  - Fuzz harness gains a `parse_retry_after` wrapper and two new
    seed-corpus entries (`retry_after_delay`, `retry_after_date`)
    pinning the §10.2.3 example values.
- RFC 9110 §5.6.7 HTTP-date receiver-side conformance: the strong-
  validator promotion path (§13.1.5 + §8.8.2.2) now accepts all three
  HTTP-date forms a recipient MUST accept, not just IMF-fixdate.
  - New `parse_rfc850_date` parses the obsolete `rfc850-date`
    `Weekday, DD-Mon-YY HH:MM:SS GMT` form. The 2-digit year follows
    §5.6.7's sliding-window MUST: a value that would otherwise land
    more than 50 years in the future maps to the most recent past
    year with the same last two digits (anchored at REF_YEAR=2026).
  - New `parse_asctime_date` parses the obsolete `asctime-date`
    `Wkd Mon DD HH:MM:SS YYYY` (with the day field accepting both the
    `2DIGIT` and `SP 1DIGIT` alternatives in §5.6.7's `date3` ABNF).
    §5.6.7: "values in the asctime format are assumed to be in UTC".
  - New `parse_http_date` is the unified §5.6.7 entry point —
    IMF-fixdate first (the form senders MUST emit), rfc850-date
    next, asctime-date last. `derive_strong_validator` now calls
    this entry point, so origins that emit Last-Modified/Date in
    either obsolete form (still seen in the wild — §5.6.7 makes
    accepting them a MUST on the recipient) light up the
    `If-Range` strong-validator path instead of falling silently to
    no-validator mode. Last-Modified and Date are no longer
    required to use the same form.
  - 14 new unit tests cover: canonical rfc850/asctime examples,
    every long weekday name, the sliding-window year expansion
    (26/76/77/00/99 — confirms the 50-year boundary), malformed
    rejections for both new parsers, the §5.6.7 MUST-accept-all-
    three guarantee on `parse_http_date`, identical-instant
    cross-form equality, and `derive_strong_validator` lighting up
    on rfc850-date / asctime-date / mixed-form inputs.
  - Fuzz harness gains 3 new wrappers (`parse_rfc850_date`,
    `parse_asctime_date`, `parse_http_date`) and seed corpus
    entries for the canonical §5.6.7 examples of each obsolete
    form.
- RFC 9110 §8.6 `Content-Length` cross-checks on every GET response:
  - On a §3.1 200-fallback (server ignored `Range` and shipped the
    full body), the GET's `Content-Length` — when present — MUST
    equal the `Content-Length` observed at HEAD. §8.6: HEAD's
    `Content-Length` MUST equal what a GET would have sent. A
    different value is a mid-stream resource resize disguised as a
    soft-fallback; the driver now surfaces a fatal `io::Error`
    rather than draining a now-wrong-sized prefix and reading
    short.
  - On a 206, the GET's `Content-Length` (when present) MUST equal
    the byte span implied by `Content-Range: bytes <first>-<last>/N`
    (`last - first + 1`). A mismatch is either a server bug or a
    multipart/byteranges body (which the driver never requests);
    either way the reader would drift past the satisfied range
    silently.
  - Both checks are skipped when the GET reply omits
    `Content-Length` (§8.6 makes it a SHOULD outside specific
    cases). 4 new local-TCP end-to-end tests cover 200-mismatch,
    200-no-CL, 206-mismatch, and 206-canonical-match.
- `fuzz/` cargo-fuzz harness (`parse_headers`) drives every internal
  response-header parser used by the source driver
  (`parse_byte_content_range`, `parse_byte_unsatisfied_range`,
  `parse_entity_tag`, `parse_imf_fixdate`, `derive_strong_validator`).
  The harness reaches the parsers through a `#[doc(hidden)] pub mod
  __fuzz` re-export gated on the new `fuzz` cargo feature, so the
  stable public surface is unchanged when the crate is consumed
  normally. Seed corpus covers canonical 206 content-range,
  star-complete, 416 unsatisfied-range, strong/weak ETag,
  IMF-fixdate, and NUL-split derive_strong_validator combinations.

### Changed

- `oxideav-http` now declares a default-off `fuzz` cargo feature
  (no transitive effect when unused — purely gates the
  `#[doc(hidden)] pub mod __fuzz` re-export).

## [0.0.7](https://github.com/OxideAV/oxideav-http/compare/v0.0.6...v0.0.7) - 2026-05-29

### Other

- capture strong validator at HEAD, surface 200 as mid-stream mutation (RFC 9110 §13.1.5)
- surface server-reported complete-length on Range Not Satisfiable (RFC 9110 §15.5.17 + §14.4)
- validate Content-Range on 206, drain prefix on 200 (RFC 7233 §3.1/§4.2)
- HttpConfig + install_default_config + open_with_config

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
- RFC 9110 §13.1.5 `If-Range` strong-validator path: at HEAD the
  driver now captures an `ETag` (only when strong — §8.8.3 weak
  `W/`-prefixed tags are rejected per §13.1.5's "MUST NOT generate
  ... an entity tag that is marked as weak") or, failing that, a
  `Last-Modified` value the §8.8.2.2 "Date - Last-Modified >= 1 s"
  rule promotes from implicitly-weak to strong. The validator is
  replayed as `If-Range: <wire-form>` on every subsequent
  `Range: bytes=N-` GET so that a mid-stream representation change
  short-circuits to 200 (full body of the NEW representation) —
  which the driver then surfaces as a fatal `io::Error` naming
  "If-Range validator did not match — representation changed since
  HEAD" rather than silently re-anchoring the byte offset. New
  parsers (`parse_entity_tag` per §8.8.3 ABNF, `parse_imf_fixdate`
  per §5.6.7 IMF-fixdate, `derive_strong_validator`) carry 12 new
  unit tests covering strong/weak ETag distinction, case-sensitive
  `W/` weakness marker, IMF-fixdate acceptance and rfc850/asctime
  rejection, the 1-second §8.8.2.2 boundary, and ETag-first /
  Last-Modified-fallback / no-validator precedence. 4 new local-TCP
  end-to-end tests verify the wire-level `If-Range` header is
  emitted for strong ETags, suppressed for weak ETags, fatally
  errored when a `If-Range` GET drops to 200, and that the §3.1
  drain-prefix path remains intact when no validator was sent.

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
