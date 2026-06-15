# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.8](https://github.com/OxideAV/oxideav-http/compare/v0.0.7...v0.0.8) - 2026-06-15

### Other

- RFC 9110 §5.6.5 parser with nested-comment recursion + quoted-pair collapse
- RFC 9110 §11.6.1 #challenge parser with list disambiguation
- add RFC 9111 §5.2 Cache-Control directive parser
- §12.5.5 Vary content-negotiation stability check at open
- refuse coded representations (RFC 9110 §8.4 + §12.5.3)
- RFC 9110 §8.3.1 parser composing §5.6.2 token + §5.6.6 parameters
- RFC 9110 §5.6.6 list parser + 23 unit tests + fuzz coverage
- RFC 9110 §5.6.4 unwrap + quoted-pair collapse primitive
- drop release-plz.toml — use release-plz defaults across the workspace
- RFC 7230 §3.2.4 normaliser + wire on Accept-Ranges / Retry-After
- multipart/byteranges + Retry-After surfacing: RFC 9110 §15.3.7.2 + §10.2.3
- §14.3 list-form parser + 4 distinct classifications
- §10.2.3 parser + 15 unit tests + fuzz coverage
- accept rfc850 + asctime forms in §13.1.5 validator path

### Added

- RFC 9110 §5.6.5 `comment` parser. New internal `parse_comment` reads
  a `comment = "(" *( ctext / quoted-pair / comment ) ")"` value into
  its logical text — outer parentheses stripped, every `quoted-pair`
  (§5.6.4) collapsed to the escaped octet, and balanced nested-comment
  delimiters preserved verbatim as part of the content. `ctext`
  (`HTAB / SP / %x21-27 / %x2A-5B / %x5D-7E / obs-text`) is validated
  byte-for-byte, with the holes at `(` / `)` / `\` carrying meaning
  only through the comment recursion or the escape; an unbalanced
  paren, trailing content after the matching close, a bare control
  byte, or a dangling/illegal `quoted-pair` is rejected (`None`).
  Recursion depth is tracked with an explicit counter rather than the
  call stack, so deeply nested `((((…))))` input cannot overflow.
  Escape-free single-level input borrows the slice (zero allocation);
  only a `quoted-pair` forces the owned path. This completes the §5.6
  generic-syntax primitive family (§5.6.1 list / §5.6.2 token / §5.6.4
  quoted-string / §5.6.6 parameters / §5.6.7 date already present) and
  backs any future consumer of a `comment`-bearing field (`User-Agent`
  / `Server` §10.1.5 / §10.2.4, `Via` §7.6.3, `Warning` RFC 7234
  §5.5). No in-driver caller yet — the driver issues unauthenticated
  `HEAD` / `Range` requests and acts on none of those response fields —
  but the primitive is exercised by 10 unit tests and the cargo-fuzz
  `parse_headers` harness through the `__fuzz` gate.

- RFC 9110 §11.6.1 `WWW-Authenticate` challenge-list parser. New
  `parse_www_authenticate` reads a `WWW-Authenticate = #challenge`
  value into a `Vec<Challenge>`, where `Challenge` carries the
  lowercased `auth-scheme` (§11.1 case-insensitive token), an optional
  `token68` (§11.2), and an ordered `(lowercased-name, decoded-value)`
  `auth-param` list (§11.2). The parser resolves the §11.6.1 list
  ambiguity — both the challenge list and each challenge's `auth-param`
  list are comma-separated — by classifying each quoted-string-aware
  top-level comma element as either a bare `auth-param`
  (`token BWS "=" …`, attaching to the challenge in progress) or a
  challenge head (`auth-scheme` alone or `auth-scheme 1*SP <arg>`,
  starting a new challenge). The canonical §11.6.1 worked example
  (`Basic realm="simple", Newauth realm="apps", type=1, title="Login
  to \"apps\""` → two challenges) round-trips. §11.2 BWS around `=` is
  tolerated (unlike the §5.6.6 `parameter` production), quoted-string
  values are unwrapped via the §5.6.4 helper (case preserved — value
  case-sensitivity is scheme-specific), and `token68` is discriminated
  from a `name=value` `auth-param` (the ambiguity resolves toward
  `auth-param`). §11.3 mutual exclusivity is enforced: a challenge that
  committed to `token68` rejects trailing `auth-param`s. Malformed
  pieces are skipped per §5.6.1 recipient robustness (the §11.6.1
  "comma, whitespace, comma" empty-element note is honoured as
  harmless). The same production backs `Proxy-Authenticate` (§11.7.1)
  and single-`credentials` `Authorization` values. Exercised by 21
  unit tests and wired into the cargo-fuzz `parse_headers` harness.

- RFC 9111 §5.2 `Cache-Control` directive parser. New
  `parse_cache_control` reads a `Cache-Control = #cache-directive`
  value into a typed `CacheControl` struct. The §5.6.1 `#`-list is
  split on top-level commas with quoted-string awareness (a comma
  inside a `no-cache="x-foo, x-bar"` argument does not start a new
  directive); empty elements are skipped and OWS trimmed. Directive
  names are lowercased (§5.2 "compared case-insensitively") and both
  the token and quoted-string argument forms are accepted on receipt
  (§5.2 "recipients ought to accept both forms"). `max-age` /
  `s-maxage` / `min-fresh` / `max-stale` carry §1.2.2 `delta-seconds`
  arguments saturated at `2147483648` (2^31) on overflow per the
  §1.2.2 MUST (exposed as `DELTA_SECONDS_MAX`); a non-`1*DIGIT`
  argument leaves the slot absent (§4.2.1 stale-on-non-integer).
  `max-stale` distinguishes the no-argument "any age" form from a
  valued bound. The qualified `#field-name` forms of `no-cache`
  (§5.2.2.4) and `private` (§5.2.2.7) split into lowercased field
  names distinct from the unqualified booleans; the boolean
  directives (`no-store`, `no-transform`, `only-if-cached`,
  `must-revalidate`, `must-understand`, `proxy-revalidate`, `public`)
  set their flags. Duplicate valued directives keep the first
  occurrence (§4.2.1) and unrecognized directives are preserved in
  `extensions` (§5.2.3 "ignore unrecognized" — kept, not dropped).
  Added to the `parse_headers` fuzz harness. 18 unit tests.

- RFC 9110 §12.5.5 content-negotiation stability check. The driver
  opens with a single `HEAD`, records length + validator, then ranges
  over the resource with independent `Range` GETs — assuming the
  target URI maps to one representation for the source's lifetime. A
  `Vary` header is the origin's §12 proactive-negotiation warning that
  a later request might be served a different representation. New
  `parse_vary` classifies the §12.5.5 `Vary = #( "*" / field-name )`
  list into Absent / Wildcard / Fields. A `Vary: *` response — whose
  selection §12.5.5 says may depend on "aspects outside the message
  syntax (e.g., the client's network address)" the driver cannot
  reproduce across requests — is refused at open (`Error::Unsupported`)
  **only when no strong validator was captured**; with one, a
  representation swap re-surfaces as the §13.1.5 `If-Range`
  200-fallback the GET path already treats as a fatal mid-stream
  mutation. The field-name-list form (form 2) is accepted: the driver
  sends a fixed, identical request header set on the `HEAD` and every
  `Range` GET, so negotiation keyed on those fields is stable.
  Field-names match case-insensitively (§5.1); a `*` member anywhere
  poisons the value to the wildcard form; obs-fold is normalised per
  §3.2.4 first. Six unit tests + a fuzz wrapper (`__fuzz::parse_vary`).
- RFC 9110 §8.4 / §12.5.3 content-coding refusal. The driver's whole
  byte-offset model — the `Content-Length` recorded at HEAD, every
  `Content-Range` echo it validates, the RFC 7233 §3.1 prefix drain —
  assumes the wire bytes ARE the representation bytes a demuxer
  consumes. But §12.5.3 rule 1 says "If no Accept-Encoding header
  field is in the request, any content coding is considered acceptable
  by the user agent", and §8.4 says a coded representation "is defined
  in terms of the coded form, and all other metadata about the
  representation is about the coded form" — so a server that elected
  to gzip the response would silently turn every offset and length the
  driver tracks into coded-byte quantities. Two-sided fix:
  - Request side: the opening `HEAD` and every `Range` GET now carry
    `Accept-Encoding: identity` — listing only the §12.5.3 "no
    encoding" synonym makes every real coding fall under rule 3's
    "not listed", steering a conformant server to "send a response
    without any content coding".
  - Response side (defence in depth — §12.5.3 is advisory): any
    response that still carries a real `Content-Encoding` is rejected
    before a single byte reaches the reader. At HEAD that is an
    `Error::Unsupported` naming the coding(s) plus the §8.4 cite; on a
    206 / 200-fallback GET it is a fatal `io::Error`. The check walks
    every `Content-Encoding` field line (the §8.4 `#` list may be
    split across lines per §5.6.1), normalises obs-fold first (RFC
    7230 §3.2.4), lowercases each coding (§8.4.1 "All content codings
    are case-insensitive"), tolerates the redundant `identity` token
    (§8.4 SHOULD NOT send it, but it codes nothing), and drops empty
    §5.6.1 list slots. Fail-direction is the opposite of the §14.3
    `Accept-Ranges` parser: a non-`token` garbage slot is KEPT in the
    diagnostic rather than skipped, because an unparseable coding name
    is still a transformation the driver cannot undo — skipping it
    would silently accept a coded body.
  New internal helper `non_identity_content_codings` implements the
  list filter; re-exported through the `#[doc(hidden)] pub mod __fuzz`
  gate and exercised by the cargo-fuzz `parse_headers` harness with
  three new seed-corpus entries. 11 new tests: 5 unit tests on the
  filter (empty/absent, identity tolerance, §8.4.1 case-folding,
  §8.4 application-order preservation, garbage-slot keeping) and 6
  local-loopback server tests (HEAD-with-gzip refused with §8.4 cite,
  HEAD-with-identity accepted, 206-with-gzip fatal, 200-fallback-with-
  gzip fatal, and request-capture proofs that both HEAD and GET carry
  `Accept-Encoding: identity` on the wire).

### Changed

- `ureq` dependency now pulled with `default-features = false,
  features = ["rustls"]`. The dropped default `gzip` feature installed
  a transparent client-side decompression layer that consumed the
  `Content-Encoding` evidence (and the coded `Content-Length`) before
  the driver's §8.4 checks could see them, attempting to inflate the
  body mid-stream and redefining every byte count behind the driver's
  back. With the layer gone the driver sees the raw coded response and
  owns the refusal with a precise RFC-cited diagnostic. https support
  is unchanged (`rustls` retained); the crate's dependency tree also
  sheds the transitive decompressor crates.

- RFC 9110 §8.3.1 `media-type` parser. New internal helper
  `parse_media_type(&str) -> Option<(String, String, Vec<(String,
  String)>)>` composes the §5.6.2 `is_token` and §5.6.6
  `parse_parameters` primitives into the §8.3.1 production
  `media-type = type "/" subtype parameters` (`type = token`,
  `subtype = token`). It returns the lowercased `type` and `subtype`
  — §8.3.1: "The type and subtype tokens are case-insensitive." — plus
  the §5.6.6 ordered `Vec<(lowercase-name, decoded-value)>` of the
  trailing parameters (already quoted-pair-collapsed per §5.6.4).
  Parameter *values* are NOT case-folded — §8.3.1: "Parameter values
  might or might not be case-sensitive, depending on the semantics of
  the parameter name" — so a consumer that knows a parameter is
  case-insensitive (e.g. `charset` per §8.3.2 / RFC 2046 §4.1.2) folds
  the value itself. This is the §8.3.1 composition the §5.6.6 helper
  was built to enable: a `charset` extractor on `Content-Type` becomes
  a `parse_media_type(ct)` then a case-insensitive `"charset"` lookup
  in the returned params. The value is rejected (`None`) when it is not
  a syntactically valid media-type: a missing `/`, an empty / non-`token`
  type or subtype, a second `/` (which makes the subtype a non-`token`
  since `/` is not a §5.6.2 `tchar`), or empty / whitespace-only input.
  Leading/trailing OWS on the whole value and OWS between the subtype
  and the first `;` are tolerated (the §8.3.1 `parameters` tail opens
  with `*( OWS ";" OWS … )`); garbage parameter slots are dropped by the
  §5.6.6 helper while the type/subtype and legitimate sibling parameters
  survive. No in-driver caller exists yet — the §15.3.7.2 multipart
  rejection only needs the bare `type/subtype` prefix and uses the
  narrower `is_multipart_byteranges_content_type`; the primitive is in
  place ready to back any future per-parameter media-type inspection.
  16 new unit tests cover: bare type/subtype (no params), §8.3.1
  type/subtype lowercasing, the §8.3.1 worked examples
  (`text/html;charset=utf-8` and `text/html; charset="utf-8"`),
  no-fold-on-parameter-value (§8.3.1) vs lowercase-on-parameter-name
  (§5.6.6), multi-parameter order preservation, OWS tolerance (whole
  value + before the first `;`), quoted-`;`-in-boundary preserved,
  missing-`/` rejection, empty-type / empty-subtype rejection,
  non-`token` (second `/` and embedded SP) rejection, empty /
  whitespace-only rejection, garbage-parameter-slot tolerance, and a
  coupling test pinning agreement with the narrow §15.3.7.2 multipart
  predicate. The helper is re-exported through the `#[doc(hidden)] pub
  mod __fuzz` gate so the cargo-fuzz `parse_headers` harness exercises
  it on arbitrary input; three new seed-corpus entries
  (`media_type_charset`, `media_type_charset_quoted`,
  `media_type_multipart_boundary`) seed the canonical happy-path inputs.

- RFC 9110 §5.6.6 `parameters` list parser. New internal helper
  `parse_parameters(&str) -> Vec<(String, String)>` consumes a
  `parameters = *( OWS ";" OWS [ parameter ] )` tail and emits an
  ordered list of `(lowercase-name, decoded-value)` pairs. The
  splitter is quoted-string-aware — a `;` inside a `"…"` body is
  part of the value (not a slot terminator), and a `\"` inside the
  body is a §5.6.4 `quoted-pair` (skipped by the splitter so the
  value isn't truncated at it). Token-shape values are preserved
  verbatim (case-sensitivity is parameter-name-specific per
  §5.6.6); quoted-string values are routed through `unquote_string`
  so a consumer receives the logical octet sequence with every
  `quoted-pair` collapsed per §5.6.4's MUST. Defensive posture
  matches `parse_accept_ranges`: empty slots, missing-`=` slots,
  slots with SP / HTAB around `=` (§5.6.6's informational "not
  even 'bad' whitespace" note), non-token names, non-token
  unquoted values, and unterminated quoted-string values are all
  silently skipped while the surrounding legitimate parameters
  survive. The primitive sits ready to back any future
  per-parameter inspection — e.g. a §8.3.1 `charset="utf-8"`
  extractor on `Content-Type`, a §14.6 `boundary=` lookup on
  `multipart/byteranges` (currently rejected wholesale per
  §15.3.7.2 — the boundary extractor would only be needed if we
  ever decided to parse rather than reject), or §11.4 `realm="…"`
  auth-param decoding once the caller has split the challenge on
  its §11.2 `,` boundaries. 23 new unit tests cover: empty input,
  whitespace-only input, semicolon-only input, single-token value,
  optional-leading-`;` invariant, §5.6.6 name lowercasing,
  quoted-string value unwrap, §5.6.4 quoted-pair collapse on the
  value, `;` inside quoted-string preserved (no premature slot
  end), `\"` inside quoted-string preserved (no premature value
  close), multi-entry order preservation, empty-slot tolerance per
  §5.6.1, missing-`=` skipped, whitespace-around-`=` skipped (and
  the only-before / only-after sub-cases), non-token name skipped,
  non-token unquoted value skipped, unterminated-quoted-string
  skipped, OWS around `;` tolerated, obs-text (U+00E9 multi-byte
  UTF-8) inside quoted-string preserved, §11.4 realm shape, comma
  inside value is not a §5.6.6 slot separator, token values with
  `.` `_` `-` accepted, and a §5.6.6 → §5.6.4 layering coupling
  test. The helper is also re-exported through the
  `#[doc(hidden)] pub mod __fuzz` gate so the cargo-fuzz
  `parse_headers` harness exercises it on arbitrary input
  alongside every other §3.2.4 / §5.6.4 / §5.6.7 / §8.8.3 /
  §10.2.3 / §14.3 / §14.4 parser; three new seed-corpus entries
  (`parameters_charset`, `parameters_boundary_quoted`,
  `parameters_multiple`) seed the corpus with canonical happy-path
  inputs.

- RFC 9110 §5.6.4 `quoted-string` unwrap primitive. New internal
  helper `unquote_string(&str) -> Option<Cow<str>>` takes a complete
  DQUOTE-wrapped `quoted-string` field value and returns the
  unescaped logical octet sequence — collapsing each
  `quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )` to the single
  octet that followed the backslash, satisfying §5.6.4's hard MUST:
  "Recipients that process the value of a quoted-string MUST handle
  a quoted-pair as if it were replaced by the octet following the
  backslash." The function rejects malformed inputs (missing DQUOTEs,
  bare control bytes outside `qdtext`, trailing lone backslash with
  no octet to escape, and backslash followed by an octet outside the
  §5.6.4 `quoted-pair` RHS — notably bare CR / LF, which would
  unbalance the field line). The hot path with no escapes returns
  `Cow::Borrowed` of the inner slice (zero allocations); only the
  slow path of an actual escape allocates. The §15.3.7.2 multipart
  rejection only needs the bare media-type prefix and the §8.8.3
  `entity-tag` production explicitly excludes `quoted-pair` from
  `etagc`, so no in-driver caller exists yet — the primitive is in
  place ready to back any future per-parameter inspection
  (§5.6.6 / §8.3.1 parameter values, §11.4 auth-param values, etc.).
  17 new unit tests cover: empty-pair (`""` → empty borrowed),
  escape-free Cow::Borrowed hot path, quoted-DQUOTE collapse,
  quoted-backslash collapse, every malformed-input rejection branch
  (missing leading DQUOTE, missing trailing DQUOTE, single DQUOTE,
  bare unwrapped value, empty input, trailing lone backslash, bare
  CR / LF after backslash, bare body DQUOTE, bare BEL control byte
  in body), obs-text byte acceptance (high U+00E9 byte in body),
  escape-preserving obs-text byte through `\<C3>`, slow-path
  Cow::Owned invariant, and a coupling test pinning the §5.6.4 →
  §5.6.6 layering with a parameter-value that contains the
  semicolon delimiter. The helper is also re-exported through the
  `#[doc(hidden)] pub mod __fuzz` gate so the cargo-fuzz
  `parse_headers` harness exercises it on arbitrary input alongside
  every other §3.2.4 / §5.6.7 / §8.8.3 / §10.2.3 / §14.3 / §14.4
  parser; three new seed-corpus entries (`quoted_string_plain`,
  `quoted_string_escaped_dquote`, `quoted_string_escaped_backslash`)
  seed the corpus with canonical happy-path inputs.

- RFC 7230 §3.2.4 obs-fold normalisation. New internal helper
  `normalize_obs_fold(&str) -> Cow<str>` collapses each `obs-fold =
  CRLF 1*( SP / HTAB )` occurrence to a single ASCII space, fulfilling
  the §3.2.4 "A user agent that receives an obs-fold in a response
  message that is not within a message/http container MUST replace
  each received obs-fold with one or more SP octets prior to
  interpreting the field value" MUST. The driver wires the helper at
  two header-consumption sites: the §14.3 `Accept-Ranges` list parser
  in `open_impl` and the §10.2.3 `Retry-After` hint formatter on the
  HEAD non-success branch. Production-path overhead is zero (the
  helper short-circuits to `Cow::Borrowed` when no fold is present,
  which is the case for every field value modern HTTP clients hand
  through; the explicit normalisation is a defence-in-depth guard
  against framing layers that pass `message/http`-style raw frames or
  obs-folded values through unmodified). 16 new unit tests cover:
  borrowed-on-absent, CRLF-without-SP-or-HTAB (not a fold), bare CR
  and bare LF (not a fold), single SP fold, single HTAB fold, mixed
  SP/HTAB run, multiple distinct folds, fold at start of value,
  trailing CRLF without continuation, obs-text byte preservation (U+00E9
  multi-byte UTF-8 across a fold boundary), intra-field whitespace
  untouched, empty input, mixed fold-then-non-fold-CRLF, fold inside
  a quoted-string span, chained back-to-back folds, and a coupling
  test pinning the §3.2.4 "prior to interpreting" ordering against
  `parse_imf_fixdate`. The helper is also re-exported through the
  `#[doc(hidden)] pub mod __fuzz` gate so the cargo-fuzz
  `parse_headers` harness exercises it on arbitrary input alongside
  every other §5.6.7 / §10.2.3 / §14.3 / §14.4 / §8.8.3 parser.
- RFC 9110 §15.3.7.2 + §14.6 + §8.3 `multipart/byteranges` rejection on
  a 206 response. The driver only ever sends `Range: bytes=N-`
  (single-range), and §15.3.7.2 makes "A server MUST NOT generate a
  multipart response to a request for a single range" a hard MUST NOT.
  New helper `is_multipart_byteranges_content_type` consults the 206's
  `Content-Type` field before the §4.2 `Content-Range` checks; on
  match, the read fails with a §15.3.7.2 cite that names the offending
  media type. The match is case-insensitive per §8.3.1 ("type, subtype,
  and parameter name tokens are case-insensitive") and tolerant of
  trailing `; boundary=…` parameters. Without this guard, the body's
  multipart framing would be parsed as bitstream bytes by the
  downstream demuxer (the §8.6 Content-Length cross-check from r197
  would also light up, but with a misleading diagnostic). 6 new
  helper unit tests (canonical, boundary-bearing, case-insensitive,
  OWS-tolerant, every-non-multipart-type sentinel, prefix-subtype
  non-match) + 3 new local-TCP end-to-end tests (canonical-multipart,
  title-cased-multipart, video/mp4 sanity-passes).
- RFC 9110 §10.2.3 `Retry-After` surfacing on HEAD non-success. New
  helper `format_retry_after_hint(raw) -> String` consumes the field
  through the existing `parse_retry_after` and renders a
  parenthesised hint suitable for appending to an error message —
  `" (Retry-After: 120 s)"` for the `delay-seconds` form,
  `" (Retry-After: 1999-12-31T23:59:59 UTC)"` for any of the three
  §5.6.7 HTTP-date forms (canonicalised — the caller gets a stable
  shape regardless of which wire form the origin emitted), and
  `" (Retry-After: \"…\", unparseable per RFC 9110 §10.2.3)"` when
  the field is set but does not match either grammar. The HEAD
  non-success branch in `open_impl` now parses any `Retry-After`
  header and surfaces the hint in the resulting `Error::other`
  message — covering the §10.2.3-named 503 (Service Unavailable) +
  3xx (Redirection) cases plus the RFC 6585 429 (Too Many Requests)
  case §10.2.3 also mentions. The driver still does NOT itself sleep
  on the value (interpreting "wait until this absolute UTC time"
  requires a clock the source does not own); the surfacing just
  spares the caller from refetching a now-consumed header. 9 new
  helper unit tests (delay-seconds, zero-delay, IMF-fixdate,
  rfc850-date canonicalisation, asctime canonicalisation,
  unparseable diagnostic + cite, empty / whitespace-only collapse,
  OWS-trimming) + 4 new local-TCP end-to-end tests (503 with delay,
  429 with date, 503 without Retry-After omits the hint, 503 with
  unparseable Retry-After surfaces the §10.2.3 cite).
- Fuzz harness gains 2 new wrappers
  (`is_multipart_byteranges_content_type`,
  `format_retry_after_hint`) and 3 new seed-corpus entries
  (`multipart_byteranges_bare`, `multipart_byteranges_boundary`,
  `content_type_video_mp4`).

- RFC 9110 §14.3 `Accept-Ranges` parser + classifier. The HEAD path now
  consumes `Accept-Ranges` as the §14.3 ABNF `acceptable-ranges =
  1#range-unit` list (§5.6.1 list constructor, OWS-tolerant, empty
  members dropped) instead of a bare case-insensitive equality on
  `"bytes"`. Behaviour change matrix:
  - `Accept-Ranges: bytes` → unchanged (accept).
  - `Accept-Ranges: bytes, foo-unit` → **now accepted** (was
    rejected). Per §14.3 a server MAY advertise multiple range units
    and the client acts on the one it speaks. Previously the bare
    equality rejected any list form.
  - `Accept-Ranges: none` → **distinct error message** ("server
    explicitly refused range support … RFC 9110 §14.3"). §14.3
    reserves `none` as the server's explicit "do not attempt"
    advice; surfacing it distinctly from "absent" lets a caller tell
    "server actively refused" from "server didn't say".
  - `Accept-Ranges: foo-unit` (any non-`bytes` token-list) → distinct
    error message naming the offered unit(s). Lets a caller report
    "server speaks ranges, just not in our unit".
  - Header absent → distinct error message ("server did not advertise
    Accept-Ranges …"). §14.3 makes the field advisory, so absence is
    informational; the driver still refuses for safety (the
    Content-Range / If-Range invariants the rest of the pipeline
    relies on assume a server that honours `Range:`) but the message
    is no longer conflated with the explicit-`none` case.
  - New `is_token` helper enforces §5.6.2 `tchar` validity per
    list-element; non-token slots (e.g. embedded SP) are silently
    skipped so one garbage element doesn't black-hole a legitimate
    `bytes` next to it.
  - 9 new parser unit tests (canonical bare-`bytes`, case-insensitive
    matching, explicit-`none`, list-with-`bytes`, list-without-`bytes`,
    `none`-alongside-other-units contradiction, empty/CSV-tolerance,
    non-token-skip, `tchar` spot-check) + 4 new local-TCP end-to-end
    tests (`Accept-Ranges: none` refusal message, list-with-`bytes`
    accepted, non-`bytes`-only refusal naming the unit, absent-header
    distinct message). All four messages include the `§14.3` cite
    for grep-ability.
  - Fuzz harness gains a `parse_accept_ranges` wrapper (returns the
    classification tag so the fuzzer drives every branch) and 3 new
    seed-corpus entries (`accept_ranges_bytes`, `accept_ranges_none`,
    `accept_ranges_list`).

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
