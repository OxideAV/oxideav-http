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

## Accept-Ranges classification (RFC 9110 §14.3)

The opening `HEAD` reads `Accept-Ranges` through the §14.3 list-form
parser (`acceptable-ranges = 1#range-unit`, §5.6.1 list constructor,
OWS-tolerant) rather than a bare equality. That gives four distinct
outcomes with separate error messages:

- `Accept-Ranges: bytes` (alone or anywhere in a comma-separated
  list, case-insensitive) — accepted; the driver proceeds.
- `Accept-Ranges: none` — the §14.3-reserved "do not attempt"
  advice. The driver returns an `Error::Unsupported` whose message
  names the explicit refusal and the §14.3 cite, so a caller can
  tell "server actively refused ranges" from "server didn't say".
- `Accept-Ranges: <other-unit>` (any non-`bytes` token, single or
  list) — the driver returns an `Error::Unsupported` that names the
  offered unit(s). Useful diagnostic when a server speaks ranges in
  some unit the driver doesn't (the driver currently only knows
  `bytes`).
- Header absent — the driver still refuses (the rest of the
  read-path's `Content-Range` / `If-Range` invariants assume a
  server that satisfies `Range:` requests), but the message is
  distinct from the explicit-`none` case so a caller can tell
  silence from refusal.

Empty list elements (`bytes,,`) and non-token list elements (e.g. a
slot with an embedded space) are tolerated — they are silently
skipped so one garbage element next to a legitimate `bytes` does not
black-hole the response.

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
- `Content-Type: multipart/byteranges` (RFC 9110 §14.6) is rejected
  with a §15.3.7.2 cite. The driver only ever issues
  `Range: bytes=N-` (single-range), and §15.3.7.2 makes "A server
  MUST NOT generate a multipart response to a request for a single
  range" a hard MUST NOT — surfacing the offence cleanly stops the
  boundary delimiter from being interpreted as bitstream bytes. The
  media-type match is case-insensitive per §8.3.1 and tolerant of
  trailing parameters (`; boundary=...`).

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

## RFC 9110 §8.6 Content-Length sanity

Beyond the §13.1.5 strong-validator path (below), the driver
cross-checks the GET-time `Content-Length` against §8.6's invariants:

- On a 200-fallback (server ignored `Range` and shipped the full
  body per RFC 7233 §3.1), the GET's `Content-Length` — when present
  — MUST equal the `Content-Length` observed at HEAD. §8.6 says
  "a server MUST NOT send Content-Length in [a HEAD] response
  unless its field value equals the decimal number of octets that
  would have been sent in the content of a response if the same
  request had used the GET method." A different value is a
  mid-stream resource resize disguised as a soft-fallback; surfacing
  it stops the demuxer from draining a now-wrong-sized prefix and
  reading short.
- On a 206, the GET's `Content-Length` (when present) MUST equal
  the byte span implied by `Content-Range: bytes <first>-<last>/N`
  (i.e. `last - first + 1`). A mismatch is either a server bug or a
  multipart/byteranges body (which we never request); either way
  it would let the reader drift past the satisfied range silently.
- Both checks are skipped silently when the GET reply omits
  `Content-Length` (§8.6 makes it a SHOULD, not a MUST, outside
  specific cases).

## Mid-stream mutation detection

The driver implements RFC 9110 §13.1.5 `If-Range` to catch the case
where a CDN, cache, or origin replaces the resource between the
opening `HEAD` and a later `Range` GET. At `HEAD` we capture a
*strong* validator:

- An `ETag` is taken as-is when it lacks the `W/` weakness prefix
  (§8.8.3 — weak entity-tags are MUST-NOT for `If-Range` per
  §13.1.5).
- Failing that, `Last-Modified` is taken only when the companion
  `Date` header is at least one second after it (§8.8.2.2's
  promotion rule from "implicitly weak" to "strong"). Both headers
  are parsed through a unified §5.6.7 HTTP-date reader that accepts
  all three forms a recipient MUST accept — IMF-fixdate
  (`Sun, 06 Nov 1994 08:49:37 GMT`), the obsolete `rfc850-date`
  (`Sunday, 06-Nov-94 08:49:37 GMT`, 2-digit year expanded under
  §5.6.7's 50-year sliding window MUST), and the obsolete
  `asctime-date` (`Sun Nov  6 08:49:37 1994`). The two headers do
  not need to share the same form.
- Otherwise no validator is captured and the read path issues
  plain `Range` GETs (matching pre-r186 behaviour).

Every range GET that has a captured validator carries
`If-Range: <wire-form>`. Per §13.1.5 the server then either
satisfies the range normally (`206 Partial Content`) or responds
with a full `200 OK` for the *new* representation. The latter is
treated as a fatal `io::Error` naming "If-Range validator did not
match — representation changed since HEAD" so a downstream demuxer
never silently re-anchors against a different resource. When no
`If-Range` was sent (no strong validator at HEAD), the §3.1
prefix-drain fallback still applies unchanged.

## Retry-After parsing (RFC 9110 §10.2.3)

The free function `parse_retry_after` consumes a `Retry-After`
field value and returns a typed [`RetryAfter`] enum — either a
`Delay(Duration)` for the `delay-seconds = 1*DIGIT` form or a
`Date { year, month, day, hour, minute, second }` for the
HTTP-date form. All three §5.6.7 receiver-side date forms
(IMF-fixdate, rfc850-date, asctime-date) are accepted in
keeping with §5.6.7's MUST.

```rust
use std::time::Duration;
use oxideav_http::{parse_retry_after, RetryAfter};

assert_eq!(
    parse_retry_after("120"),
    Some(RetryAfter::Delay(Duration::from_secs(120))),
);
assert!(matches!(
    parse_retry_after("Fri, 31 Dec 1999 23:59:59 GMT"),
    Some(RetryAfter::Date { year: 1999, .. }),
));
```

The driver does NOT itself sleep on `Retry-After` — interpreting
"wait until this absolute UTC time" requires a clock the source
does not own, and a back-off strategy belongs in the caller. The
parser is exported so consumers that *do* hold both can act on
503 / 429 / 3xx-with-Retry-After responses without writing the
§10.2.3 grammar a second time.

When the opening `HEAD` returns a non-success status, the driver
parses any `Retry-After` field through `parse_retry_after` and
surfaces the canonicalised value in the resulting error message:

- `delay-seconds` form renders as `" (Retry-After: <N> s)"`.
- HTTP-date form renders as
  `" (Retry-After: YYYY-MM-DDTHH:MM:SS UTC)"` regardless of which
  of the three §5.6.7 wire forms the server emitted.
- An unparseable `Retry-After` surfaces the raw value plus a
  §10.2.3 cite (`"Retry-After: \"…\", unparseable per RFC 9110
  §10.2.3"`) so a buggy origin is visible rather than silently
  dropped.

This lets a caller wiring back-off act on the message text alone
without having to also fish the header out of a now-consumed
response.

The §10.2.3 grammar is intentionally strict:

- `delay-seconds` is 1*DIGIT — a leading `+` or `-`, fractional
  digits, hex prefixes, or trailing units (`"120s"`) all
  produce `None`.
- An all-digit value that overflows `u64` (≈ 584 billion years
  worth of seconds) surfaces `None` rather than saturating.
- A non-digit value MUST parse through `parse_http_date`
  (IMF-fixdate / rfc850-date / asctime-date) — random tokens
  like `"never"` or `"Tomorrow at noon"` produce `None`.

## Obs-fold normalisation (RFC 7230 §3.2.4)

Field values picked off of the response are normalised through a
small §3.2.4 helper before they reach a grammar-specific parser.
The §3.2 ABNF allows `field-value = *( field-content / obs-fold )`
with `obs-fold = CRLF 1*( SP / HTAB )`, and §3.2.4 makes the
following hard requirement on a user agent that receives an
obs-folded response (not inside a `message/http` container):

> A user agent that receives an obs-fold in a response message that
> is not within a message/http container MUST replace each received
> obs-fold with one or more SP octets prior to interpreting the
> field value.

The driver collapses each maximal `CRLF (SP/HTAB)+` run to a single
ASCII space — the smallest stable choice that preserves the
token-boundary signal the original whitespace carried (so an
obs-folded comma-separated list still tokenises the same way) —
before invoking the §14.3 `Accept-Ranges` list parser or the
§10.2.3 `Retry-After` hint formatter on the HEAD non-success path.
Bare CR, bare LF, and CRLF NOT followed by SP/HTAB are left
untouched: they are not obs-fold per the §3.2 ABNF and the framing
layer below is the right place to flag them. Empty inputs and
inputs that carry no fold short-circuit through a `Cow::Borrowed`
return so the production path stays allocation-free (modern HTTP
clients strip folds at the framing layer, so the helper is a
defence-in-depth guard that almost never has to act, but the
invariant is now explicit in the code).

## Fuzzing

`fuzz/` carries a cargo-fuzz harness (`parse_headers`) that drives
every internal response-header parser used by the source driver —
`parse_byte_content_range` (RFC 7233 §4.2 / RFC 9110 §14.4),
`parse_byte_unsatisfied_range` (§14.4), `parse_entity_tag` (§8.8.3),
`parse_imf_fixdate` / `parse_rfc850_date` / `parse_asctime_date`
plus the unified §5.6.7 dispatcher `parse_http_date`,
`parse_retry_after` (§10.2.3),
`parse_accept_ranges` (§14.3),
`is_multipart_byteranges_content_type` (§8.3 / §14.6 / §15.3.7.2),
`format_retry_after_hint` (§10.2.3 HEAD surfacing helper),
`normalize_obs_fold` (RFC 7230 §3.2.4 obs-fold normaliser),
and the composite
`derive_strong_validator` (§13.1.5 + §8.8.2.2 + §8.8.3).
The harness
reaches the parsers through a `#[doc(hidden)] pub mod __fuzz`
re-export gated on the `fuzz` cargo feature, so the stable public
surface is unchanged when the crate is consumed normally.

```sh
cargo +nightly fuzz run --fuzz-dir fuzz parse_headers
```

A small seed corpus lives under `fuzz/corpus/parse_headers/`.

## License

MIT — see [LICENSE](LICENSE).
