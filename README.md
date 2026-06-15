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

## Content-coding refusal (RFC 9110 §8.4 + §12.5.3)

The driver's byte-offset model — the `Content-Length` recorded at
HEAD, every `Content-Range` echo it validates, the §3.1 prefix
drain — assumes the wire bytes ARE the representation bytes a
demuxer consumes. §8.4 breaks that for coded representations: "the
representation is defined in terms of the coded form, and all other
metadata about the representation is about the coded form". And
§12.5.3 rule 1 makes silence consent — a request with no
`Accept-Encoding` declares every coding acceptable. So the driver
acts on both sides:

- The opening `HEAD` and every `Range` GET carry
  `Accept-Encoding: identity`. Listing only the §12.5.3 "no
  encoding" synonym makes every real coding "not listed" under
  rule 3, steering a conformant server to send the un-coded bytes.
- Any response that still carries a real `Content-Encoding` is
  rejected before a byte reaches the reader — `Error::Unsupported`
  at HEAD (with the coding names + §8.4 cite), fatal `io::Error` on
  a 206 / 200-fallback GET. Every `Content-Encoding` field line is
  walked (the §8.4 `#` list may span lines per §5.6.1), obs-fold is
  normalised first (RFC 7230 §3.2.4), codings are lowercased
  (§8.4.1 — case-insensitive), the redundant `identity` token is
  tolerated as a no-op (§8.4 SHOULD NOT send it, but it codes
  nothing), and empty list slots are dropped. Fail-direction is the
  opposite of the §14.3 `Accept-Ranges` parser: a garbage
  (non-token) slot is KEPT in the diagnostic, because a coding name
  the driver cannot even parse is still a transformation it cannot
  undo — skipping it would silently accept a coded body.

The underlying client is built without its optional transparent
decompression layer (see `Cargo.toml`), so the raw coded response —
header evidence and all — reaches these checks instead of being
inflated mid-stream behind the driver's back.

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

## Content-negotiation stability (RFC 9110 §12.5.5)

The driver opens a resource with a single `HEAD`, records its length
and validator, then satisfies every read with an independent `Range`
GET — so it assumes the target URI maps to one representation that
stays put for the source's lifetime. A `Vary` header on the `HEAD`
response is the origin's warning that the response was subject to
proactive content negotiation (§12) and a *different* representation
might be served on a later request.

The driver classifies `Vary` per its §12.5.5 ABNF
(`Vary = #( "*" / field-name )`):

- **`Vary: *`** — §12.5.5 says other aspects of the request, "possibly
  including aspects outside the message syntax (e.g., the client's
  network address)", might have selected this representation. The
  driver cannot reproduce such out-of-band aspects across its `HEAD`
  and later `Range` GETs. This is fatal **only when no strong
  validator was captured**: with one in hand, a representation swap
  re-materialises as the §13.1.5 `If-Range` 200-fallback the GET path
  already treats as a fatal mid-stream mutation. Without one, the open
  is refused (`Error::Unsupported`) rather than ranging blindly over a
  resource that may change underfoot undetected.
- **A list of field-names** (§12.5.5 form 2) — always safe here. The
  driver sends a fixed, identical request header set on the `HEAD` and
  on every `Range` GET (`Accept-Encoding: identity`, no
  `Accept-Language`/`Accept` overrides), so negotiation keyed purely on
  request fields lands on the same representation each time.
- **Absent / empty** — no warning, no refusal.

Field-names are matched case-insensitively (§5.1) and a member of `*`
anywhere in the list poisons the whole value to the wildcard form. The
value is run through the §3.2.4 obs-fold normaliser before parsing.

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

## Quoted-string unwrap (RFC 9110 §5.6.4)

A small `unquote_string` helper turns a DQUOTE-wrapped
`quoted-string` field value (or the RHS of a §5.6.6 parameter, or an
auth-param value, etc.) into its logical octet sequence — collapsing
every `quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )` to the
single octet that followed the backslash, as §5.6.4 makes a hard
MUST for any recipient that processes the value.

The helper is used by the cargo-fuzz `parse_headers` harness so any
panic mode is found by fuzzing; no in-driver caller exists yet (the
§15.3.7.2 multipart rejection only needs the bare media-type
prefix and the §8.8.3 `entity-tag` production explicitly excludes
`quoted-pair` from `etagc`). The primitive is in place ready to back
any future per-parameter inspection — e.g. a §5.6.6 / §8.3.1
`charset="utf-8"` parameter extractor, or the `realm="…"` value
inside a §11.4 `WWW-Authenticate` challenge.

The unwrap rejects anything that is not a syntactically valid
`quoted-string`: missing DQUOTEs, bare control bytes outside
`qdtext`, a trailing lone backslash with no octet to escape, or a
backslash followed by an octet outside the §5.6.4 `quoted-pair` RHS
(notably bare CR or LF, which would unbalance the field line). On
the happy path with no escapes present the return is a borrow of
the input slice (zero allocations); only the slow path of an actual
escape allocates.

## Parameters list (RFC 9110 §5.6.6)

`parse_parameters` consumes a `parameters` tail —
`*( OWS ";" OWS [ parameter ] )` with
`parameter = parameter-name "=" parameter-value` and
`parameter-value = ( token / quoted-string )` — and returns an
ordered `Vec<(name, value)>` of `(lowercase-name, decoded-value)`
pairs.

The splitter is quoted-string-aware: a `;` inside a `"…"` body is
part of the value, not a slot terminator, and a `\"` inside the
body is a §5.6.4 `quoted-pair` (skipped by the splitter so it does
not prematurely close the value). Each quoted-string value is
routed through `unquote_string` so the consumer receives the
logical octet sequence; each token-shape value is preserved
verbatim (case-sensitivity of the value is parameter-name-specific
per §5.6.6, so we don't fold the case).

Defensive posture for malformed slots matches `parse_accept_ranges`:
empty slots, missing-`=` slots, whitespace-around-`=` slots (per
§5.6.6's "Parameters do not allow whitespace (not even 'bad'
whitespace) around the '=' character" note), non-token names,
non-token unquoted values, and unterminated quoted-strings are all
silently skipped — the surrounding legitimate parameters survive.

The primitive sits ready to back any future per-parameter
inspection — e.g. a §8.3.1 `charset="utf-8"` extractor on
`Content-Type`, a §14.6 `boundary=` lookup on
`multipart/byteranges` if we ever decide to parse rather than
reject it (§15.3.7.2), or §11.4 `realm="…"` auth-param decoding
after the caller has split the challenge on its `,` boundaries
(§11.2 auth-params themselves are `,`-separated, but each
individual auth-param value follows the §5.6.6 shape and can be
processed by this helper one slot at a time).

The helper is exercised by 23 unit tests and the cargo-fuzz
`parse_headers` harness through the `__fuzz` re-export gate.

## Comment parse (RFC 9110 §5.6.5)

`parse_comment` reads a `comment` production into its logical text:

```text
comment = "(" *( ctext / quoted-pair / comment ) ")"
ctext   = HTAB / SP / %x21-27 / %x2A-5B / %x5D-7E / obs-text
```

It strips the outermost parentheses, collapses every §5.6.4
`quoted-pair` to the escaped octet (the same MUST `unquote_string`
applies for a §5.6.4 quoted-string), and preserves balanced
nested-comment delimiters
verbatim — `(a (b) c)` is one comment whose text is `a (b) c`. The
`ctext` holes at `(` / `)` / `\` carry meaning only through the comment
recursion or the escape, so a bare one of those bytes is illegal text.

The value is rejected (`None`) when it is not a single syntactically
valid comment: missing outer parens, content after the matching close
paren, an unbalanced paren, a bare control byte (e.g. CR / LF), or a
dangling / illegal `quoted-pair` (notably `\` before a bare CR / LF,
which would unbalance the field line). Recursion depth is tracked with
an explicit counter rather than the call stack, so an adversarial
deeply nested `((((…))))` input cannot overflow the stack. The
escape-free single-level happy path borrows the input slice (zero
allocations); only an actual `quoted-pair` allocates.

This completes the §5.6 generic-syntax primitive family already in the
crate (§5.6.1 list, §5.6.2 token, §5.6.4 quoted-string, §5.6.6
parameters, §5.6.7 date). §5.6.5 permits comments only "in fields
containing 'comment' as part of their field value definition" —
`User-Agent` / `Server` (§10.1.5 / §10.2.4), `Via` (§7.6.3), and the
`Warning` field (RFC 7234 §5.5). No in-driver caller wires this yet
(the driver issues unauthenticated `HEAD` / `Range` requests and acts
on none of those response fields), but the primitive is exported for
the fuzz harness and exercised by 10 unit tests.

## Media-type parse (RFC 9110 §8.3.1)

`parse_media_type` composes the §5.6.2 `is_token` and §5.6.6
`parse_parameters` primitives into the §8.3.1 production
`media-type = type "/" subtype parameters`. It returns
`(type, subtype, params)` where:

- `type` and `subtype` are lowercased — §8.3.1: "The type and subtype
  tokens are case-insensitive." So `Text/HTML` and `text/html` both
  yield `("text", "html", …)`.
- `params` is the §5.6.6 ordered `Vec<(lowercase-name, decoded-value)>`
  of the trailing parameters, already quoted-pair-collapsed per §5.6.4.

Parameter *values* are NOT case-folded — §8.3.1: "Parameter values
might or might not be case-sensitive, depending on the semantics of the
parameter name." A consumer that knows a parameter is case-insensitive
(e.g. `charset` per §8.3.2 / RFC 2046 §4.1.2) folds the value itself.
This is exactly the layering the §5.6.6 helper was built to enable: a
`charset` extractor on `Content-Type` is `parse_media_type(ct)` then a
case-insensitive lookup of `"charset"` in `params`.

The value is rejected (`None`) when it is not a syntactically valid
media-type: a missing `/`, an empty or non-`token` type or subtype, a
second `/` (which makes the subtype a non-`token` since `/` is not a
`tchar`), or empty / whitespace-only input. Leading/trailing OWS on the
whole value, and OWS between the subtype and the first `;`, are
tolerated (the §8.3.1 `parameters` tail opens with `*( OWS ";" OWS … )`).
Garbage parameter slots are dropped by the §5.6.6 helper while the
type/subtype and legitimate sibling parameters survive.

No in-driver caller exists yet — the §15.3.7.2 multipart rejection only
needs the bare `type/subtype` prefix and uses the narrower
`is_multipart_byteranges_content_type`. The primitive is in place ready
to back any future per-parameter media-type inspection. Exercised by 16
unit tests (including a coupling test pinning agreement with the narrow
multipart predicate) and the cargo-fuzz `parse_headers` harness.

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

## Cache-Control parse (RFC 9111 §5.2)

`parse_cache_control` parses a `Cache-Control` field value into a
typed `CacheControl` per §5.2:

```text
Cache-Control   = #cache-directive
cache-directive = token [ "=" ( token / quoted-string ) ]
```

The `#`-list (RFC 9110 §5.6.1) is split on top-level commas with
quoted-string awareness, so a comma inside a `"…"` argument — e.g.
`no-cache="x-foo, x-bar"` — does not start a new directive; empty
list elements are skipped and OWS (§5.6.3) is trimmed from each.
§5.2 makes directive names "compared case-insensitively", so they
are lowercased before dispatch, and "recipients ought to accept
both [token and quoted-string] forms" for arguments, so a quoted
`max-age="60"` is honoured on receipt even though §5.2.2.1 requires
senders to emit the bare token.

Recognized §5.2.1 / §5.2.2 directives populate typed fields:
`max-age` / `s-maxage` / `min-fresh` / `max-stale` carry §1.2.2
`delta-seconds` arguments saturated at `2147483648` (2^31) on
overflow per the §1.2.2 MUST; a non-`1*DIGIT` argument leaves the
slot absent (§4.2.1 "non-integer content" → stale). `max-stale`
distinguishes the no-argument form (`Some(None)`, "accept a stale
response of any age") from a valued bound. The qualified
`#field-name` forms of `no-cache` (§5.2.2.4) and `private`
(§5.2.2.7) split their quoted argument into lowercased field names
distinct from the unqualified booleans. The boolean directives
(`no-store`, `no-transform`, `only-if-cached`, `must-revalidate`,
`must-understand`, `proxy-revalidate`, `public`) set their flags.
Duplicate valued directives keep the first occurrence (§4.2.1), and
unrecognized directives are preserved in `extensions` rather than
dropped (§5.2.3 "ignore unrecognized" — preserved so a behavioural
extension consumer can still inspect them). A malformed element
(bad token name, OWS around `=`, unterminated quoted-string) is
skipped, never a hard error.

## WWW-Authenticate challenge parse (RFC 9110 §11.6.1)

`parse_www_authenticate` reads a `WWW-Authenticate` (or
`Proxy-Authenticate`) field value into a `Vec<Challenge>` per §11.6.1:

```text
WWW-Authenticate = #challenge
challenge        = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
auth-scheme      = token
auth-param       = token BWS "=" BWS ( token / quoted-string )
token68          = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~"
                       / "+" / "/" ) *"="
```

Each `Challenge` carries the lowercased `auth-scheme` (§11.1 —
case-insensitive token), an optional `token68` (the base64-ish blob form
used by schemes like Negotiate), and an ordered list of
`(lowercased-name, decoded-value)` `auth-param` pairs. Per §11.3 a
challenge carries EITHER a `token68` OR `auth-param`s, never both.

The §11.6.1 ambiguity is the interesting part: both the challenge list
AND each challenge's `auth-param` list are comma-separated, so a flat
comma split cannot tell "next challenge" from "next param of the current
challenge". The parser does a quoted-string-aware top-level comma split
(§5.6.1 — a comma inside a `"…"` value never splits) then classifies
each element:

- a **bare `auth-param`** (`token BWS "=" …`) has no scheme of its own,
  so it attaches to the challenge currently being built;
- a **challenge head** (`auth-scheme` alone, or `auth-scheme 1*SP
  <arg>`) starts a new challenge.

The canonical §11.6.1 worked example —

```text
Basic realm="simple", Newauth realm="apps", type=1, title="Login to \"apps\""
```

— parses as **two** challenges: `basic` with `realm="simple"`, and
`newauth` with `realm="apps", type=1, title="Login to "apps""` (the
`\"` quoted-pair collapsed via the §5.6.4 helper).

§11.2 details honoured: BWS ("bad" whitespace) is tolerated on both
sides of the `=` (unlike the stricter §5.6.6 `parameter` production);
`auth-param` names are lowercased (case-insensitive) while values keep
their case (value case-sensitivity is scheme-specific); a quoted value
is unwrapped through the §5.6.4 `quoted-string` reader and a bare token
value is kept verbatim. A `name=value`-shaped first argument is always
read as an `auth-param`, never a `token68` (the §11.6.1 note resolves
the ambiguity toward `auth-param`).

Robustness matches the rest of the driver's §5.6.1 list handling:
empty list elements (the §11.6.1 "comma, whitespace, comma" note calls
these harmless), malformed `auth-param` slots, a leading bare
`auth-param` with no challenge to attach to, and an `auth-param`
trailing a `token68` challenge are all skipped while the surrounding
well-formed challenges survive. An `obs-fold` (RFC 7230 §3.2.4) is
normalised to a single SP first. The same production backs
`Proxy-Authenticate` (§11.7.1) and a single-`credentials`
`Authorization` value (read the first element of the returned `Vec`).

No in-driver caller wires this yet — the driver issues unauthenticated
`HEAD` / `Range` requests — but the primitive is exported so a consumer
acting on a 401 / 407 can inspect the offered schemes and realms without
re-implementing the §11.6.1 grammar.

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
`unquote_string` (RFC 9110 §5.6.4 quoted-string unwrap),
`parse_comment` (RFC 9110 §5.6.5 `comment = "(" *( ctext /
quoted-pair / comment ) ")"` with nested-comment recursion),
`parse_parameters` (RFC 9110 §5.6.6 semicolon-delimited
`name=value` list with quoted-string-aware splitting),
`parse_media_type` (RFC 9110 §8.3.1 `media-type = type "/" subtype
parameters`),
`non_identity_content_codings` (RFC 9110 §8.4 `Content-Encoding`
list filter behind the content-coding refusal),
`parse_cache_control` (RFC 9111 §5.2 `Cache-Control =
#cache-directive`),
`parse_www_authenticate` (RFC 9110 §11.6.1 `WWW-Authenticate =
#challenge` with the §11.6.1 challenge/auth-param list disambiguation
and §11.2 `token68` vs `auth-param` discrimination),
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
