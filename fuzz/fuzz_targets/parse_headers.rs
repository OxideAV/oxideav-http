#![no_main]

//! Decode-side fuzz harness for every internal HTTP response-header
//! parser used by the oxideav-http source driver.
//!
//! The contract under test is that none of these parsers ever panics
//! on attacker-controlled input. They are invoked in two passes:
//!
//! 1. The fuzz input is treated as one byte string. Any non-UTF-8
//!    bytes short-circuit (the parsers take `&str`); for UTF-8
//!    inputs the string is fed to every single-arg parser so the
//!    fuzzer can find any panic mode each of them carries on its
//!    own.
//! 2. The fuzz input is split on ASCII NUL (`0x00`) into up to three
//!    optional fields and fed to `derive_strong_validator` so the
//!    fuzzer reaches every combination of present / absent ETag,
//!    Last-Modified, Date inputs.
//!
//! Parsers exercised:
//!
//! * `parse_byte_content_range`  — RFC 7233 §4.2 / RFC 9110 §14.4
//!   canonical `bytes <first>-<last>/<complete-or-*>` form.
//! * `parse_byte_unsatisfied_range` — RFC 9110 §14.4 `bytes */N`
//!   form for 416 responses.
//! * `parse_entity_tag` — RFC 9110 §8.8.3 entity-tag grammar.
//! * `parse_imf_fixdate` — RFC 9110 §5.6.7 IMF-fixdate
//!   `Wkd, DD Mon YYYY HH:MM:SS GMT`.
//! * `parse_rfc850_date` — RFC 9110 §5.6.7 obsolete rfc850-date
//!   `Weekday, DD-Mon-YY HH:MM:SS GMT` (a §5.6.7 MUST-accept form).
//! * `parse_asctime_date` — RFC 9110 §5.6.7 obsolete asctime-date
//!   `Wkd Mon  D HH:MM:SS YYYY` (a §5.6.7 MUST-accept form).
//! * `parse_http_date` — unified §5.6.7 dispatcher that tries all
//!   three forms in turn.
//! * `parse_retry_after` — RFC 9110 §10.2.3 `HTTP-date /
//!   delay-seconds` grammar for the `Retry-After` field.
//! * `parse_accept_ranges` — RFC 9110 §14.3 `acceptable-ranges =
//!   1#range-unit` list-form classifier (Bytes / None / Other /
//!   Absent).
//! * `is_multipart_byteranges_content_type` — RFC 9110 §8.3
//!   media-type / §14.6 / §15.3.7.2 single-range MUST-NOT detector.
//! * `format_retry_after_hint` — RFC 9110 §10.2.3 surfacing helper
//!   exercised on the HEAD non-success branch.
//! * `normalize_obs_fold` — RFC 7230 §3.2.4 obs-fold normalisation
//!   helper. Contract: never panics, output is always valid UTF-8.
//! * `unquote_string` — RFC 9110 §5.6.4 `quoted-string` unwrap with
//!   `quoted-pair` collapse. Contract: never panics, every output
//!   string (when `Some`) is valid UTF-8.
//! * `parse_parameters` — RFC 9110 §5.6.6 `parameters` grammar
//!   (semicolon-delimited `name=value` list with quoted-string-aware
//!   splitting). Contract: never panics, every returned `(name, value)`
//!   pair is valid UTF-8.
//! * `derive_strong_validator` — §13.1.5 + §8.8.2.2 + §8.8.3
//!   composite that picks an If-Range value from a HEAD's three
//!   relevant headers.

use libfuzzer_sys::fuzz_target;
use oxideav_http::__fuzz;

fuzz_target!(|data: &[u8]| {
    // Pass 1: every parser sees the whole input as one string.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = __fuzz::parse_byte_content_range(s);
        let _ = __fuzz::parse_byte_unsatisfied_range(s);
        let _ = __fuzz::parse_entity_tag(s);
        let _ = __fuzz::parse_imf_fixdate(s);
        let _ = __fuzz::parse_rfc850_date(s);
        let _ = __fuzz::parse_asctime_date(s);
        let _ = __fuzz::parse_http_date(s);
        let _ = __fuzz::parse_retry_after(s);
        let _ = __fuzz::parse_accept_ranges(s);
        let _ = __fuzz::is_multipart_byteranges_content_type(s);
        let _ = __fuzz::format_retry_after_hint(s);
        let _ = __fuzz::normalize_obs_fold(s);
        let _ = __fuzz::unquote_string(s);
        let _ = __fuzz::parse_parameters(s);
    }

    // Pass 2: NUL-split the input into up to three fields for the
    // composite validator. Empty / missing fields are `None`. This is
    // how the fuzzer drives the 8 presence combinations (etag,
    // last-modified, date) × every (UTF-8) field shape.
    let mut parts = data.splitn(3, |&b| b == 0);
    let etag = parts.next().and_then(|b| std::str::from_utf8(b).ok());
    let lm = parts.next().and_then(|b| std::str::from_utf8(b).ok());
    let date = parts.next().and_then(|b| std::str::from_utf8(b).ok());
    // Treat an empty field as "header absent" so the fuzzer can reach
    // the all-None path without having to find a no-NUL input.
    let etag = etag.filter(|s| !s.is_empty());
    let lm = lm.filter(|s| !s.is_empty());
    let date = date.filter(|s| !s.is_empty());
    __fuzz::derive_strong_validator(etag, lm, date);
});
